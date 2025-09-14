// src/main.cpp - BLE-only, NimBLE NUS + WiFi promiscuous sniffer
// Removes BluetoothSerial (Classic SPP) to avoid stack/mutex conflicts.

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_netif.h" // replace deprecated tcpip_adapter_init()
#include <NimBLEDevice.h>

// ---------- BLE NUS UUIDs ----------
#define NUS_SERVICE_UUID "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define NUS_CHAR_RX_UUID "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
#define NUS_CHAR_TX_UUID "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

NimBLEServer *pServer = nullptr;
NimBLECharacteristic *pTxChar = nullptr;
NimBLECharacteristic *pRxChar = nullptr;
bool bleClientConnected = false;

// ---------- sniffer state ----------
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
int channel = 1;
bool doHop = true;
unsigned long lastHop = 0;
const unsigned long hopIntervalMs = 200;
bool sniffing = true;

// filters
String macFilter = "";
int minRssi = -1000;
String typeFilter = "";
int lockChannel = 0; // 0 = unlocked

// ---------- BLE RX queue (thread safe) ----------
static QueueHandle_t bleRxQueue = NULL; // queue of bytes

// ---------- utilities ----------
String macToStr(const uint8_t *mac)
{
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void sendToBLEAndSerial(const String &s)
{
  String out = s;
  if (!out.endsWith("\n"))
    out += "\n";
  Serial.print(out);
  if (bleClientConnected && pTxChar)
  {
    const char *buf = out.c_str();
    size_t len = out.length();
    size_t pos = 0;
    while (pos < len)
    {
      size_t chunk = min((size_t)20, len - pos);
      pTxChar->setValue((uint8_t *)(buf + pos), chunk);
      pTxChar->notify(true);
      pos += chunk;
      delay(2);
    }
  }
}

// ---------- promiscuous callback ----------
typedef struct
{
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;

void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
  if (!sniffing)
    return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t rx_ctrl = pkt->rx_ctrl;
  const uint8_t *payload = pkt->payload;
  int len = rx_ctrl.sig_len;
  if (payload == nullptr || len <= 0)
    return;

  if (len >= (int)sizeof(wifi_ieee80211_mac_hdr_t))
  {
    wifi_ieee80211_mac_hdr_t hdr;
    memcpy(&hdr, payload, sizeof(hdr));
    uint16_t fc = hdr.frame_ctrl;
    uint8_t subtype = (fc & 0x000F);
    uint8_t typefield = (fc & 0x000C) >> 2;

    String typestr = "UNK";
    if (typefield == 0)
      typestr = "Mgmt";
    else if (typefield == 1)
      typestr = "Ctrl";
    else if (typefield == 2)
      typestr = "Data";

    String mgmtSubtype = "";
    if (typefield == 0)
    {
      if (subtype == 8)
        mgmtSubtype = "Beacon";
      else if (subtype == 4)
        mgmtSubtype = "ProbeReq";
      else if (subtype == 5)
        mgmtSubtype = "ProbeResp";
    }

    String src = macToStr(hdr.addr2);
    String dst = macToStr(hdr.addr1);
    String bssid = macToStr(hdr.addr3);

    // filters
    if (minRssi > -999 && rx_ctrl.rssi < minRssi)
      return;
    if (lockChannel && rx_ctrl.channel != lockChannel)
      return;
    if (typeFilter.length() && !(typestr.equalsIgnoreCase(typeFilter) || mgmtSubtype.equalsIgnoreCase(typeFilter)))
      return;
    if (macFilter.length())
    {
      String low = macFilter;
      low.toLowerCase();
      String ssrc = src;
      ssrc.toLowerCase();
      String sdst = dst;
      sdst.toLowerCase();
      String sbssid = bssid;
      sbssid.toLowerCase();
      if (ssrc.indexOf(low) < 0 && sdst.indexOf(low) < 0 && sbssid.indexOf(low) < 0)
        return;
    }

    String obj = "{";
    obj += "\"ts\": " + String(millis());
    obj += ", \"chan\": " + String(rx_ctrl.channel);
    obj += ", \"rssi\": " + String(rx_ctrl.rssi);
    obj += ", \"type\": \"" + typestr + "\"";
    if (mgmtSubtype.length())
      obj += ", \"subtype\": \"" + mgmtSubtype + "\"";
    obj += ", \"src\": \"" + src + "\"";
    obj += ", \"dst\": \"" + dst + "\"";
    obj += ", \"bssid\": \"" + bssid + "\"";
    obj += "}";
    sendToBLEAndSerial(obj);
  }
  else
  {
    String obj = "{";
    obj += "\"ts\": " + String(millis());
    obj += ", \"chan\": " + String(rx_ctrl.channel);
    obj += ", \"rssi\": " + String(rx_ctrl.rssi);
    obj += ", \"type\": \"SHORT\"";
    obj += ", \"len\": " + String(len);
    obj += "}";
    sendToBLEAndSerial(obj);
  }
}

// ---------- BLE callbacks ----------
class ServerCallbacks : public NimBLEServerCallbacks
{
  void onConnect(NimBLEServer *pServer)
  {
    bleClientConnected = true;
    sendToBLEAndSerial("[BLE] Client connected");
  }
  void onDisconnect(NimBLEServer *pServer)
  {
    bleClientConnected = false;
    sendToBLEAndSerial("[BLE] Client disconnected");
  }
};

class RxCharCallbacks : public NimBLECharacteristicCallbacks
{
  void onWrite(NimBLECharacteristic *pCharacteristic)
  {
    std::string v = pCharacteristic->getValue();
    if (v.size())
    {
      // push bytes safely into a FreeRTOS queue to be processed in loop()
      for (size_t i = 0; i < v.size(); ++i)
      {
        char c = v[i];
        // non-blocking enqueue; drop if full
        if (bleRxQueue)
          xQueueSend(bleRxQueue, &c, 0);
      }
    }
  }
};

// ---------- command handling ----------
String inputBuffer = "";

void handleLine(String line)
{
  line.trim();
  if (line.length() == 0)
    return;
  sendToBLEAndSerial(String("[ACK] ") + line);

  if (line.equalsIgnoreCase("START"))
  {
    sniffing = true;
    sendToBLEAndSerial("[INFO] Sniffer STARTED");
  }
  else if (line.equalsIgnoreCase("STOP"))
  {
    sniffing = false;
    sendToBLEAndSerial("[INFO] Sniffer STOPPED");
  }
  else if (line.equalsIgnoreCase("HOP TOGGLE") || line.equalsIgnoreCase("HOP"))
  {
    doHop = !doHop;
    sendToBLEAndSerial(String("[INFO] Channel hopping ") + (doHop ? "ENABLED" : "DISABLED"));
  }
  else if (line.equalsIgnoreCase("HOP ON"))
  {
    doHop = true;
    sendToBLEAndSerial("[INFO] Channel hopping ENABLED");
  }
  else if (line.equalsIgnoreCase("HOP OFF"))
  {
    doHop = false;
    sendToBLEAndSerial("[INFO] Channel hopping DISABLED");
  }
  else if (line.startsWith("SET_CH"))
  {
    int n = -1;
    int sp = line.indexOf(' ');
    if (sp > 0)
      n = line.substring(sp + 1).toInt();
    else
    {
      int col = line.indexOf(':');
      if (col > 0)
        n = line.substring(col + 1).toInt();
    }
    if (n >= 1 && n <= 13)
    {
      channel = n;
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
      sendToBLEAndSerial(String("[INFO] Channel set to ") + String(channel));
    }
    else
      sendToBLEAndSerial("[ERR] SET_CH requires 1..13");
  }
  else if (line.startsWith("FILTER ADD"))
  {
    int p = line.indexOf(' ');
    String mac = line.substring(line.indexOf(' ', p + 1) + 1);
    mac.trim();
    if (mac.length())
    {
      macFilter = mac;
      sendToBLEAndSerial(String("[INFO] MAC filter set to ") + macFilter);
    }
    else
      sendToBLEAndSerial("[ERR] FILTER ADD <mac-substring>");
  }
  else if (line.startsWith("FILTER CLR") || line.startsWith("FILTER CLEAR") || line.equalsIgnoreCase("FILTER CLR"))
  {
    macFilter = "";
    minRssi = -1000;
    typeFilter = "";
    sendToBLEAndSerial("[INFO] Filters cleared");
  }
  else if (line.startsWith("RSSI_MIN"))
  {
    int sp2 = line.indexOf(' ');
    if (sp2 > 0)
    {
      int r = line.substring(sp2 + 1).toInt();
      minRssi = r;
      sendToBLEAndSerial(String("[INFO] minRssi=") + String(minRssi));
    }
    else
      sendToBLEAndSerial("[ERR] RSSI_MIN <value>");
  }
  else if (line.startsWith("TYPE "))
  {
    String t = line.substring(5);
    typeFilter = t;
    sendToBLEAndSerial(String("[INFO] Type filter set to ") + typeFilter);
  }
  else if (line.equalsIgnoreCase("GET_STATUS"))
  {
    String s = "[STATUS] ";
    s += sniffing ? "sniffing" : "stopped";
    s += ", hop=" + String(doHop ? "on" : "off");
    s += ", ch=" + String(channel);
    s += ", macFilter=" + macFilter;
    s += ", minRssi=" + String(minRssi);
    s += ", typeFilter=" + typeFilter;
    sendToBLEAndSerial(s);
  }
  else
  {
    sendToBLEAndSerial(String("[WARN] Unknown command: ") + line);
  }
}

void processIncomingFromSerials()
{
  // USB Serial first
  while (Serial.available())
  {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r')
    {
      if (inputBuffer.length())
      {
        handleLine(inputBuffer);
        inputBuffer = "";
      }
    }
    else
      inputBuffer += c;
  }
  // BLE RX queue -> append to inputBuffer
  if (bleRxQueue)
  {
    char c;
    while (xQueueReceive(bleRxQueue, &c, 0) == pdTRUE)
    {
      if (c == '\n' || c == '\r')
      {
        if (inputBuffer.length())
        {
          handleLine(inputBuffer);
          inputBuffer = "";
        }
      }
      else
        inputBuffer += c;
      // prevent runaway long buffers
      if (inputBuffer.length() > 512)
        inputBuffer = inputBuffer.substring(inputBuffer.length() - 512);
    }
  }
}

// ---------- setup ----------
void setup()
{
  Serial.begin(115200);
  delay(100);

  // Create BLE RX queue (512 bytes)
  bleRxQueue = xQueueCreate(512, sizeof(char));
  if (!bleRxQueue)
  {
    Serial.println("[ERR] bleRxQueue creation failed");
  }

  // NimBLE BLE NUS server
  NimBLEDevice::init("ESP32-NUS");
  pServer = NimBLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());
  NimBLEService *pService = pServer->createService(NUS_SERVICE_UUID);
  pTxChar = pService->createCharacteristic(NUS_CHAR_TX_UUID, NIMBLE_PROPERTY::NOTIFY);
  pRxChar = pService->createCharacteristic(NUS_CHAR_RX_UUID, NIMBLE_PROPERTY::WRITE);
  pRxChar->setCallbacks(new RxCharCallbacks());
  pService->start();
  NimBLEAdvertising *pAdv = NimBLEDevice::getAdvertising();
  pAdv->addServiceUUID(NUS_SERVICE_UUID);
  pAdv->start();
  Serial.println("BLE NUS started");

  // Network init (replace deprecated tcpip_adapter_init)
  esp_netif_init();

  // WiFi driver init for promiscuous
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_stop();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_err_t err = esp_wifi_init(&cfg);
  if (err != ESP_OK)
  {
    sendToBLEAndSerial(String("[ERR] esp_wifi_init failed: ") + String((int)err));
    while (true)
      delay(1000);
  }
  err = esp_wifi_set_mode(WIFI_MODE_STA);
  if (err != ESP_OK)
    sendToBLEAndSerial(String("[ERR] esp_wifi_set_mode failed: ") + String((int)err));
  err = esp_wifi_start();
  if (err != ESP_OK)
    sendToBLEAndSerial(String("[ERR] esp_wifi_start failed: ") + String((int)err));

  // promiscuous callback
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  sendToBLEAndSerial("[INFO] ESP32 sniffer started (BLE-only). Channel hopping enabled by default.");
}

// ---------- loop ----------
void loop()
{
  unsigned long now = millis();
  if (doHop && (now - lastHop) > hopIntervalMs)
  {
    lastHop = now;
    channel++;
    if (channel > 13)
      channel = 1;
    if (!lockChannel)
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  }
  processIncomingFromSerials();
  delay(10);
}
