/* ESP32 Sniffer + Bluetooth (SPP + BLE NUS) streamer
   - Streams JSON lines with metadata over Classic BT SPP and BLE UART (NUS)
   - Accepts simple commands to control the sniffer
   - Filters: MAC substring filter, min RSSI, type filter, single-channel lock
*/

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "BluetoothSerial.h"
#include <NimBLEDevice.h>

// ---------- Bluetooth (Classic) ----------
BluetoothSerial SerialBT;

// ---------- BLE NUS (UART-like) ----------
#define NUS_SERVICE_UUID "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define NUS_CHAR_RX_UUID "6e400002-b5a3-f393-e0a9-e50e24dcca9e" // write from client
#define NUS_CHAR_TX_UUID "6e400003-b5a3-f393-e0a9-e50e24dcca9e" // notify to client

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
String macFilter = ""; // case-insensitive substring match on src/dst/bssid
int minRssi = -1000;
String typeFilter = ""; // "Mgmt","Ctrl","Data","Beacon" or ""
int lockChannel = 0;    // 0 = not locked, otherwise 1..13

// ---------- utilities ----------
String macToStr(const uint8_t *mac)
{
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void sendToAll(String s)
{
  // safe single-line outputs; add newline if missing
  if (!s.endsWith("\n"))
    s += "\n";
  Serial.print(s); // USB serial

  // Classic Bluetooth
  if (SerialBT.hasClient())
  {
    SerialBT.print(s);
  }
  // BLE notify (chunk if necessary)
  if (bleClientConnected && pTxChar)
  {
    // NimBLE handles chunking but we'll do small writes
    const char *buf = s.c_str();
    size_t len = s.length();
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

    // apply filters
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

    // build JSON line
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
    sendToAll(obj);
  }
  else
  {
    // short payload; still report summary
    String obj = "{";
    obj += "\"ts\": " + String(millis());
    obj += ", \"chan\": " + String(rx_ctrl.channel);
    obj += ", \"rssi\": " + String(rx_ctrl.rssi);
    obj += ", \"type\": \"SHORT\"";
    obj += ", \"len\": " + String(len);
    obj += "}";
    sendToAll(obj);
  }
}

// ---------- BLE callbacks ----------
class ServerCallbacks : public NimBLEServerCallbacks
{
  void onConnect(NimBLEServer *pServer)
  {
    bleClientConnected = true;
    sendToAll("[BLE] Client connected");
  }
  void onDisconnect(NimBLEServer *pServer)
  {
    bleClientConnected = false;
    sendToAll("[BLE] Client disconnected");
  }
};

class RxCharCallbacks : public NimBLECharacteristicCallbacks
{
  void onWrite(NimBLECharacteristic *pCharacteristic)
  {
    std::string v = pCharacteristic->getValue();
    if (v.size())
    {
      String s((char *)v.c_str());
      // write callback may receive partial chunks; we accumulate on main loop via a buffer
      // we'll push into Serial input queue for unified processing
      Serial.print("[BLE RX CHUNK] ");
      Serial.println(s);
      // push to serial buffer (we'll use SerialBT as intermediary if present)
      if (SerialBT.hasClient())
      {
        SerialBT.print(s.c_str());
      }
      // also feed USB Serial so monitor can see
      Serial.print(s.c_str());
    }
  }
};

// ---------- command handling (from Serial, SerialBT, or BLE RX) ----------
String inputBuffer = "";
void handleLine(String line)
{
  line.trim();
  if (line.length() == 0)
    return;
  sendToAll(String("[ACK] ") + line); // echo ack
  // parse simple commands
  if (line.equalsIgnoreCase("START"))
  {
    sniffing = true;
    sendToAll("[INFO] Sniffer STARTED");
  }
  else if (line.equalsIgnoreCase("STOP"))
  {
    sniffing = false;
    sendToAll("[INFO] Sniffer STOPPED");
  }
  else if (line.equalsIgnoreCase("HOP TOGGLE") || line.equalsIgnoreCase("HOP"))
  {
    doHop = !doHop;
    sendToAll(String("[INFO] Channel hopping ") + (doHop ? "ENABLED" : "DISABLED"));
  }
  else if (line.equalsIgnoreCase("HOP ON"))
  {
    doHop = true;
    sendToAll("[INFO] Channel hopping ENABLED");
  }
  else if (line.equalsIgnoreCase("HOP OFF"))
  {
    doHop = false;
    sendToAll("[INFO] Channel hopping DISABLED");
  }
  else if (line.startsWith("SET_CH"))
  {
    int n = -1;
    // allow "SET_CH N" or "SET_CH:N"
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
      sendToAll(String("[INFO] Channel set to ") + String(channel));
    }
    else
      sendToAll("[ERR] SET_CH requires 1..13");
  }
  else if (line.startsWith("FILTER ADD"))
  {
    int p = line.indexOf(' ');
    String mac = line.substring(line.indexOf(' ', p + 1) + 1);
    mac.trim();
    if (mac.length())
    {
      macFilter = mac;
      sendToAll(String("[INFO] MAC filter set to ") + macFilter);
    }
    else
      sendToAll("[ERR] FILTER ADD <mac-substring>");
  }
  else if (line.startsWith("FILTER CLR") || line.startsWith("FILTER CLEAR") || line.equalsIgnoreCase("FILTER CLR"))
  {
    macFilter = "";
    minRssi = -1000;
    typeFilter = "";
    sendToAll("[INFO] Filters cleared");
  }
  else if (line.startsWith("RSSI_MIN"))
  {
    // RSSI_MIN -60
    int sp2 = line.indexOf(' ');
    if (sp2 > 0)
    {
      int r = line.substring(sp2 + 1).toInt();
      minRssi = r;
      sendToAll(String("[INFO] minRssi=") + String(minRssi));
    }
    else
      sendToAll("[ERR] RSSI_MIN <value>");
  }
  else if (line.startsWith("TYPE "))
  {
    String t = line.substring(5);
    typeFilter = t;
    sendToAll(String("[INFO] Type filter set to ") + typeFilter);
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
    sendToAll(s);
  }
  else
  {
    sendToAll(String("[WARN] Unknown command: ") + line);
  }
}

void processIncomingFromSerials()
{
  // read from USB Serial
  while (Serial.available())
  {
    char c = Serial.read();
    if (c == '\n' || c == '\r')
    {
      if (inputBuffer.length())
      {
        handleLine(inputBuffer);
        inputBuffer = "";
      }
    }
    else
    {
      inputBuffer += c;
    }
  }
  // read from Classic BT
  if (SerialBT.hasClient())
  {
    while (SerialBT.available())
    {
      char c = SerialBT.read();
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
  }
  // Note: BLE RX writes are forwarded into Serial and SerialBT in RxCharCallbacks
}

// ---------- setup ----------
void setup()
{
  Serial.begin(115200);
  delay(100);

  // Classic Bluetooth SPP
  if (!SerialBT.begin("ESP32-Sniffer"))
  {
    Serial.println("SerialBT begin failed");
  }
  else
  {
    Serial.println("SerialBT started - pair from PC/Android");
  }

  // BLE NUS
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

  // WiFi driver init for promiscuous
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_stop();
  tcpip_adapter_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_err_t err = esp_wifi_init(&cfg);
  if (err != ESP_OK)
  {
    sendToAll(String("[ERR] esp_wifi_init failed: ") + String((int)err));
    while (true)
      delay(1000);
  }
  err = esp_wifi_set_mode(WIFI_MODE_STA);
  if (err != ESP_OK)
    sendToAll(String("[ERR] esp_wifi_set_mode failed: ") + String((int)err));
  err = esp_wifi_start();
  if (err != ESP_OK)
    sendToAll(String("[ERR] esp_wifi_start failed: ") + String((int)err));

  // set promisc callback
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  sendToAll("[INFO] ESP32 sniffer started. Use Bluetooth serial (SPP) or BLE to connect. Channel hopping enabled by default.");
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
