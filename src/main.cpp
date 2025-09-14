/*
  ESP32 WiFi Promiscuous Sniffer (Arduino)

  - Schaltet in den Promiscuous-Modus
  - Channel hopping (1..13)
  - Gibt Timestamp, Channel, RSSI, Source MAC, Dest MAC, Frame-Typ aus
  - Nur Metadaten; keine Payload-Entschlüsselung
*/

#include <WiFi.h>
#include "esp_wifi.h"

portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
int channel = 1;
bool doHop = true;
unsigned long lastHop = 0;
const unsigned long hopIntervalMs = 200; // Channel dwell time

// 802.11 header we need (management/data frames use this basic layout)
typedef struct
{
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;

// helper to print MAC
String macToStr(const uint8_t *mac)
{
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// promiscuous RX callback
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t rx_ctrl = pkt->rx_ctrl;

  const uint8_t *payload = pkt->payload;
  // Verwendung von sig_len statt payload_len
  int len = rx_ctrl.sig_len; // sig_len ist in vielen SDKs die empfangene Länge (bytes)

  if (payload == nullptr || len <= 0)
  {
    // kein verwertbarer Payload — evtl. nur Control-Frame/keine Nutzdaten
    return;
  }

  // Sicherstellen, dass genug Daten für den 802.11 Header vorhanden sind
  if (len >= (int)sizeof(wifi_ieee80211_mac_hdr_t))
  {
    wifi_ieee80211_mac_hdr_t hdr;
    memcpy(&hdr, payload, sizeof(hdr));
    uint16_t fc = hdr.frame_ctrl;
    uint8_t subtype = (fc & 0x000F);
    uint8_t typefield = (fc & 0x000C) >> 2;

    const char *typestr = "UNK";
    if (typefield == 0)
      typestr = "Mgmt";
    else if (typefield == 1)
      typestr = "Ctrl";
    else if (typefield == 2)
      typestr = "Data";

    const char *mgmtSubtype = "";
    if (typefield == 0)
    {
      if (subtype == 8)
        mgmtSubtype = "Beacon";
      else if (subtype == 4)
        mgmtSubtype = "ProbeReq";
      else if (subtype == 5)
        mgmtSubtype = "ProbeResp";
      else
        mgmtSubtype = "";
    }

    Serial.printf("%10lu ms  CH:%02d  RSSI:%d dBm  %-6s %-8s  SRC:%s DST:%s BSSID:%s\n",
                  millis(),
                  rx_ctrl.channel,
                  rx_ctrl.rssi,
                  typestr,
                  mgmtSubtype[0] ? mgmtSubtype : "",
                  macToStr(hdr.addr2).c_str(),
                  macToStr(hdr.addr1).c_str(),
                  macToStr(hdr.addr3).c_str());
  }
  else
  {
    Serial.printf("%10lu ms  CH:%02d  RSSI:%d dBm  (short payload len=%d)\n",
                  millis(),
                  rx_ctrl.channel,
                  rx_ctrl.rssi,
                  len);
  }
}

void setup()
{
  Serial.begin(115200);
  delay(100);

  // init WiFi in station mode (required before promiscuous)
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_stop();
  esp_err_t err;

  // initialize TCP/IP adapter & WiFi driver
  tcpip_adapter_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  err = esp_wifi_init(&cfg);
  if (err != ESP_OK)
  {
    Serial.printf("esp_wifi_init failed: %d\n", err);
    while (true)
      delay(1000);
  }
  err = esp_wifi_set_mode(WIFI_MODE_STA);
  if (err != ESP_OK)
  {
    Serial.printf("esp_wifi_set_mode failed: %d\n", err);
  }
  err = esp_wifi_start();
  if (err != ESP_OK)
  {
    Serial.printf("esp_wifi_start failed: %d\n", err);
  }

  // set promisc callback and enable promisc
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_promiscuous(true);

  // start on channel 1
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  Serial.println("ESP32 WiFi sniffer started. Channel hopping enabled.");
}

void loop()
{
  // channel hopper (quick/simple)
  if (doHop && (millis() - lastHop) > hopIntervalMs)
  {
    lastHop = millis();
    channel++;
    if (channel > 13)
      channel = 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  }
  delay(10);
}
