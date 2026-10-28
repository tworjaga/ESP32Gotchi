// ESP32 Cheapagotchi — passive WPA handshake sniffer + AP logger.
// Target: ESP32 Dev Module (ESP32-WROOM-32), esp32 core 2.0.x. See state.h for the shared-state/lock model.

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <Wire.h>
#include <esp_task_wdt.h>

#include "config.h"
#include "state.h"
#include "capture.h"
#include "sdlog.h"
#include "gps.h"
#include "ui.h"

void setup(void) {
    Serial.begin(115200);
    delay(200);
    Serial.println("\n[BOOT] ESP32 Cheapagotchi v" FW_VERSION);

    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_BTN, INPUT_PULLUP);
    digitalWrite(PIN_LED, LOW);

    analogSetAttenuation(ADC_11db);
    analogReadResolution(12);
    pinMode(PIN_BATT_ADC, INPUT);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "v" FW_VERSION " Boot...");
    display.sendBuffer();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    state_init();

    bool sd_ok = sd_init();

    Serial2.begin(GPS_BAUD, SERIAL_8N1, PIN_GPS_RX, PIN_GPS_TX);
    bool gps_uart_ok = true;
    g_gps_available.store(gps_uart_ok);
    Serial2.end();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);

    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    bool wifi_ok = (esp_wifi_set_promiscuous(true) == ESP_OK);
    if (!wifi_ok) {
        Serial.println("[WIFI] promiscuous failed -> restart");
        ESP.restart();
    }
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[WIFI] promiscuous active");

    selftest(sd_ok, gps_uart_ok, wifi_ok);

    xTaskCreatePinnedToCore(task_proc,  "pkt_proc", STACK_PROC,  NULL, 5, &h_proc,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", STACK_WRITE, NULL, 4, &h_write, 0);
    xTaskCreatePinnedToCore(task_hop,   "ch_hop",   STACK_HOP,   NULL, 6, &h_hop,   0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       STACK_UI,    NULL, 1, &h_ui,    1);
    xTaskCreatePinnedToCore(task_gps,   "gps",      STACK_GPS,   NULL, 2, &h_gps,   1);

    configASSERT(h_proc);
    configASSERT(h_write);
    configASSERT(h_hop);
    configASSERT(h_ui);
    configASSERT(h_gps);

    Serial.printf("[MEM]  free heap: %lu bytes\n", (unsigned long)ESP.getFreeHeap());

    esp_task_wdt_delete(NULL);
}

void loop(void) {
    vTaskDelay(portMAX_DELAY);
}
