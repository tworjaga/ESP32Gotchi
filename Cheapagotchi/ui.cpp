// LED patterns, button, OLED pages, battery, deep sleep, self-test, UI task (core 1).
#include "ui.h"
#include "state.h"

#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <esp_sleep.h>
#include <esp_task_wdt.h>
#include <driver/rtc_io.h>

static void led_tick(void) {
    static uint32_t last_ms   = 0;
    static bool     on        = false;
    static uint8_t  err_phase = 0;

    uint32_t    now = millis();
    led_state_t led = g_led.load();
    switch (led) {
        case LED_SLOW:
            if (now - last_ms >= 500) { on = !on; digitalWrite(PIN_LED, on); last_ms = now; }
            break;
        case LED_FAST:
            if (now - last_ms >= 100) { on = !on; digitalWrite(PIN_LED, on); last_ms = now; }
            break;
        case LED_FLASH:
            if (!on) { digitalWrite(PIN_LED, HIGH); on = true; last_ms = now; }
            else if (now - last_ms >= 120) { digitalWrite(PIN_LED, LOW); on = false; g_led.store(LED_SLOW); }
            break;
        case LED_ERROR: {
            uint32_t period;
            if      (err_phase == 6)       period = 1000;
            else if (err_phase % 2 == 0)   period = 2000;
            else                           period =  500;
            if (now - last_ms >= period) {
                last_ms   = now;
                err_phase = (err_phase >= 6) ? 0 : err_phase + 1;
                on = (err_phase % 2 == 0) && (err_phase < 6);
                digitalWrite(PIN_LED, on);
            }
            break;
        }
    }
}

// Short press: cycle page. Long (>=3s): restart. Extra-long (>=6s): deep sleep.
static void btn_tick(void) {
    static bool     prev     = HIGH;
    static uint32_t press_ms = 0;
    static uint32_t last_ms  = 0;

    uint32_t now = millis();
    if (now - last_ms < (uint32_t)DEBOUNCE_MS) return;
    last_ms = now;

    bool cur = digitalRead(PIN_BTN);
    if ((prev == HIGH) && (cur == LOW)) {
        press_ms = now;
    } else if ((prev == LOW) && (cur == HIGH)) {
        uint32_t dur = now - press_ms;
        if (dur >= (uint32_t)SLEEP_PRESS_MS) {
            g_sleep_req.store(true);
        } else if (dur >= (uint32_t)LONG_PRESS_MS) {
            Serial.println("[BTN] long press -> restart");
            ESP.restart();
        } else if (dur >= (uint32_t)DEBOUNCE_MS) {
            uint8_t p = g_display_page.load();
            g_display_page.store((p + 1) % 4);
            Serial.printf("[BTN] page -> %u\n", (unsigned)g_display_page.load());
        }
    }
    prev = cur;
}

static uint8_t batt_read_pct(void) {
    uint32_t sum = 0;
    for (int i = 0; i < BATT_SAMPLES; i++) {
        sum += analogRead(PIN_BATT_ADC);
        delayMicroseconds(200);
    }
    uint32_t avg = sum / BATT_SAMPLES;
    uint32_t vadc_mv = (avg * BATT_VREF_MV) / BATT_ADC_MAX;
    uint32_t vbat_mv = vadc_mv * BATT_DIVIDER;
    if (vbat_mv >= BATT_MAX_MV) return 100;
    if (vbat_mv <= BATT_MIN_MV) return 0;
    return (uint8_t)(((vbat_mv - BATT_MIN_MV) * 100UL) / (BATT_MAX_MV - BATT_MIN_MV));
}

static void oled_draw(void) {
    static const char *faces[] = { "(o_o)", "(^o^)", "(X_X)", "(-_-)" };
    char   line[24];
    face_t f    = g_face.load();
    uint8_t page = g_display_page.load();

    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 10, faces[f]);

    switch (page) {
        case 0:
            snprintf(line, sizeof(line), "HS:  %lu", (unsigned long)g_hs_count.load());
            display.drawStr(0, 20, line);
            snprintf(line, sizeof(line), "CH:  %u",  (unsigned)g_channel.load(std::memory_order_relaxed));
            display.drawStr(0, 30, line);
            snprintf(line, sizeof(line), "AP:  %lu", (unsigned long)g_ap_count.load());
            display.drawStr(0, 40, line);
            snprintf(line, sizeof(line), "PKT: %lu", (unsigned long)g_pkt_rate.load());
            display.drawStr(0, 50, line);
            snprintf(line, sizeof(line), "RSSI:%-4d D:%lu",
                     (int)g_last_rssi.load(std::memory_order_relaxed),
                     (unsigned long)g_rssi_drops.load(std::memory_order_relaxed));
            display.drawStr(0, 60, line);
            display.drawStr(110, 10, "1/4");
            break;

        case 1: {
            display.drawStr(110, 10, "2/4");
            bool fix = g_gps_fix.load();
            bool avail = g_gps_available.load();
            if (!avail) {
                display.drawStr(0, 30, "GPS: N/A");
                break;
            }
            snprintf(line, sizeof(line), "FIX: %s", fix ? "YES" : "NO");
            display.drawStr(0, 20, line);
            if (fix && xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                snprintf(line, sizeof(line), "LAT:%.5f", (double)g_gps.lat);
                display.drawStr(0, 30, line);
                snprintf(line, sizeof(line), "LON:%.5f", (double)g_gps.lon);
                display.drawStr(0, 40, line);
                snprintf(line, sizeof(line), "ALT:%.0fm", (double)g_gps.alt_m);
                display.drawStr(0, 50, line);
                snprintf(line, sizeof(line), "SAT:%u HDOP:%.1f", g_gps.sats, (double)g_gps.hdop);
                display.drawStr(0, 60, line);
                xSemaphoreGive(g_gps_mutex);
            } else if (!fix) {
                display.drawStr(0, 35, "Waiting for fix..");
            }
            break;
        }

        case 2: {
            display.drawStr(110, 10, "3/4");
            bool sd = g_sd_ok.load();
            snprintf(line, sizeof(line), "SD:  %s", sd ? "OK" : "ERR");
            display.drawStr(0, 20, line);
            if (sd) {
                uint64_t card = 0, used = 0;
                if (xSemaphoreTake(g_sd_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                    card = SD.cardSize();
                    used = SD.usedBytes();
                    xSemaphoreGive(g_sd_mutex);
                }
                uint32_t free_mb = (uint32_t)((card >= used ? card - used : 0) / (1024ULL * 1024ULL));
                snprintf(line, sizeof(line), "FREE:%luMB", (unsigned long)free_mb);
                display.drawStr(0, 30, line);

                uint32_t ap_kb = 0, st_kb = 0;
                if (xSemaphoreTake(g_sd_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                    if (SD.exists(APLOG_PATH)) {
                        File f = SD.open(APLOG_PATH, FILE_READ);
                        if (f) { ap_kb = f.size() / 1024; f.close(); }
                    }
                    if (SD.exists(STATS_PATH)) {
                        File f = SD.open(STATS_PATH, FILE_READ);
                        if (f) { st_kb = f.size() / 1024; f.close(); }
                    }
                    xSemaphoreGive(g_sd_mutex);
                }

                snprintf(line, sizeof(line), "APS: %luKB", (unsigned long)ap_kb);
                display.drawStr(0, 40, line);
                snprintf(line, sizeof(line), "STS: %luKB", (unsigned long)st_kb);
                display.drawStr(0, 50, line);
            }
            snprintf(line, sizeof(line), "WR:  %s", g_last_write_ok.load() ? "OK" : "ERR");
            display.drawStr(0, 60, line);
            break;
        }

        case 3: {
            display.drawStr(110, 10, "4/4");
            snprintf(line, sizeof(line), "HEAP:%luB", (unsigned long)ESP.getFreeHeap());
            display.drawStr(0, 20, line);
            uint32_t up_s = millis() / 1000;
            snprintf(line, sizeof(line), "UP: %02lu:%02lu:%02lu",
                     (unsigned long)(up_s / 3600),
                     (unsigned long)((up_s % 3600) / 60),
                     (unsigned long)(up_s % 60));
            display.drawStr(0, 30, line);
            snprintf(line, sizeof(line), "PKT: %lu/s", (unsigned long)g_pkt_rate.load());
            display.drawStr(0, 40, line);
            snprintf(line, sizeof(line), "DRP: %lu", (unsigned long)g_rssi_drops.load(std::memory_order_relaxed));
            display.drawStr(0, 50, line);
            snprintf(line, sizeof(line), "BAT: %u%%", (unsigned)g_batt_pct.load());
            display.drawStr(0, 60, line);
            break;
        }
    }

    display.sendBuffer();
}

static void do_deep_sleep(void) {
    Serial.println("[SLEEP] entering deep sleep");

    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(20, 30, "SLEEP ZZZ");
    display.drawStr(10, 45, "Hold BTN to wake");
    display.sendBuffer();

    esp_wifi_set_promiscuous(false);

    uint32_t flush_start = millis();
    while (uxQueueMessagesWaiting(g_write_queue) > 0 &&
           (millis() - flush_start) < 2000) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (h_write != NULL) vTaskSuspend(h_write);

    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
    SD.end();
    xSemaphoreGive(g_sd_mutex);

    vTaskDelay(pdMS_TO_TICKS(1000));

    esp_sleep_enable_ext0_wakeup((gpio_num_t)PIN_BTN, 0);
    // Hold GPIO4 high in sleep (internal digital pull-up is off then) so only a press to GND wakes.
    rtc_gpio_pullup_en((gpio_num_t)PIN_BTN);
    rtc_gpio_pulldown_dis((gpio_num_t)PIN_BTN);

    esp_deep_sleep_start();
}

void task_ui(void *arg) {
    configASSERT(xPortGetCoreID() == 1);
    esp_task_wdt_add(NULL);

    uint32_t last_oled = 0;
    uint32_t last_batt = 0;

    g_batt_pct.store(batt_read_pct());

    while (1) {
        esp_task_wdt_reset();
        uint32_t now = millis();

        if (g_sleep_req.load()) {
            g_sleep_req.store(false);
            do_deep_sleep();
        }

        btn_tick();
        led_tick();

        if (now - last_batt >= BATT_UPDATE_MS) {
            g_batt_pct.store(batt_read_pct());
            last_batt = now;
        }

        if (now - last_oled >= 200) {
            oled_draw();
            last_oled = now;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void selftest(bool sd_ok, bool gps_uart_ok, bool wifi_ok) {
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 10, "Self-test v" FW_VERSION);
    display.sendBuffer();
    delay(300);

    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v" FW_VERSION);
    char line[24];
    snprintf(line, sizeof(line), "SD:   %s", sd_ok ? "OK" : "FAIL");
    display.drawStr(0, 22, line);
    if (sd_ok) {
        xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
        uint64_t card = SD.cardSize();
        uint64_t used = SD.usedBytes();
        xSemaphoreGive(g_sd_mutex);
        uint32_t free_mb = (uint32_t)((card >= used ? card - used : 0) / (1024ULL * 1024ULL));
        snprintf(line, sizeof(line), "  free: %luMB", (unsigned long)free_mb);
        display.drawStr(0, 32, line);
    }
    display.sendBuffer();
    delay(600);

    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v" FW_VERSION);
    snprintf(line, sizeof(line), "GPS:  %s", gps_uart_ok ? "UART OK" : "N/A");
    display.drawStr(0, 22, line);
    display.sendBuffer();
    delay(600);

    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v" FW_VERSION);
    snprintf(line, sizeof(line), "HEAP: %luB", (unsigned long)ESP.getFreeHeap());
    display.drawStr(0, 22, line);
    display.sendBuffer();
    delay(600);

    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v" FW_VERSION);
    snprintf(line, sizeof(line), "WIFI: %s", wifi_ok ? "OK" : "FAIL");
    display.drawStr(0, 22, line);
    display.sendBuffer();
    delay(600);

    display.clearBuffer();
    display.drawStr(20, 25, "Cheapagotchi");
    display.drawStr(25, 40, "v" FW_VERSION " Ready");
    display.sendBuffer();
    delay(1000);
}
