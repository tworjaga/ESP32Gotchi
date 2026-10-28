// Promiscuous RX callback + packet-processor and channel-hopper tasks (core 0).
#include "capture.h"
#include "state.h"
#include "ap_table.h"
#include "handshake.h"

#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_task_wdt.h>
#include <string.h>

void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;
    if (rssi < (int8_t)RSSI_THRESHOLD) {
        g_rssi_drops.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_last_rssi.store(rssi, std::memory_order_relaxed);

    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen >= 4) plen -= 4;   // strip FCS
    if (plen == 0 || plen > MAX_PKT_LEN) return;

    if (type == WIFI_PKT_MGMT && plen >= 24) {
        const uint8_t *mf = pkt->payload;
        {
            uint8_t fc_subtype = (mf[0] >> 4) & 0x0F;
            if (fc_subtype == 8 || fc_subtype == 5) {   // beacon / probe response
                const uint8_t *bssid = mf + 16;
                BaseType_t woken = pdFALSE;
                if (ap_record(bssid)) {
                    ap_log_item_t item;
                    memcpy(item.bssid, bssid, 6);
                    item.rssi    = rssi;
                    item.channel = (uint8_t)g_channel.load(std::memory_order_relaxed);
                    if (xQueueSendFromISR(g_ap_log_queue, &item, &woken) != pdTRUE) {
                        g_ap_log_drops.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (woken == pdTRUE) portYIELD_FROM_ISR();
                }
            }
        }
    }

    uint8_t    pool_idx = POOL_NONE;
    BaseType_t woken    = pdFALSE;
    if (xQueueReceiveFromISR(g_pkt_free_q, &pool_idx, &woken) != pdTRUE) return;

    memcpy(pkt_pool_mem[pool_idx], pkt->payload, plen);

    pkt_item_t item = { pool_idx, plen, (uint8_t)g_channel.load(std::memory_order_relaxed) };
    if (xQueueSendFromISR(g_pkt_queue, &item, &woken) != pdTRUE) {
        xQueueSendFromISR(g_pkt_free_q, &pool_idx, &woken);
    }
    if (woken == pdTRUE) portYIELD_FROM_ISR();
}

void task_proc(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t pkt_count   = 0;
    uint32_t rate_window = millis();
    int      batch_count = 0;

    while (1) {
        esp_task_wdt_reset();
        pkt_item_t item;

        if (xQueueReceive(g_pkt_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
            process_packet(item.pool_idx, item.len);
            pkt_count++;
            batch_count++;
            if (batch_count >= TASK_PROC_BATCH_MAX) {
                batch_count = 0;
                taskYIELD();
            }
        } else {
            batch_count = 0;
        }

        uint32_t now = millis();
        if (now - rate_window >= 1000) {
            g_pkt_rate.store(pkt_count);

            // FACE_IDLE after a few idle seconds; restore on traffic. compare_exchange
            // only swaps the normal<->idle faces, so capture/error faces win.
            static uint8_t idle_secs = 0;
            if (pkt_count == 0) {
                if (idle_secs < 3) idle_secs++;
                if (idle_secs >= 3) {
                    face_t nf = FACE_NORMAL;
                    g_face.compare_exchange_strong(nf, FACE_IDLE);
                }
            } else {
                idle_secs = 0;
                face_t idf = FACE_IDLE;
                g_face.compare_exchange_strong(idf, FACE_NORMAL);
            }

            Serial.printf("[STAT] pkt/s=%lu  rssi=%ddBm  drops=%lu  thr=%ddBm  ap_log_drops=%lu  hs_pool_drops=%lu\n",
                (unsigned long)pkt_count,
                (int)g_last_rssi.load(std::memory_order_relaxed),
                (unsigned long)g_rssi_drops.load(std::memory_order_relaxed),
                RSSI_THRESHOLD,
                (unsigned long)g_ap_log_drops.load(std::memory_order_relaxed),
                (unsigned long)g_hs_pool_drops.load(std::memory_order_relaxed));
            pkt_count   = 0;
            rate_window = now;

            bool any_active = true;
            if (xSemaphoreTakeRecursive(g_hs_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                hs_expire();
                any_active = false;
                for (int i = 0; i < MAX_HS_SLOTS; i++) {
                    if (g_hs[i].active) { any_active = true; break; }
                }
                xSemaphoreGiveRecursive(g_hs_mutex);
            }
            // Drop stuck capture face/LED once nothing is capturing (CAS leaves error states alone).
            if (!any_active) {
                face_t cf = FACE_CAPTURE;
                g_face.compare_exchange_strong(cf, FACE_NORMAL);
                led_state_t cl = LED_FAST;
                g_led.compare_exchange_strong(cl, LED_SLOW);
            }

            if (!g_sd_ok.load() &&
                (now - g_last_sd_retry.load(std::memory_order_relaxed)) > SD_RETRY_MS) {
                g_last_sd_retry.store(now, std::memory_order_relaxed);
                g_sd_retry_req.store(true, std::memory_order_relaxed);
            }
        }
    }
}

void task_hop(void *arg) {
    configASSERT(xPortGetCoreID() == 0);
    esp_task_wdt_add(NULL);
    uint8_t ch = 1;
    while (1) {
        esp_task_wdt_reset();
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        g_channel.store(ch, std::memory_order_relaxed);
        ch = (ch % CHANNELS_2G) + 1;
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
    }
}
