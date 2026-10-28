// Core 802.11 parser, EAPOL classification, handshake-slot lifecycle (g_hs guarded by g_hs_mutex).
#include "handshake.h"
#include "state.h"
#include "ap_table.h"
#include "util.h"

#include <Arduino.h>
#include <string.h>

static hs_slot_t *hs_find_or_create(const uint8_t *bssid, const uint8_t *sta) {
    static uint32_t last_slot_create_ms = 0;
    hs_slot_t *empty = NULL;

    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        // Skip queued slots: they stay reserved until task_write frees them.
        if (g_hs[i].active && !g_hs[i].queued &&
            mac_eq(g_hs[i].bssid, bssid) && mac_eq(g_hs[i].sta, sta))
            return &g_hs[i];
        if (!g_hs[i].active && (empty == NULL))
            empty = &g_hs[i];
    }

    uint32_t now = millis();
    if ((now - last_slot_create_ms) < HS_NEW_SLOT_RATE_MS) return NULL;

    if (empty != NULL) {
        memset(empty, 0, sizeof(hs_slot_t));
        for (int i = 0; i < 4; i++) empty->raw_idx[i] = POOL_NONE;
        memcpy(empty->bssid, bssid, 6);
        memcpy(empty->sta,   sta,   6);
        empty->active       = true;
        empty->last_ms      = now;
        last_slot_create_ms = now;
    }
    return empty;
}

void hs_expire(void) {
    uint32_t now = millis();
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active && !g_hs[i].queued && (now - g_hs[i].last_ms) > HS_EXPIRE_MS) {
            for (int j = 0; j < 4; j++) {
                if (g_hs[i].raw_idx[j] != POOL_NONE) {
                    uint8_t ridx = g_hs[i].raw_idx[j];
                    xQueueSend(g_hs_raw_free_q, &ridx, 0);
                    g_hs[i].raw_idx[j] = POOL_NONE;
                }
            }
            g_hs[i].active = false;
        }
    }
}

typedef enum {
    EAPOL_MSG_INVALID = 0,
    EAPOL_MSG_1, EAPOL_MSG_2, EAPOL_MSG_3, EAPOL_MSG_4
} eapol_msg_t;

static eapol_msg_t eapol_msg_number(uint16_t ki) {
    bool pairwise = (ki >> 3) & 1;
    bool install  = (ki >> 6) & 1;
    bool ack      = (ki >> 7) & 1;
    bool mic      = (ki >> 8) & 1;
    bool secure   = (ki >> 9) & 1;

    if (!pairwise) return EAPOL_MSG_INVALID;
    if ( ack && !mic && !install && !secure) return EAPOL_MSG_1;
    if (!ack &&  mic && !install && !secure) return EAPOL_MSG_2;
    if ( ack &&  mic &&  install &&  secure) return EAPOL_MSG_3;
    if (!ack &&  mic && !install &&  secure) return EAPOL_MSG_4;
    return EAPOL_MSG_INVALID;
}

void process_packet(uint8_t pkt_pool_idx, uint16_t len) {
    const uint8_t *buf = pkt_pool_mem[pkt_pool_idx];

    if (len < 8) goto done;

    {
        const uint8_t *mf  = buf;
        uint16_t       mfl = len;

        if (mfl < 24) goto done;

        uint8_t fc0 = mf[0];
        uint8_t fc1 = mf[1];
        uint8_t fc_type    = (fc0 >> 2) & 0x03;
        uint8_t fc_subtype = (fc0 >> 4) & 0x0F;
        uint8_t to_ds      =  fc1       & 0x01;
        uint8_t from_ds    = (fc1 >> 1) & 0x01;

        const uint8_t *addr1 = mf + 4;
        const uint8_t *addr2 = mf + 10;
        const uint8_t *addr3 = mf + 16;

        if (fc_type == 0 && (fc_subtype == 8 || fc_subtype == 5)) {
            ap_record(addr3);
            goto done;
        }

        if (fc_type != 2) goto done;
        if ((to_ds != 0) && (from_ds != 0)) goto done;

        uint8_t bssid[6], sta[6];
        if ((to_ds == 0) && (from_ds == 0)) {
            memcpy(bssid, addr3, 6); memcpy(sta, addr2, 6);
        } else if (from_ds != 0) {
            memcpy(bssid, addr2, 6); memcpy(sta, addr1, 6);
        } else {
            memcpy(bssid, addr1, 6); memcpy(sta, addr2, 6);
        }

        if (mac_zero(bssid) || mac_zero(sta)) goto done;
        ap_record(bssid);

        uint16_t mac_hdr_sz = 24;
        if ((fc_subtype & 0x08) != 0) mac_hdr_sz += 2;

        if (mfl < mac_hdr_sz + 8) goto done;
        const uint8_t *llc = mf + mac_hdr_sz;
        if (llc[0] != 0xAA || llc[1] != 0xAA) goto done;
        if (llc[6] != 0x88 || llc[7] != 0x8E) goto done;

        uint16_t eapol_off = mac_hdr_sz + 8;
        // Need 3 bytes past eapol_off+4: ek[0] + read16_be(ek+1) over ek[1..2].
        if (mfl < eapol_off + 4 + 3) goto done;
        const uint8_t *eh = mf + eapol_off;
        if (eh[1] != 0x03) goto done;

        const uint8_t *ek = mf + eapol_off + 4;
        if (ek[0] != 0x02 && ek[0] != 0xFE) goto done;

        uint16_t    ki  = read16_be(ek + 1);
        eapol_msg_t msg = eapol_msg_number(ki);
        if (msg == EAPOL_MSG_INVALID) goto done;

        bool    complete = false;
        uint8_t done_idx = 0xFF;

        if (xSemaphoreTakeRecursive(g_hs_mutex, pdMS_TO_TICKS(10)) != pdTRUE) goto done;
        hs_slot_t *slot = hs_find_or_create(bssid, sta);
        if (slot != NULL) {
            int frame_idx = (int)msg - 1;
            if (!slot->seen[frame_idx]) {
                uint8_t rblk = POOL_NONE;
                xQueueReceive(g_hs_raw_free_q, &rblk, 0);
                if (rblk != POOL_NONE) {
                    uint16_t cplen = (len > MAX_PKT_LEN) ? (uint16_t)MAX_PKT_LEN : len;
                    memcpy(hs_raw_pool_mem[rblk], buf, cplen);
                    slot->raw_idx[frame_idx] = rblk;
                    slot->raw_len[frame_idx] = cplen;
                    slot->seen[frame_idx]    = true;
                    slot->last_ms            = millis();
                    Serial.printf("[HS] %02x:%02x:%02x -> %02x:%02x:%02x  msg%d\n",
                        bssid[0], bssid[1], bssid[2],
                        sta[0],   sta[1],   sta[2], (int)msg);
                } else {
                    g_hs_pool_drops.fetch_add(1, std::memory_order_relaxed);
                }
            }

            g_face.store(FACE_CAPTURE);
            g_led.store(LED_FAST);

            // Enqueue at most once: reserve via queued=true under the mutex so a
            // retransmission can't re-fire the completion test or be re-matched.
            if (!slot->queued &&
                slot->seen[0] && slot->seen[1] && slot->seen[2] && slot->seen[3]) {
                done_idx     = (uint8_t)(slot - g_hs);
                slot->queued = true;
                complete     = true;
            }
        }

        xSemaphoreGiveRecursive(g_hs_mutex);
        if (complete) {
            write_item_t wi = done_idx;
            if (xQueueSend(g_write_queue, &wi, 0) != pdTRUE) {
                Serial.println("[HS] write queue full, drop");
                if (xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY) == pdTRUE) {
                    for (int j = 0; j < 4; j++) {
                        if (g_hs[done_idx].raw_idx[j] != POOL_NONE) {
                            uint8_t ridx = g_hs[done_idx].raw_idx[j];
                            xQueueSend(g_hs_raw_free_q, &ridx, 0);
                            g_hs[done_idx].raw_idx[j] = POOL_NONE;
                        }
                    }
                    g_hs[done_idx].active = false;
                    g_hs[done_idx].queued = false;
                    xSemaphoreGiveRecursive(g_hs_mutex);
                }
            }
            g_face.store(FACE_NORMAL);
        }
    }

done:
    xQueueSend(g_pkt_free_q, &pkt_pool_idx, 0);
}
