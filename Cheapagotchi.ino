/*
 * ESP32 Cheapagotchi — WPA/WPA2 Handshake Sniffer
 * Project: ESP32Gotchi | github: tworjaga | telegram: @al7exy
 *
 * Target  : ESP32 Dev Module (ESP32-WROOM-32, 30-pin)
 * Core    : esp32 by Espressif 2.0.x+
 * Libraries (install via Library Manager):
 *   - U8g2
 *   SD, SPI, WiFi, esp_wifi, FreeRTOS — bundled with core
 *
 * Arduino IDE:
 *   Board            : ESP32 Dev Module
 *   Partition scheme : Default 4MB with spiffs
 *   CPU freq         : 240 MHz
 */

/* --------------------------------------------------------------------------
 * Includes
 * -------------------------------------------------------------------------- */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SD.h>
#include <SPI.h>
#include <Wire.h>
#include <U8g2lib.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <esp_task_wdt.h>
#include <lwip/def.h>       /* ntohs / ntohl */

/* --------------------------------------------------------------------------
 * Pin map
 * -------------------------------------------------------------------------- */
#define PIN_OLED_SDA  21
#define PIN_OLED_SCL  22
#define PIN_SD_CS      5
#define PIN_SD_SCK    18
#define PIN_SD_MOSI   23
#define PIN_SD_MISO   19
#define PIN_BTN        0
#define PIN_LED        2

/* --------------------------------------------------------------------------
 * Tuning constants
 * -------------------------------------------------------------------------- */
#define PKT_QUEUE_DEPTH      64
#define WRITE_QUEUE_DEPTH     8
#define MAX_HS_SLOTS         32
#define MAX_UNIQUE_APS      100
#define CHANNEL_DWELL_MS    200
#define DEBOUNCE_MS          50
#define LONG_PRESS_MS      3000
#define SD_RETRY_MS       10000
#define MIN_FREE_BYTES    (1024ULL * 1024ULL)
#define WDT_TIMEOUT_S        30
#define CHANNELS_2G          11
#define MAX_PKT_LEN        1600
#define HS_EXPIRE_MS      30000

/* --------------------------------------------------------------------------
 * OLED instance  (hardware I2C, address 0x3C)
 * -------------------------------------------------------------------------- */
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

/* --------------------------------------------------------------------------
 * Packed structures
 * -------------------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct {
    uint8_t  revision;
    uint8_t  pad;
    uint8_t  len_lo;   /* radiotap header length, little-endian */
    uint8_t  len_hi;
    uint32_t present;
} radiotap_hdr_t;

typedef struct {
    uint8_t  fc0;      /* frame control byte 0 */
    uint8_t  fc1;      /* frame control byte 1 */
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr_t;

typedef struct {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t oui[3];
    uint8_t etype_hi;
    uint8_t etype_lo;
} llc_snap_hdr_t;

typedef struct {
    uint8_t version;
    uint8_t type;      /* 0x03 = Key */
    uint8_t len_hi;
    uint8_t len_lo;
} eapol_hdr_t;

typedef struct {
    uint8_t  descriptor;   /* 0x02 = RSN, 0xFE = WPA */
    uint8_t  ki_hi;        /* key_info high byte */
    uint8_t  ki_lo;        /* key_info low byte  */
    uint16_t key_length;
    uint8_t  replay_counter[8];
    uint8_t  nonce[32];
    uint8_t  iv[16];
    uint8_t  rsc[8];
    uint8_t  id[8];
    uint8_t  mic[16];
    uint16_t key_data_len;
} eapol_key_body_t;

typedef struct {
    uint32_t magic;        /* 0xa1b2c3d4 */
    uint16_t ver_major;    /* 2 */
    uint16_t ver_minor;    /* 4 */
    int32_t  thiszone;     /* 0 */
    uint32_t sigfigs;      /* 0 */
    uint32_t snaplen;      /* 65535 */
    uint32_t network;      /* 105 = IEEE 802.11 + radiotap */
} pcap_file_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_pkt_hdr_t;

#pragma pack(pop)

/* --------------------------------------------------------------------------
 * Queue / task items
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t *buf;   /* heap-allocated; receiver must free() */
    uint16_t len;
    uint8_t  ch;
} pkt_item_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  raw[4][MAX_PKT_LEN];
    uint16_t raw_len[4];
    bool     seen[4];
    bool     active;
    uint32_t last_ms;
} hs_slot_t;

typedef struct {
    hs_slot_t hs;   /* full value copy — no pointers */
} write_item_t;

/* --------------------------------------------------------------------------
 * Global state — all declared here to avoid any forward-reference issues
 * -------------------------------------------------------------------------- */
static QueueHandle_t     g_pkt_queue;
static QueueHandle_t     g_write_queue;
static SemaphoreHandle_t g_hs_mutex;
static SemaphoreHandle_t g_ap_mutex;

static hs_slot_t g_hs[MAX_HS_SLOTS];
static uint8_t   g_aps[MAX_UNIQUE_APS][6];

static volatile uint32_t g_ap_count      = 0;
static volatile uint32_t g_hs_count      = 0;
static volatile uint32_t g_pkt_rate      = 0;
static volatile uint8_t  g_channel       = 1;
static volatile bool     g_sd_ok         = false;
static volatile uint32_t g_last_sd_retry = 0;

typedef enum { LED_SLOW, LED_FAST, LED_FLASH, LED_ERROR } led_state_t;
static volatile led_state_t g_led = LED_SLOW;

typedef enum { FACE_NORMAL, FACE_CAPTURE, FACE_ERROR, FACE_IDLE } face_t;
static volatile face_t g_face = FACE_NORMAL;

static TaskHandle_t h_proc;
static TaskHandle_t h_ui;
static TaskHandle_t h_hop;
static TaskHandle_t h_write;

/* --------------------------------------------------------------------------
 * MAC helpers
 * -------------------------------------------------------------------------- */
static inline bool mac_eq(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}
static inline bool mac_zero(const uint8_t *a) {
    for (int i = 0; i < 6; i++) if (a[i]) return false;
    return true;
}
static void mac_str(const uint8_t *m, char *out) {
    sprintf(out, "%02x_%02x_%02x_%02x_%02x_%02x",
            m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* --------------------------------------------------------------------------
 * SD
 * -------------------------------------------------------------------------- */
static bool sd_init(void) {
    SPI.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
    if (!SD.begin(PIN_SD_CS)) {
        g_sd_ok = false;
        g_face  = FACE_ERROR;
        g_led   = LED_ERROR;
        Serial.println("[SD] init failed");
        return false;
    }
    g_sd_ok = true;
    if (g_face == FACE_ERROR) g_face = FACE_NORMAL;
    g_led = LED_SLOW;
    if (!SD.exists("/handshakes")) SD.mkdir("/handshakes");
    Serial.println("[SD] OK");
    return true;
}

static void pcap_write(hs_slot_t *hs) {
    if (!g_sd_ok) return;

    uint64_t free_b = (uint64_t)SD.cardSize() - (uint64_t)SD.usedBytes();
    if (free_b < MIN_FREE_BYTES) {
        Serial.println("[SD] low space");
        g_face = FACE_ERROR;
        return;
    }

    char bssid_s[24];
    mac_str(hs->bssid, bssid_s);
    uint32_t ts = millis() / 1000;
    char path[80];
    snprintf(path, sizeof(path), "/handshakes/hs_%s_%lu.pcap",
             bssid_s, (unsigned long)ts);

    File f = SD.open(path, FILE_WRITE);
    if (!f) {
        Serial.printf("[SD] open failed: %s\n", path);
        return;
    }

    pcap_file_hdr_t gh;
    gh.magic     = 0xa1b2c3d4;
    gh.ver_major = 2;
    gh.ver_minor = 4;
    gh.thiszone  = 0;
    gh.sigfigs   = 0;
    gh.snaplen   = 65535;
    gh.network   = 105;
    f.write((const uint8_t *)&gh, sizeof(gh));

    for (int i = 0; i < 4; i++) {
        if (!hs->seen[i] || hs->raw_len[i] == 0) continue;
        pcap_pkt_hdr_t ph;
        ph.ts_sec  = ts;
        ph.ts_usec = (uint32_t)i * 1000;
        ph.incl_len = hs->raw_len[i];
        ph.orig_len = hs->raw_len[i];
        f.write((const uint8_t *)&ph, sizeof(ph));
        f.write(hs->raw[i], hs->raw_len[i]);
    }

    f.close();
    g_hs_count++;
    g_led = LED_FLASH;
    Serial.printf("[HS] saved %s  total=%lu\n", path, (unsigned long)g_hs_count);
}

/* --------------------------------------------------------------------------
 * Unique AP tracker
 * -------------------------------------------------------------------------- */
static void ap_record(const uint8_t *bssid) {
    if (mac_zero(bssid)) return;
    if (xSemaphoreTake(g_ap_mutex, 0) != pdTRUE) return;
    for (uint32_t i = 0; i < g_ap_count; i++) {
        if (mac_eq(g_aps[i], bssid)) { xSemaphoreGive(g_ap_mutex); return; }
    }
    if (g_ap_count < MAX_UNIQUE_APS)
        memcpy(g_aps[g_ap_count++], bssid, 6);
    xSemaphoreGive(g_ap_mutex);
}

/* --------------------------------------------------------------------------
 * Handshake slot management  (caller must hold g_hs_mutex)
 * -------------------------------------------------------------------------- */
static hs_slot_t *hs_find_or_create(const uint8_t *bssid, const uint8_t *sta) {
    hs_slot_t *empty = NULL;
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active &&
            mac_eq(g_hs[i].bssid, bssid) &&
            mac_eq(g_hs[i].sta,   sta))
            return &g_hs[i];
        if (!g_hs[i].active && !empty)
            empty = &g_hs[i];
    }
    if (empty) {
        memset(empty, 0, sizeof(hs_slot_t));
        memcpy(empty->bssid, bssid, 6);
        memcpy(empty->sta,   sta,   6);
        empty->active  = true;
        empty->last_ms = millis();
    }
    return empty;
}

static void hs_expire(void) { /* caller holds g_hs_mutex */
    uint32_t now = millis();
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active && (now - g_hs[i].last_ms) > HS_EXPIRE_MS)
            g_hs[i].active = false;
    }
}

/* --------------------------------------------------------------------------
 * EAPOL message classifier
 *
 * IEEE 802.11-2020 §12.7.2 — key_info bit positions:
 *   bit 3  Key Type  (1 = pairwise)
 *   bit 6  Install
 *   bit 7  Key ACK
 *   bit 8  Key MIC
 *   bit 9  Secure
 *
 * 4-way messages:
 *   Msg1: pairwise, ACK=1, MIC=0, Install=0, Secure=0
 *   Msg2: pairwise, ACK=0, MIC=1, Install=0, Secure=0
 *   Msg3: pairwise, ACK=1, MIC=1, Install=1, Secure=1
 *   Msg4: pairwise, ACK=0, MIC=1, Install=0, Secure=1
 * -------------------------------------------------------------------------- */
static int eapol_msg_number(uint16_t ki) {
    bool pairwise = (ki >> 3) & 1;
    bool install  = (ki >> 6) & 1;
    bool ack      = (ki >> 7) & 1;
    bool mic      = (ki >> 8) & 1;
    bool secure   = (ki >> 9) & 1;

    if (!pairwise) return -1;

    if ( ack && !mic && !install && !secure) return 1;
    if (!ack &&  mic && !install && !secure) return 2;
    if ( ack &&  mic &&  install &&  secure) return 3;
    if (!ack &&  mic && !install &&  secure) return 4;
    return -1;
}

/* --------------------------------------------------------------------------
 * Core packet parser
 * -------------------------------------------------------------------------- */
static void process_packet(const uint8_t *buf, uint16_t len) {
    if (len < sizeof(radiotap_hdr_t)) return;

    /* Radiotap length — split bytes to avoid unaligned read */
    const radiotap_hdr_t *rt = (const radiotap_hdr_t *)buf;
    uint16_t rt_len = (uint16_t)rt->len_lo | ((uint16_t)rt->len_hi << 8);
    if (rt_len >= len) return;

    const uint8_t *mf  = buf + rt_len;
    uint16_t       mfl = len - rt_len;

    if (mfl < sizeof(dot11_hdr_t)) return;

    const dot11_hdr_t *dh = (const dot11_hdr_t *)mf;

    /*
     * 802.11 frame control byte 0:
     *   bits [1:0] protocol version
     *   bits [3:2] type  (0=mgmt, 1=ctrl, 2=data)
     *   bits [7:4] subtype
     * byte 1:
     *   bit 0 ToDS, bit 1 FromDS
     */
    uint8_t fc_type    = (dh->fc0 >> 2) & 0x03;
    uint8_t fc_subtype = (dh->fc0 >> 4) & 0x0F;
    uint8_t to_ds      =  dh->fc1       & 0x01;
    uint8_t from_ds    = (dh->fc1 >> 1) & 0x01;

    /* Management: track BSSIDs from beacons (8) and probe responses (5) */
    if (fc_type == 0 && (fc_subtype == 8 || fc_subtype == 5)) {
        ap_record(dh->addr3);
        return;
    }

    if (fc_type != 2) return;              /* only data frames from here */
    if (to_ds && from_ds)  return;         /* skip WDS 4-addr frames */

    /* Determine BSSID and STA */
    uint8_t bssid[6], sta[6];
    if (!to_ds && !from_ds) {
        memcpy(bssid, dh->addr3, 6);
        memcpy(sta,   dh->addr2, 6);
    } else if (from_ds) {
        memcpy(bssid, dh->addr2, 6);
        memcpy(sta,   dh->addr1, 6);
    } else {
        memcpy(bssid, dh->addr1, 6);
        memcpy(sta,   dh->addr2, 6);
    }

    if (mac_zero(bssid) || mac_zero(sta)) return;
    ap_record(bssid);

    /* Skip MAC header; add QoS field (2 bytes) if QoS data (subtype bit 3) */
    uint16_t mac_hdr_sz = (uint16_t)sizeof(dot11_hdr_t);
    if (fc_subtype & 0x08) mac_hdr_sz += 2;

    if (mfl < mac_hdr_sz + (uint16_t)sizeof(llc_snap_hdr_t)) return;

    const llc_snap_hdr_t *llc = (const llc_snap_hdr_t *)(mf + mac_hdr_sz);

    /* SNAP: DSAP=0xAA, SSAP=0xAA, EtherType=0x888E */
    if (llc->dsap != 0xAA || llc->ssap != 0xAA)       return;
    if (llc->etype_hi != 0x88 || llc->etype_lo != 0x8E) return;

    uint16_t eapol_off = mac_hdr_sz + (uint16_t)sizeof(llc_snap_hdr_t);
    if (mfl < eapol_off + (uint16_t)sizeof(eapol_hdr_t) +
                          (uint16_t)sizeof(eapol_key_body_t)) return;

    const eapol_hdr_t      *eh = (const eapol_hdr_t *)(mf + eapol_off);
    const eapol_key_body_t *ek = (const eapol_key_body_t *)
                                 (mf + eapol_off + sizeof(eapol_hdr_t));

    if (eh->type != 0x03) return;                              /* EAPOL-Key only */
    if (ek->descriptor != 0x02 && ek->descriptor != 0xFE) return; /* RSN or WPA */

    uint16_t ki  = ((uint16_t)ek->ki_hi << 8) | ek->ki_lo;
    int      msg = eapol_msg_number(ki);
    if (msg < 1 || msg > 4) return;

    /* --- Handshake slot update --- */
    bool      complete = false;
    hs_slot_t local_copy;

    if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(10)) != pdTRUE) return;

    hs_slot_t *slot = hs_find_or_create(bssid, sta);
    if (slot) {
        int idx = msg - 1;
        if (!slot->seen[idx]) {
            uint16_t cplen = (len > MAX_PKT_LEN) ? (uint16_t)MAX_PKT_LEN : len;
            memcpy(slot->raw[idx], buf, cplen);
            slot->raw_len[idx] = cplen;
            slot->seen[idx]    = true;
            slot->last_ms      = millis();
            Serial.printf("[HS] %02x:%02x:%02x -> %02x:%02x:%02x  msg%d\n",
                bssid[0], bssid[1], bssid[2],
                sta[0],   sta[1],   sta[2],   msg);
        }

        g_face = FACE_CAPTURE;
        g_led  = LED_FAST;

        if (slot->seen[0] && slot->seen[1] && slot->seen[2] && slot->seen[3]) {
            memcpy(&local_copy, slot, sizeof(hs_slot_t));
            slot->active = false;
            complete     = true;
        }
    }

    xSemaphoreGive(g_hs_mutex);

    if (complete) {
        write_item_t wi;
        memcpy(&wi.hs, &local_copy, sizeof(hs_slot_t));
        if (xQueueSend(g_write_queue, &wi, 0) != pdTRUE)
            Serial.println("[HS] write queue full, drop");
        g_face = FACE_NORMAL;
    }
}

/* --------------------------------------------------------------------------
 * Promiscuous callback — ISR context, must not block
 * -------------------------------------------------------------------------- */
static void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen == 0 || plen > MAX_PKT_LEN) return;

    uint8_t *copy = (uint8_t *)malloc(plen);
    if (!copy) return;
    memcpy(copy, pkt->payload, plen);

    pkt_item_t item = { copy, plen, g_channel };
    BaseType_t woken = pdFALSE;
    if (xQueueSendFromISR(g_pkt_queue, &item, &woken) != pdTRUE)
        free(copy);
    if (woken) portYIELD_FROM_ISR();
}

/* --------------------------------------------------------------------------
 * Task: packet processor  (core 0, priority 5)
 * -------------------------------------------------------------------------- */
static void task_proc(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t pkt_count   = 0;
    uint32_t rate_window = millis();

    while (1) {
        esp_task_wdt_reset();
        pkt_item_t item;
        if (xQueueReceive(g_pkt_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
            process_packet(item.buf, item.len);
            free(item.buf);
            pkt_count++;
        }

        uint32_t now = millis();
        if (now - rate_window >= 1000) {
            g_pkt_rate  = pkt_count;
            pkt_count   = 0;
            rate_window = now;

            if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                hs_expire();
                xSemaphoreGive(g_hs_mutex);
            }

            if (!g_sd_ok && (now - g_last_sd_retry) > SD_RETRY_MS) {
                g_last_sd_retry = now;
                sd_init();
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Task: SD writer  (core 0, priority 2)
 * Separate low-priority task: SD blocking does not stall packet processing
 * -------------------------------------------------------------------------- */
static void task_write(void *arg) {
    esp_task_wdt_add(NULL);
    while (1) {
        esp_task_wdt_reset();
        write_item_t wi;
        if (xQueueReceive(g_write_queue, &wi, pdMS_TO_TICKS(200)) == pdTRUE)
            pcap_write(&wi.hs);
    }
}

/* --------------------------------------------------------------------------
 * Task: channel hopper  (core 0, priority 3)
 * -------------------------------------------------------------------------- */
static void task_hop(void *arg) {
    esp_task_wdt_add(NULL);
    uint8_t ch = 1;
    while (1) {
        esp_task_wdt_reset();
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        g_channel = ch;
        ch = (ch % CHANNELS_2G) + 1;
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
    }
}

/* --------------------------------------------------------------------------
 * LED state machine — non-blocking, ~10 ms tick
 * -------------------------------------------------------------------------- */
static void led_tick(void) {
    static uint32_t last_ms   = 0;
    static bool     on        = false;
    static uint8_t  err_phase = 0;

    uint32_t now = millis();

    switch (g_led) {
        case LED_SLOW:
            if (now - last_ms >= 500) {
                on = !on;
                digitalWrite(PIN_LED, on ? HIGH : LOW);
                last_ms = now;
            }
            break;

        case LED_FAST:
            if (now - last_ms >= 100) {
                on = !on;
                digitalWrite(PIN_LED, on ? HIGH : LOW);
                last_ms = now;
            }
            break;

        case LED_FLASH:
            if (!on) {
                digitalWrite(PIN_LED, HIGH);
                on = true; last_ms = now;
            } else if (now - last_ms >= 120) {
                digitalWrite(PIN_LED, LOW);
                on = false; g_led = LED_SLOW;
            }
            break;

        case LED_ERROR:
            /* 3 x (ON 2 s / OFF 0.5 s), then 1 s gap, repeat */
            {
                uint32_t period;
                if      (err_phase == 6) period = 1000;
                else if (err_phase % 2 == 0) period = 2000;
                else                         period =  500;

                if (now - last_ms >= period) {
                    last_ms = now;
                    err_phase = (err_phase >= 6) ? 0 : err_phase + 1;
                    on = (err_phase % 2 == 0) && (err_phase < 6);
                    digitalWrite(PIN_LED, on ? HIGH : LOW);
                }
            }
            break;
    }
}

/* --------------------------------------------------------------------------
 * Button handler — non-blocking, ~10 ms tick
 * -------------------------------------------------------------------------- */
static void btn_tick(void) {
    static bool     prev     = HIGH;
    static uint32_t press_ms = 0;
    static uint32_t last_ms  = 0;

    uint32_t now = millis();
    if (now - last_ms < (uint32_t)DEBOUNCE_MS) return;
    last_ms = now;

    bool cur = digitalRead(PIN_BTN);

    if (prev == HIGH && cur == LOW) {
        press_ms = now;
    } else if (prev == LOW && cur == HIGH) {
        uint32_t dur = now - press_ms;
        if (dur >= (uint32_t)LONG_PRESS_MS) {
            Serial.println("[BTN] long press -> restart");
            ESP.restart();
        } else if (dur >= (uint32_t)DEBOUNCE_MS) {
            g_channel = 1;
            Serial.println("[BTN] short press -> ch=1");
        }
    }
    prev = cur;
}

/* --------------------------------------------------------------------------
 * OLED draw — called every 200 ms
 * Only ASCII used — compatible with u8g2_font_6x10_tf on all platforms
 * -------------------------------------------------------------------------- */
static void oled_draw(void) {
    static const char *faces[] = {
        "(o_o)",   /* FACE_NORMAL  */
        "(^o^)",   /* FACE_CAPTURE */
        "(X_X)",   /* FACE_ERROR   */
        "(-_-)"    /* FACE_IDLE    */
    };

    char line[24];
    face_t f = g_face;

    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);

    display.drawStr(0, 10, faces[f]);

    snprintf(line, sizeof(line), "HS:  %lu", (unsigned long)g_hs_count);
    display.drawStr(0, 22, line);

    snprintf(line, sizeof(line), "CH:  %u",  (unsigned)g_channel);
    display.drawStr(0, 32, line);

    snprintf(line, sizeof(line), "AP:  %lu", (unsigned long)g_ap_count);
    display.drawStr(0, 42, line);

    snprintf(line, sizeof(line), "PKT: %lu", (unsigned long)g_pkt_rate);
    display.drawStr(0, 52, line);

    display.drawStr(0, 62, g_sd_ok ? "SD:  OK" : "SD:  ERR");

    display.sendBuffer();
}

/* --------------------------------------------------------------------------
 * Task: UI  (core 1, priority 1)
 * -------------------------------------------------------------------------- */
static void task_ui(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t last_oled = 0;

    while (1) {
        esp_task_wdt_reset();
        uint32_t now = millis();

        btn_tick();
        led_tick();

        if (now - last_oled >= 200) {
            oled_draw();
            last_oled = now;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* --------------------------------------------------------------------------
 * setup()
 * -------------------------------------------------------------------------- */
void setup(void) {
    Serial.begin(115200);
    delay(200);
    Serial.println("\n[BOOT] ESP32 Cheapagotchi");

    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_BTN, INPUT_PULLUP);
    digitalWrite(PIN_LED, LOW);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "Booting...");
    display.sendBuffer();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    sd_init();

    g_pkt_queue   = xQueueCreate(PKT_QUEUE_DEPTH,  sizeof(pkt_item_t));
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH, sizeof(write_item_t));
    g_hs_mutex    = xSemaphoreCreateMutex();
    g_ap_mutex    = xSemaphoreCreateMutex();

    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);
    configASSERT(g_hs_mutex);
    configASSERT(g_ap_mutex);

    memset(g_hs,  0, sizeof(g_hs));
    memset(g_aps, 0, sizeof(g_aps));

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);

    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA |
                      WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        Serial.println("[WIFI] promiscuous failed -> restart");
        ESP.restart();
    }
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[WIFI] promiscuous active");

    xTaskCreatePinnedToCore(task_proc,  "pkt_proc", 8192, NULL, 5, &h_proc,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", 4096, NULL, 2, &h_write, 0);
    xTaskCreatePinnedToCore(task_hop,   "ch_hop",   2048, NULL, 3, &h_hop,   0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       4096, NULL, 1, &h_ui,    1);

    display.clearBuffer();
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "Running...");
    display.sendBuffer();

    Serial.println("[BOOT] tasks started");
    esp_task_wdt_delete(NULL);
}

/* --------------------------------------------------------------------------
 * loop() — idle; all logic in tasks
 * -------------------------------------------------------------------------- */
void loop(void) {
    vTaskDelay(portMAX_DELAY);
}