// Shared data structures and enums.
#pragma once

#include <stdint.h>

#define POOL_NONE 0xFF

typedef struct {
    uint8_t  pool_idx;
    uint16_t len;
    uint8_t  ch;
} pkt_item_t;

typedef uint8_t write_item_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  raw_idx[4];
    uint16_t raw_len[4];
    bool     seen[4];
    bool     active;
    bool     queued;
    uint32_t last_ms;
} hs_slot_t;

typedef struct {
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
} ap_log_item_t;

typedef struct {
    float    lat;
    float    lon;
    float    alt_m;
    float    hdop;
    uint8_t  sats;
    bool     valid;
    uint16_t year;
    uint8_t  month, day;
    uint8_t  hour, minute, second;
    bool     time_set;
    uint32_t last_fix_ms;
} gps_fix_t;

typedef enum { LED_SLOW, LED_FAST, LED_FLASH, LED_ERROR } led_state_t;
typedef enum { FACE_NORMAL, FACE_CAPTURE, FACE_ERROR, FACE_IDLE } face_t;
