// Shared-state core: queues, mutexes, pools, tables, atomics, display, tasks.
// Lock order: gps before sd; g_hs_mutex and g_ap_mux are leaf locks (never nested). g_sd_mutex is task_write only.
#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/portmacro.h>
#include <atomic>
#include <U8g2lib.h>

#include "config.h"
#include "types.h"

extern QueueHandle_t     g_pkt_free_q;
extern QueueHandle_t     g_hs_raw_free_q;
extern QueueHandle_t     g_ap_log_queue;
extern QueueHandle_t     g_pkt_queue;
extern QueueHandle_t     g_write_queue;
extern SemaphoreHandle_t g_hs_mutex;
extern SemaphoreHandle_t g_sd_mutex;
extern SemaphoreHandle_t g_gps_mutex;
extern portMUX_TYPE      g_ap_mux;

extern uint8_t pkt_pool_mem    [PKT_POOL_DEPTH]   [MAX_PKT_LEN];
extern uint8_t hs_raw_pool_mem [HS_RAW_POOL_DEPTH][MAX_PKT_LEN];

extern uint8_t    g_ap_table[MAX_UNIQUE_APS][6];
extern hs_slot_t  g_hs[MAX_HS_SLOTS];
extern gps_fix_t  g_gps;

extern std::atomic<uint32_t> g_ap_count;
extern std::atomic<uint32_t> g_hs_count;
extern std::atomic<uint32_t> g_pkt_rate;
extern std::atomic<bool>     g_sd_ok;
extern std::atomic<int8_t>   g_last_rssi;
extern std::atomic<uint32_t> g_rssi_drops;
extern std::atomic<uint32_t> g_ap_log_drops;
extern std::atomic<uint32_t> g_hs_pool_drops;
extern std::atomic<bool>     g_sd_retry_req;
extern std::atomic<uint8_t>  g_display_page;
extern std::atomic<uint8_t>  g_batt_pct;
extern std::atomic<bool>     g_sleep_req;
extern std::atomic<bool>     g_last_write_ok;
extern std::atomic<uint8_t>  g_channel;
extern std::atomic<uint32_t> g_last_sd_retry;
extern std::atomic<led_state_t> g_led;
extern std::atomic<face_t>      g_face;
extern std::atomic<bool>     g_gps_available;
extern std::atomic<bool>     g_gps_fix;

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C display;

extern TaskHandle_t h_proc;
extern TaskHandle_t h_ui;
extern TaskHandle_t h_hop;
extern TaskHandle_t h_write;
extern TaskHandle_t h_gps;

void state_init(void);
