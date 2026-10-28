// Definitions of the shared-state core + state_init().
#include "state.h"

static_assert(PKT_POOL_DEPTH    < 0xFF, "PKT_POOL_DEPTH too large: POOL_NONE sentinel invalid");
static_assert(HS_RAW_POOL_DEPTH < 0xFF, "HS_RAW_POOL_DEPTH too large: POOL_NONE sentinel invalid");

QueueHandle_t     g_pkt_free_q;
QueueHandle_t     g_hs_raw_free_q;
QueueHandle_t     g_ap_log_queue;
QueueHandle_t     g_pkt_queue;
QueueHandle_t     g_write_queue;
SemaphoreHandle_t g_hs_mutex;
SemaphoreHandle_t g_sd_mutex;
SemaphoreHandle_t g_gps_mutex;
portMUX_TYPE      g_ap_mux = portMUX_INITIALIZER_UNLOCKED;

uint8_t pkt_pool_mem    [PKT_POOL_DEPTH]   [MAX_PKT_LEN];
uint8_t hs_raw_pool_mem [HS_RAW_POOL_DEPTH][MAX_PKT_LEN];

uint8_t    g_ap_table[MAX_UNIQUE_APS][6];
hs_slot_t  g_hs[MAX_HS_SLOTS];
gps_fix_t  g_gps;

std::atomic<uint32_t> g_ap_count{0};
std::atomic<uint32_t> g_hs_count{0};
std::atomic<uint32_t> g_pkt_rate{0};
std::atomic<bool>     g_sd_ok{false};
std::atomic<int8_t>   g_last_rssi{0};
std::atomic<uint32_t> g_rssi_drops{0};
std::atomic<uint32_t> g_ap_log_drops{0};
std::atomic<uint32_t> g_hs_pool_drops{0};
std::atomic<bool>     g_sd_retry_req{false};
std::atomic<uint8_t>  g_display_page{0};
std::atomic<uint8_t>  g_batt_pct{0};
std::atomic<bool>     g_sleep_req{false};
std::atomic<bool>     g_last_write_ok{true};
std::atomic<uint8_t>  g_channel{1};
std::atomic<uint32_t> g_last_sd_retry{0};
std::atomic<led_state_t> g_led{LED_SLOW};
std::atomic<face_t>      g_face{FACE_NORMAL};
std::atomic<bool>     g_gps_available{false};
std::atomic<bool>     g_gps_fix{false};

U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

TaskHandle_t h_proc;
TaskHandle_t h_ui;
TaskHandle_t h_hop;
TaskHandle_t h_write;
TaskHandle_t h_gps;

void state_init(void) {
    g_pkt_free_q    = xQueueCreate(PKT_POOL_DEPTH,    sizeof(uint8_t));
    g_hs_raw_free_q = xQueueCreate(HS_RAW_POOL_DEPTH, sizeof(uint8_t));
    g_ap_log_queue  = xQueueCreate(AP_LOG_QUEUE_DEPTH, sizeof(ap_log_item_t));
    configASSERT(g_pkt_free_q);
    configASSERT(g_hs_raw_free_q);
    configASSERT(g_ap_log_queue);

    for (uint8_t i = 0; i < PKT_POOL_DEPTH; i++)
        xQueueSend(g_pkt_free_q, &i, 0);
    for (uint8_t i = 0; i < HS_RAW_POOL_DEPTH; i++)
        xQueueSend(g_hs_raw_free_q, &i, 0);

    g_pkt_queue   = xQueueCreate(PKT_QUEUE_DEPTH,   sizeof(pkt_item_t));
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH, sizeof(write_item_t));
    g_hs_mutex    = xSemaphoreCreateRecursiveMutex();
    g_sd_mutex    = xSemaphoreCreateMutex();
    g_gps_mutex   = xSemaphoreCreateMutex();
    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);
    configASSERT(g_hs_mutex);
    configASSERT(g_sd_mutex);
    configASSERT(g_gps_mutex);

    memset(g_hs,       0, sizeof(g_hs));
    memset(g_ap_table, 0, sizeof(g_ap_table));
    memset(&g_gps,     0, sizeof(g_gps));

    for (int i = 0; i < MAX_HS_SLOTS; i++)
        for (int j = 0; j < 4; j++)
            g_hs[i].raw_idx[j] = POOL_NONE;
}
