// Promiscuous RX callback + capture-side tasks (packet processor, channel hopper).
#pragma once

#include <esp_wifi.h>

void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type);
void task_proc(void *arg);
void task_hop(void *arg);
