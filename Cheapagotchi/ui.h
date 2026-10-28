// OLED/LED/button UI task and the boot self-test.
#pragma once

void selftest(bool sd_ok, bool gps_uart_ok, bool wifi_ok);
void task_ui(void *arg);
