// SD mount + the SD writer task (the only task allowed to touch the SD filesystem).
#pragma once

bool sd_init(void);
void task_write(void *arg);
