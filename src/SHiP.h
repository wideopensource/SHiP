#pragma once

#include <stdint.h>

struct interface_t
{
    uint32_t protocol_address;
    uint8_t hardware_address[6];
};

typedef int (*SHiP_send_callback_t)(uint8_t const *data, int length);
typedef void (*SHiP_log_callback_t)(char const *message);

void SHiP_init(SHiP_send_callback_t, SHiP_log_callback_t);
void SHiP_run(struct interface_t const *, uint8_t *data);

