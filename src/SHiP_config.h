#pragma once

#define ARP_CACHE_NUMBER_OF_ENTRIES 32
#define LOG_MESSAGE_MAX_LENGTH 100

#define STATIC_ARP_CACHE \
    { .hardware_address = { 1, 2, 3, 4, 5, 6 }, .protocol_address = MAKE_IP_U32(10, 0, 0, 97) }, \
    { .hardware_address = { 1, 2, 3, 4, 5, 7 }, .protocol_address = MAKE_IP_U32(10, 0, 0, 98) }, \

#define LOGI(...) logger(__VA_ARGS__)
#define LOGD(...) logger(__VA_ARGS__)
// #define LOGV(...) logger(__VA_ARGS__)

