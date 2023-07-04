#pragma once

#include <stdint.h>

#define MAKE_U32_BE(A, B, C, D) (((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
#define MAKE_U32_LE(A, B, C, D) MAKE_U32_BE(D, C, B, A)
#define MAKE_IP_U32 MAKE_U32_LE

enum SHiP_event_type_enum
{
    SHiP_EVENT_TYPE_INVALID = 0,
    SHiP_EVENT_TYPE_DELIVER_FRAME,
    SHiP_EVENT_TYPE_FRAME_REJECTED,
    SHiP_EVENT_TYPE_FRAME_UNSUPPORTED,
    SHiP_EVENT_TYPE_ARP,
    SHiP_EVENT_TYPE_PING,
    SHiP_EVENT_TYPE_UDP_ECHO,
};

struct interface_t
{
    uint32_t protocol_address;
    uint8_t hardware_address[6];
};

struct ethernet_frame_t
{
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

struct ipv4_frame_t
{
    uint8_t header_length : 4;
    uint8_t version : 4;
    uint8_t type_of_service;
    uint16_t frame_length;
    uint16_t identification;
    uint16_t flags : 3;
    uint16_t fragment_offset : 13;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t payload[];
} __attribute__((packed));

struct udp_frame_t
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t payload[];
} __attribute__((packed));

struct tcp_frame_t
{
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint8_t payload[];
} __attribute__((packed));


typedef int (*SHiP_event_callback_t)(enum SHiP_event_type_enum, struct interface_t const *, struct ethernet_frame_t const *frame,
                                                 int frame_length);

typedef void (*SHiP_udp_received_callback_t)(
    struct interface_t const *, struct ethernet_frame_t *frame,
    uint8_t const *payload, int payload_length, int destination_port,
    uint32_t source_ip, int source_port);

typedef void (*SHiP_log_callback_t)(char const *message);

struct SHiP_api
{
    SHiP_event_callback_t event_callback;
    SHiP_udp_received_callback_t udp_received_callback;
    SHiP_log_callback_t log_callback;

    uint8_t *tx_buffer;
    int tx_buffer_length;
};

void SHiP_init(struct SHiP_api const *api);
void SHiP_process_raw_frame(struct interface_t const *, uint8_t *data, int length);
void SHiP_send_udp(struct interface_t const *, uint8_t const *data, int length,
                   uint32_t destination_ip, int destination_port,
                   int source_port);
void SHiP_send_frame(struct interface_t const *, struct ethernet_frame_t *frame,
                     int frame_length);
