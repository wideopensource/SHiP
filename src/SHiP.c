#include "SHiP.h"
#include "SHiP_config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HTONS(V) (uint16_t)((V >> 8) | (V << 8))
#define NTOHS(V) (uint16_t)((V >> 8) | (V << 8))
#else
#define HTONS(V) (V)
#define NTOHS(V) (V)
#endif

#define INPLACE(M, V) V = M(V)

enum ethertype_enum
{
    ETHERTYPE_IPV4 = 0x0800,
    ETHERTYPE_ARP = 0x0806,
};

#define IPV4_PROTOCOL_VERSION 0x04
#define IPV4_HEADER_WORD_SIZE 4
#define IPV4_MINIMUM_HEADER_LENGTH_WORDS 5

#define IPV4_PROTOCOL_ICMPV4 0x01
#define IPV4_PROTOCOL_TCP 0x06
#define IPV4_PROTOCOL_UDP 0x11

#define UDP_HEADER_LENGTH 8
#define UDP_PORT_ECHO 7

#define TCP_PORT_ECHO 7

enum arp_constants_enum
{
    ARP_HARDWARE_TYPE_ETHERNET = 0x0001,
    ARP_PROTOCOL_TYPE_IPV4 = 0x0800,
    ARP_OPERATION_TYPE_REQUEST = 0x0001,
    ARP_OPERATION_TYPE_REPLY = 0x0002,
};

struct arp_frame_t
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_address_length;
    uint8_t protocol_address_length;
    uint16_t operation;
    uint8_t sender_hardware_address[6];
    uint32_t sender_protocol_address;
    uint8_t target_hardware_address[6];
    uint32_t target_protocol_address;
} __attribute__((packed));

struct arp_cache_entry_t
{
    uint32_t protocol_address;
    uint8_t hardware_address[6];
};

enum icmpv4_message_type_enum
{
    ICMPV4_MESSAGE_TYPE_ECHO_REPLY = 0x00,
    ICMPV4_MESSAGE_TYPE_ECHO_REQUEST = 0x08,
};

enum icmpv4_message_code_enum
{
    ICMPV4_MESSAGE_CODE_ECHO_REPLY = 0x00,
    ICMPV4_MESSAGE_CODE_ECHO_REQUEST = 0x00,
};

struct icmpv4_frame_t
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t payload[];
} __attribute__((packed));

#ifndef LOGE
#define LOGE(...) logger(__VA_ARGS__)
#endif
#ifndef LOGW
#define LOGW(...) logger(__VA_ARGS__)
#endif
#ifndef LOGI
#define LOGI(...)
#endif
#ifndef LOGD
#define LOGD(...)
#endif
#ifndef LOGV
#define LOGV(...)
#endif

uint8_t const *arp_lookup(uint32_t protocol_address);

#ifndef STATIC_ARP_CACHE
#define STATIC_ARP_CACHE
#endif

static struct arp_cache_entry_t arp_cache[ARP_CACHE_NUMBER_OF_ENTRIES] = {
    STATIC_ARP_CACHE};

static int arp_cache_next_entry_index = 2;
static struct SHiP_api _api;

static void logger(char *str, ...)
{
    va_list ap;
    va_start(ap, str);

    char buffer[LOG_MESSAGE_MAX_LENGTH];
    vsnprintf(buffer, sizeof(buffer), str, ap);

    va_end(ap);

    _api.log_callback(buffer);
}

// https://tools.ietf.org/html/rfc1071

static uint16_t ipv4_checksum(void const *addr, int count)
{
    uint16_t checksum = 0;

    {
        /* Compute Internet Checksum for "count" bytes
         *         beginning at location "addr".
         */
        uint32_t sum = 0;

        while (count > 1)
        {
            /*  This is the inner loop */
            sum += *(uint16_t *)addr;
            addr += 2;
            count -= 2;
        }

        /*  Add left-over byte, if any */
        if (count > 0)
        {
            sum += *(uint8_t *)addr;
        }

        /*  Fold 32-bit sum to 16 bits */
        while (sum >> 16)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        checksum = ~sum;
    }

    return checksum;
}

static void ethernet_send_from(struct interface_t const *interface,
                               struct ethernet_frame_t *frame,
                               uint16_t ethertype, int payload_length,
                               uint8_t const *destination_mac)
{
    frame->ethertype = HTONS(ethertype);

    memcpy(frame->source_mac, interface->hardware_address,
           sizeof(frame->source_mac));
    memcpy(frame->destination_mac, destination_mac,
           sizeof(frame->destination_mac));

    int const frame_length = sizeof(struct ethernet_frame_t) + payload_length;

    _api.event_callback(SHiP_EVENT_TYPE_DELIVER_FRAME, interface, frame,
                        frame_length);
}

void ipv4_send_from(struct interface_t const *interface,
                    struct ethernet_frame_t *frame, int payload_length,
                    uint32_t destination_ip)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;

    ipv4_frame->header_length = IPV4_MINIMUM_HEADER_LENGTH_WORDS;

    int const ipv4_frame_length =
        (ipv4_frame->header_length * IPV4_HEADER_WORD_SIZE) + payload_length;

    ipv4_frame->destination_ip = destination_ip;
    ipv4_frame->source_ip = interface->protocol_address;
    ipv4_frame->frame_length = ipv4_frame_length;

    ipv4_frame->flags = 0;
    ipv4_frame->identification = 0;
    ipv4_frame->version = IPV4_PROTOCOL_VERSION;
    ipv4_frame->time_to_live = 0xff;
    ipv4_frame->type_of_service = 0;

    INPLACE(HTONS, ipv4_frame->frame_length);

    ipv4_frame->header_checksum = 0;
    ipv4_frame->header_checksum = ipv4_checksum(ipv4_frame, ipv4_frame_length);

    uint8_t const *destination_mac = arp_lookup(ipv4_frame->destination_ip);
    if (destination_mac)
    {
        ethernet_send_from(interface, frame, ETHERTYPE_IPV4, ipv4_frame_length,
                           destination_mac);
    }
}

void udp_send_from(struct interface_t const *interface,
                   struct ethernet_frame_t *frame, uint8_t const *payload,
                   int payload_length, uint32_t destination_ip,
                   int destination_port, int source_port)
{
    int const udp_frame_length = UDP_HEADER_LENGTH + payload_length;

    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;
    struct udp_frame_t *udp_frame = (struct udp_frame_t *)ipv4_frame->payload;

    memcpy(udp_frame->payload, payload, payload_length);

    udp_frame->source_port = source_port;
    udp_frame->destination_port = destination_port;
    udp_frame->length = udp_frame_length;

    INPLACE(HTONS, udp_frame->source_port);
    INPLACE(HTONS, udp_frame->destination_port);
    INPLACE(HTONS, udp_frame->length);

    ipv4_frame->protocol = IPV4_PROTOCOL_UDP;

    ipv4_send_from(interface, frame, udp_frame_length, destination_ip);
}

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

static void icmpv4_handle_frame(struct interface_t const *interface,
                                struct ethernet_frame_t *frame,
                                int frame_length)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;
    struct icmpv4_frame_t *icmp_frame =
        (struct icmpv4_frame_t *)ipv4_frame->payload;

    int const icmpv4_frame_length =
        ipv4_frame->frame_length -
        (ipv4_frame->header_length * IPV4_HEADER_WORD_SIZE);

    if (ipv4_checksum(icmp_frame, icmpv4_frame_length))
    {
        LOGW("bad ICMPV4 checksum");
        // return; // todo foss: why is this often wrong?
    }

    switch (icmp_frame->type)
    {
    case ICMPV4_MESSAGE_TYPE_ECHO_REQUEST:
        LOGD("ICMP: ICMPV4_MESSAGE_TYPE_ECHO_REQUEST");

        icmp_frame->type = ICMPV4_MESSAGE_TYPE_ECHO_REPLY;
        icmp_frame->code = ICMPV4_MESSAGE_CODE_ECHO_REPLY;

        icmp_frame->checksum = 0;
        icmp_frame->checksum = ipv4_checksum(icmp_frame, icmpv4_frame_length);

        _api.event_callback(SHiP_EVENT_TYPE_PING, interface, frame,
                            frame_length);

        ipv4_send_from(interface, frame, icmpv4_frame_length,
                       ipv4_frame->source_ip);

        break;
    default:
        LOGW("unsupported ICMPV4 message type (%04x)", (int)icmp_frame->type);
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        return;
    }
}

// https://en.wikipedia.org/wiki/Transmission_Control_Protocol

static void tcp_handle_frame(struct interface_t const *interface,
                             struct ethernet_frame_t *frame, int frame_length)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;
    struct tcp_frame_t *tcp_frame = (struct tcp_frame_t *)ipv4_frame->payload;

    // todo foss: checksum

    unsigned const source_port = NTOHS(tcp_frame->source_port);
    unsigned const destination_port = NTOHS(tcp_frame->destination_port);
    int const ipv4_frame_length = ipv4_frame->frame_length;
    int const payload_length = ipv4_frame_length - sizeof(struct tcp_frame_t);

    LOGV("TCP: rx source port: %u, dest port: %u (%04x), payload length: %d",
         source_port, destination_port, destination_port, payload_length);

    _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                        frame_length);
}

// https://en.wikipedia.org/wiki/User_Datagram_Protocol
// https://en.wikipedia.org/wiki/Echo_Protocol

static void udp_handle_frame(struct interface_t const *interface,
                             struct ethernet_frame_t *frame, int frame_length)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;
    struct udp_frame_t *udp_frame = (struct udp_frame_t *)ipv4_frame->payload;

    // todo foss: UDP checksum calc seems a bit complicated

    unsigned const source_port = NTOHS(udp_frame->source_port);
    unsigned const destination_port = NTOHS(udp_frame->destination_port);
    int const udp_frame_length = NTOHS(udp_frame->length);
    int const payload_length = udp_frame_length - sizeof(struct udp_frame_t);

    if (UDP_PORT_ECHO == destination_port)
    {
        LOGD("returning ECHO request with '%.*s'", payload_length,
             (char *)udp_frame->payload);

        udp_frame->destination_port = udp_frame->source_port;
        udp_frame->source_port = HTONS(UDP_PORT_ECHO);

        _api.event_callback(SHiP_EVENT_TYPE_UDP_ECHO, interface, frame,
                            frame_length);

        ipv4_send_from(interface, frame, udp_frame_length,
                       ipv4_frame->source_ip);
    }
    else
    {
        LOGV("UDP rx source port: %u, dest port: %u (%04x), payload length: %d",
             source_port, destination_port, destination_port, payload_length);

        _api.udp_received_callback(interface, frame, udp_frame->payload,
                                   payload_length, destination_port,
                                   ipv4_frame->source_ip, source_port);
    }
}

static void ipv4_handle_frame(struct interface_t const *interface,
                              struct ethernet_frame_t *frame, int frame_length)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;

    if (ipv4_frame->version != IPV4_PROTOCOL_VERSION)
    {
        LOGW("IPV4: unsupported datagram version %d", (int)ipv4_frame->version);
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        return;
    }

    if (ipv4_frame->header_length < IPV4_MINIMUM_HEADER_LENGTH_WORDS)
    {
        LOGW("IPV4: unsupported header length %d", ipv4_frame->header_length);
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        return;
    }

    if (ipv4_frame->time_to_live == 0)
    {
        LOGW("IPV4: TTL is zero");
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        return;
    }

    int const header_length_bytes = ipv4_frame->header_length *
                                    IPV4_HEADER_WORD_SIZE;
    if (ipv4_checksum(ipv4_frame, header_length_bytes))
    {
        LOGW("IPV4: bad checksum");
        // return;
    }

    INPLACE(NTOHS, ipv4_frame->frame_length);

    switch (ipv4_frame->protocol)
    {
    case IPV4_PROTOCOL_ICMPV4:
        LOGV("IPV4: ICMPV4");
        icmpv4_handle_frame(interface, frame, frame_length);
        break;
    case IPV4_PROTOCOL_TCP:
        LOGV("IPV4: TCP");
        tcp_handle_frame(interface, frame, frame_length);
        break;
    case IPV4_PROTOCOL_UDP:
        LOGV("IPV4: UDP");
        udp_handle_frame(interface, frame, frame_length);
        break;
    default:
        LOGV("IPV4: unsupported protocol 0x02%x\n", (int)ipv4_frame->protocol);
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        break;
    }
}

// https://datatracker.ietf.org/doc/html/rfc826
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol

static void arp_cache_insert(struct arp_frame_t const *frame)
{
    struct arp_cache_entry_t *entry = arp_cache + arp_cache_next_entry_index++;
    arp_cache_next_entry_index %= ARP_CACHE_NUMBER_OF_ENTRIES;

    entry->protocol_address = frame->sender_protocol_address;
    memcpy(entry->hardware_address, frame->sender_hardware_address,
           sizeof(entry->hardware_address));
}

static int arp_cache_try_merge(struct arp_frame_t const *frame)
{
    for (int i = 0; i < ARP_CACHE_NUMBER_OF_ENTRIES; ++i)
    {
        struct arp_cache_entry_t *entry = arp_cache + i;

        if (entry->protocol_address == frame->sender_protocol_address)
        {
            memcpy(entry->hardware_address, frame->sender_hardware_address,
                   sizeof(entry->hardware_address));

            return 1;
        }
    }

    return 0;
}

uint8_t const *arp_lookup(uint32_t protocol_address)
{
    for (int i = 0; i < arp_cache_next_entry_index; ++i)
    {
        struct arp_cache_entry_t const *entry = arp_cache + i;

        if (entry->protocol_address == protocol_address)
        {
            return entry->hardware_address;
        }
    }

    LOGW("ARP: lookup failed for protocol address %08x", protocol_address);

    return 0;
}

static void arp_handle_frame(struct interface_t const *interface,
                             struct ethernet_frame_t *frame, int frame_length)
{
    struct arp_frame_t *arp_frame = (struct arp_frame_t *)frame->payload;
    INPLACE(NTOHS, arp_frame->operation);
    INPLACE(NTOHS, arp_frame->hardware_type);
    INPLACE(NTOHS, arp_frame->protocol_type);

    if (ARP_HARDWARE_TYPE_ETHERNET != arp_frame->hardware_type)
    {
        LOGW("ARP: unsupported hardware type (%d)",
             (int)arp_frame->hardware_type);
        return;
    }

    if (ARP_PROTOCOL_TYPE_IPV4 != arp_frame->protocol_type)
    {
        LOGW("ARP: unsupported protocol type (%d)",
             (int)arp_frame->protocol_type);
        return;
    }

    int const merged = arp_cache_try_merge(arp_frame);

    if (interface->protocol_address != arp_frame->target_protocol_address)
    {
        LOGV("ARP: request for some other IP");

        return;
    }

    if (!merged)
    {
        arp_cache_insert(arp_frame);
    }

    switch (arp_frame->operation)
    {
    case ARP_OPERATION_TYPE_REQUEST:
        LOGV("ARP: sending response");

        arp_frame->operation = ARP_OPERATION_TYPE_REPLY;
        INPLACE(HTONS, arp_frame->operation);
        INPLACE(HTONS, arp_frame->hardware_type);
        INPLACE(HTONS, arp_frame->protocol_type);

        arp_frame->target_protocol_address = arp_frame->sender_protocol_address;
        arp_frame->sender_protocol_address = interface->protocol_address;

        memcpy(arp_frame->target_hardware_address,
               arp_frame->sender_hardware_address,
               sizeof(arp_frame->target_hardware_address));
        memcpy(arp_frame->sender_hardware_address, interface->hardware_address,
               sizeof(arp_frame->sender_hardware_address));

        _api.event_callback(SHiP_EVENT_TYPE_ARP, interface, frame,
                            frame_length);

        ethernet_send_from(interface, frame, ETHERTYPE_ARP,
                           sizeof(struct arp_frame_t),
                           arp_frame->target_hardware_address);
        break;
    default:
        LOGV("ARP: unsupported opcode 0x%02x", arp_frame->operation);
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        break;
    }
}

static void ethernet_handle_frame(struct interface_t const *interface,
                                  struct ethernet_frame_t *frame,
                                  int frame_length)
{
    LOGD("ETH: length %d", frame_length);

    INPLACE(NTOHS, frame->ethertype);

    switch (frame->ethertype)
    {
    case ETHERTYPE_ARP:
        LOGD("ETH: ethertype 0x%04x (ARP)", frame->ethertype);
        arp_handle_frame(interface, frame, frame_length);
        break;
    case ETHERTYPE_IPV4:
        LOGD("ETH: ethertype 0x%04x (IPV4)", frame->ethertype);
        ipv4_handle_frame(interface, frame, frame_length);
        break;
    default:
        LOGD("ETH: unsupported ethertype 0x%04x", frame->ethertype);
        _api.event_callback(SHiP_EVENT_TYPE_FRAME_UNSUPPORTED, interface, frame,
                            frame_length);
        break;
    }
}

void SHiP_init(struct SHiP_api const *api)
{
    _api = *api;
}

void SHiP_process_raw_frame(struct interface_t const *interface, uint8_t *data,
                            int length)
{
    struct ethernet_frame_t *frame = (struct ethernet_frame_t *)data;

    ethernet_handle_frame(interface, frame, length);
}

void SHiP_send_udp(struct interface_t const *interface, uint8_t const *payload,
                   int payload_length, uint32_t destination_ip,
                   int destination_port, int source_port)
{
    struct ethernet_frame_t *frame = (struct ethernet_frame_t *)_api.tx_buffer;

    udp_send_from(interface, frame, payload, payload_length, destination_ip,
                  destination_port, source_port);
}

void SHiP_send_frame(struct interface_t const *interface,
                     struct ethernet_frame_t *frame, int frame_length)
{
    _api.event_callback(SHiP_EVENT_TYPE_DELIVER_FRAME, interface, frame,
                        frame_length);
}
