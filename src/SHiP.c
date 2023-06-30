#include "SHiP.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARP_CACHE_NUMBER_OF_ENTRIES 32
#define LOG_MESSAGE_MAX_LENGTH 100

#if BYTE_ORDER == LITTLE_ENDIAN
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

struct ethernet_frame_t
{
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

#define IPV4_PROTOCOL_VERSION 0x04
#define IPV4_HEADER_WORD_SIZE 4
#define IPV4_MINIMUM_HEADER_LENGTH_WORDS 5

#define IPV4_PROTOCOL_ICMPV4 0x01
#define IPV4_PROTOCOL_UDP 0x11

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

uint8_t const *arp_lookup(uint32_t protocol_address);

static SHiP_send_callback_t _send_func;
static SHiP_log_callback_t _log_func;

#define LOGE(...) logger(__VA_ARGS__)
#define LOGW(...) logger(__VA_ARGS__)
#define LOGI(...) logger(__VA_ARGS__)
#define LOGD(...) logger(__VA_ARGS__)
#define LOGV(...) logger(__VA_ARGS__)

static void logger(char *str, ...)
{
    va_list ap;
    va_start(ap, str);

    char buffer[LOG_MESSAGE_MAX_LENGTH];
    vsnprintf(buffer, sizeof(buffer), str, ap);

    va_end(ap);

    _log_func(buffer);
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

    _send_func((uint8_t *)frame, frame_length);
}

void ipv4_send_from(struct interface_t const *interface,
                    struct ethernet_frame_t *frame, int payload_length,
                    uint32_t destination_ip)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;

    ipv4_frame->destination_ip = destination_ip;
    ipv4_frame->source_ip = interface->protocol_address;

    int const ipv4_frame_length =
        (ipv4_frame->header_length * IPV4_HEADER_WORD_SIZE) + payload_length;
    ipv4_frame->frame_length = HTONS(ipv4_frame_length);

    ipv4_frame->header_checksum = 0;
    ipv4_frame->header_checksum = ipv4_checksum(ipv4_frame, ipv4_frame_length);

    ethernet_send_from(interface, frame, ETHERTYPE_IPV4, ipv4_frame_length,
                       arp_lookup(ipv4_frame->destination_ip));
}

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

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

static void icmpv4_handle_frame(struct interface_t const *interface,
                                struct ethernet_frame_t *frame)
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
        return;
    }

    switch (icmp_frame->type)
    {
    case ICMPV4_MESSAGE_TYPE_ECHO_REQUEST:
        LOGD("ICMPV4_MESSAGE_TYPE_ECHO_REQUEST");

        icmp_frame->type = ICMPV4_MESSAGE_TYPE_ECHO_REPLY;
        icmp_frame->code = ICMPV4_MESSAGE_CODE_ECHO_REPLY;

        icmp_frame->checksum = 0;
        icmp_frame->checksum = ipv4_checksum(icmp_frame, icmpv4_frame_length);

        ipv4_send_from(interface, frame, icmpv4_frame_length,
                       ipv4_frame->source_ip);

        break;
    default:
        LOGW("unsupported ICMPV4 message type (%04x)", (int)icmp_frame->type);
        return;
    }
}

// https://en.wikipedia.org/wiki/User_Datagram_Protocol
// https://en.wikipedia.org/wiki/Echo_Protocol

struct udp_frame_t
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t payload[];
} __attribute__((packed));

#define UDP_PORT_ECHO 7

static void udp_handle_frame(struct interface_t const *interface,
                             struct ethernet_frame_t *frame)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;
    struct udp_frame_t *udp_frame = (struct udp_frame_t *)ipv4_frame->payload;

    NTOHS_INPLACE(udp_frame->source_port);
    NTOHS_INPLACE(udp_frame->destination_port);
    NTOHS_INPLACE(udp_frame->length);

    int const udp_frame_length = udp_frame->length;
    int const udp_payload_length = udp_frame_length -
                                   sizeof(struct udp_frame_t);

    LOGV("UDP rx source port: %d, dest port: %d, payload length: %d",
         (int)udp_frame->source_port, (int)udp_frame->destination_port,
         udp_payload_length);

    // todo crz: UDP checksum calc seems a bit complicated

    if (UDP_PORT_ECHO == udp_frame->destination_port)
    {
        LOGD("returning ECHO request with '%.*s'", udp_payload_length,
             (char *)udp_frame->payload);

        udp_frame->destination_port = udp_frame->source_port;
        udp_frame->source_port = UDP_PORT_ECHO;

        HTONS_INPLACE(udp_frame->source_port);
        HTONS_INPLACE(udp_frame->destination_port);
        HTONS_INPLACE(udp_frame->length);

        ipv4_send_from(interface, frame, udp_frame_length,
                       ipv4_frame->source_ip);
    }
    else
    {
        // todo crz: do something fun with UDP
    }
}

static void ipv4_handle_frame(struct interface_t const *interface,
                              struct ethernet_frame_t *frame)
{
    struct ipv4_frame_t *ipv4_frame = (struct ipv4_frame_t *)frame->payload;

    if (ipv4_frame->version != IPV4_PROTOCOL_VERSION)
    {
        LOGW("bad IPV4 datagram version");
        return;
    }

    if (ipv4_frame->header_length < IPV4_MINIMUM_HEADER_LENGTH_WORDS)
    {
        LOGW("bad IPV4 header length");
        return;
    }

    if (ipv4_frame->time_to_live == 0)
    {
        LOGW("IPV4 TTL is zero");
        return;
    }

    int const header_length_bytes = ipv4_frame->header_length *
                                    IPV4_HEADER_WORD_SIZE;
    if (ipv4_checksum(ipv4_frame, header_length_bytes))
    {
        LOGW("bad IPV4 checksum");
        return;
    }

    NTOHS_INPLACE(ipv4_frame->frame_length);

    switch (ipv4_frame->protocol)
    {
    case IPV4_PROTOCOL_ICMPV4:
        LOGD("IPV4 ICMPV4");
        icmpv4_handle_frame(interface, frame);
        break;
    case IPV4_PROTOCOL_UDP:
        LOGD("IPV4 UDP");
        udp_handle_frame(interface, frame);
        break;
    default:
        LOGV("unhandled IPv4 protocol 0x02%x\n", (int)ipv4_frame->protocol);
        break;
    }
}

// https://datatracker.ietf.org/doc/html/rfc826
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol

enum arp_constants_enum
{
    ARP_HARDWARE_TYPE_ETHERNET = 0x0001,
    ARP_PROTOCOL_TYPE_IPV4 = 0x0800,
    ARP_OPERATION_TYPE_REQUEST = 0x0001,
    ARP_OPERATION_TYPE_REPLY = 0x0002,
};

enum arp_cache_entry_state_enum
{
    ARP_CACHE_ENTRY_STATE_FREE = 0,
    ARP_CACHE_ENTRY_STATE_WAITING,
    ARP_CACHE_ENTRY_STATE_RESOLVED,
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

static struct arp_cache_entry_t arp_cache[ARP_CACHE_NUMBER_OF_ENTRIES];
static int arp_cache_next_entry_index = 0;

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
    for (int i = 0; i < ARP_CACHE_NUMBER_OF_ENTRIES; ++i)
    {
        struct arp_cache_entry_t const *entry = arp_cache + i;

        if (entry->protocol_address == protocol_address)
        {
            return entry->hardware_address;
        }
    }

    return 0;
}

static void arp_handle_frame(struct interface_t const *interface,
                             struct ethernet_frame_t *frame)
{
    struct arp_frame_t *arp_frame = (struct arp_frame_t *)frame->payload;
    NTOHS_INPLACE(arp_frame->hardware_type);
    NTOHS_INPLACE(arp_frame->protocol_type);
    NTOHS_INPLACE(arp_frame->operation);

    if (ARP_HARDWARE_TYPE_ETHERNET != arp_frame->hardware_type)
    {
        LOGW("wrong hardware type (%d)", (int)arp_frame->hardware_type);
        return;
    }

    if (ARP_PROTOCOL_TYPE_IPV4 != arp_frame->protocol_type)
    {
        LOGW("wrong protocol type (%d)", (int)arp_frame->protocol_type);
        return;
    }

    int const merged = arp_cache_try_merge(arp_frame);

    if (interface->protocol_address != arp_frame->target_protocol_address)
    {
        LOGV("ARP request for some other IP");

        return;
    }

    if (!merged)
    {
        arp_cache_insert(arp_frame);
    }

    switch (arp_frame->operation)
    {
    case ARP_OPERATION_TYPE_REQUEST:
        LOGV("sending ARP response");

        arp_frame->operation = ARP_OPERATION_TYPE_REPLY;
        HTONS_INPLACE(arp_frame->operation);
        HTONS_INPLACE(arp_frame->hardware_type);
        HTONS_INPLACE(arp_frame->protocol_type);

        arp_frame->target_protocol_address = arp_frame->sender_protocol_address;
        arp_frame->sender_protocol_address = interface->protocol_address;

        memcpy(arp_frame->target_hardware_address,
               arp_frame->sender_hardware_address,
               sizeof(arp_frame->target_hardware_address));
        memcpy(arp_frame->sender_hardware_address, interface->hardware_address,
               sizeof(arp_frame->sender_hardware_address));

        ethernet_send_from(interface, frame, ETHERTYPE_ARP,
                           sizeof(struct arp_frame_t),
                           arp_frame->target_hardware_address);
        break;
    default:
        LOGV("unhandled ARP opcode (0x%02x)", arp_frame->operation);
        break;
    }
}

static void ethernet_handle_frame(struct interface_t const *interface,
                                  struct ethernet_frame_t *frame)
{
    NTOHS_INPLACE(frame->ethertype);

    switch (frame->ethertype)
    {
    case ETHERTYPE_ARP:
        LOGD("ethertype: ARP");
        arp_handle_frame(interface, frame);
        break;
    case ETHERTYPE_IPV4:
        LOGD("ethertype: IPV4");
        ipv4_handle_frame(interface, frame);
        break;
    default:
        LOGV("unhandled ethertype: %04x", frame->ethertype);
        break;
    }
}

void SHiP_init(SHiP_send_callback_t send_func, SHiP_log_callback_t log_func)
{
    _send_func = send_func;
    _log_func = log_func;

    memset(arp_cache, 0,
           ARP_CACHE_NUMBER_OF_ENTRIES * sizeof(struct arp_cache_entry_t));
}

void SHiP_run(struct interface_t const *interface, uint8_t *data)
{
    struct ethernet_frame_t *frame = (struct ethernet_frame_t *)data;

    ethernet_handle_frame(interface, frame);
}
