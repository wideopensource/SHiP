#include "SHiP.h"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MTU_SIZE 1536

// https://www.kernel.org/doc/Documentation/networking/tuntap.txt

static int fd;

static uint8_t rx_buffer[MTU_SIZE];
static uint8_t tx_buffer[MTU_SIZE];

static int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tap", O_RDWR)) < 0)
    {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

static int system_with_interface_name(char const *command,
                                      char const *interface_name)
{
    char s[100];

    snprintf(s, sizeof(s), command, interface_name);

    return system(s);
}

static int send_callback(uint8_t const *data, int len)
{
    return len == write(fd, data, len);
}

static void udp_rx_callback(struct interface_t const *interface,
                            struct ethernet_frame_t *frame, uint8_t const *data,
                            int length, int destination_port,
                            uint32_t source_ip, int source_port)
{
    printf("udp_rx_callback: port: %d (<- %d), payload length: %d\n", destination_port,
           source_port, length);

    if (1234 == destination_port)
    {
        printf("udp_rx_callback: port 1234 handler\n");

        SHiP_send_udp(interface, "hello me!", 9, source_ip, 1729, 1234);
    }
}

static void tcp_rx_callback(struct interface_t const *interface,
                            struct ethernet_frame_t *frame, int frame_length)
{
    printf("tcp_rx_callback: frame length: %d\n", frame_length);
}

static void log_callback(char const *message)
{
    puts(message);
}

#define MAKE_U32_BE(A, B, C, D) (((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
#define MAKE_U32_LE(A, B, C, D) MAKE_U32_BE(D, C, B, A)
#define MAKE_IP_U32 MAKE_U32_LE

static void setup_virtual_subnet(char *interface_name)
{
    fd = tun_alloc(interface_name);

    system_with_interface_name("ip link set dev %s up", interface_name);
    system_with_interface_name("ip route add dev %s 10.0.0.0/24",
                               interface_name);
    system_with_interface_name("ip address add dev %s local 10.0.0.1/24",
                               interface_name);
}

int main(int argc, char **argv)
{
    char local_interface_name[10];
    setup_virtual_subnet(local_interface_name);

    struct SHiP_api const api = {
        .deliver_raw_frame_callback = send_callback,
        .udp_received_callback = udp_rx_callback,
        .tcp_received_callback = tcp_rx_callback,
        .log_callback = log_callback,
        .tx_buffer = tx_buffer,
        .tx_buffer_length = sizeof(tx_buffer),
    };

    SHiP_init(&api);

    struct interface_t const remote_interface = {
        .protocol_address = MAKE_IP_U32(10, 0, 0, 3),
        .hardware_address = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};

    printf("name; %s, hw: %02x, proto:%08x\n", local_interface_name,
           remote_interface.hardware_address[0],
           remote_interface.protocol_address);

    while (read(fd, rx_buffer, sizeof(rx_buffer)) >= 0)
    {
        SHiP_process_raw_frame(&remote_interface, rx_buffer);
    }

    return 0;
}
