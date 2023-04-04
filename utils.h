#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <asm/byteorder.h>
#include <arpa/inet.h>

#define uint unsigned int
#define bool uint
#define true 1
#define false 0
#define mac_t uint8_t
#define mask_t uint32_t
#define MAX_BYTE_VAL 255
#define MAX_ROUTE_TABLE_ENTRIES 100000

typedef struct {
    mac_t mac[6];
    in_addr_t ip;
} mac_ip_t;

int route_table_cmp(const void *x, const void *y);
bool is_equal_mac(mac_t *mac_1, mac_t *mac_2);
bool is_broadcast(mac_t* mac);
bool check_mac(mac_t *d_mac, mac_t *int_mac);

#endif