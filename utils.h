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
#include <netinet/in.h>
#include <asm/byteorder.h>
#include <arpa/inet.h>

#define uint unsigned int
#define bool uint
#define true 1
#define false 0
#define mac_t uint8_t
#define ttl_t uint8_t
#define mask_t uint32_t
#define checksum_t uint16_t
#define MAX_BYTE_VAL 255
#define MAX_ROUTE_TABLE_ENTRIES 100000
#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHO 8
#define ICMP_NET_UNREACH 0
#define ICMP_DEST_UNREACH 3
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define IP_V4_LEN 4

typedef struct {
    mac_t mac[6];
    in_addr_t ip;
} mac_ip_t;

void set_broadcast(mac_t *mac);
void swap_ip(in_addr_t *ip_1, in_addr_t *ip_2);
void swap_mac(mac_t *mac_1, mac_t *mac_2);
mac_t *find_mac(in_addr_t ip, mac_ip_t *cache, uint cache_len);
int route_table_cmp(const void *x, const void *y);
bool is_equal_mac(mac_t *mac_1, mac_t *mac_2);
bool is_broadcast(mac_t* mac);
bool check_mac(mac_t *d_mac, mac_t *int_mac);

#endif