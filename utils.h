/* SPDX-License-Identifier: EUPL-1.2 */
/* Copyright Mitran Andrei-Gabriel 2023 */

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
#include "include/protocols.h"

#define uint unsigned int

// Bool type defining
#define bool uint
#define true 1
#define false 0

// Type defining
#define mac_t uint8_t
#define mask_t uint32_t
#define checksum_t uint16_t

// Macros for protocols and max lengths
#define MAX_BYTE_VAL 0xff
#define MAX_ROUTE_TABLE_ENTRIES 100000
#define MAX_CACHE_ENTRIES 1000
#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMP_NET_UNREACH 0
#define ICMP_EXC_TTL 0
#define ICMP_DEST_UNREACH 3
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define IP_V4_LEN 4
#define ETHERNET 1

// Packet structure in which both the payload and size are stored
typedef struct {
	char payload[MAX_PACKET_LEN];
	size_t len;
} pack_t;

#endif /* _UTILS_H_ */
