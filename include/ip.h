/* SPDX-License-Identifier: EUPL-1.2 */
/* Copyright Mitran Andrei-Gabriel 2023 */

#ifndef _IP_H_
#define _IP_H_

#include "queue.h"
#include "lib.h"
#include "utils.h"

/**
 * @brief Updates the IP header checksum
 * 
 * @param ip_hdr the IP header
 */
void update_checksum_ip(struct iphdr *ip_hdr);

/**
 * @brief Compares two routing table entries
 * 
 * @param x the first one
 * @param y the second one
 */
int route_table_cmp(const void *x, const void *y);

/**
 * @brief Binary search algorithm for searching the routing table
 * 
 * @param route_table the routing table
 * @param route_table_len the routing table's size
 * @param daddr the destination address that is being searched
 * 
 * @return pointer to the entry or NULL if it not found
 */
struct route_table_entry *bin_search(struct route_table_entry *route_table, uint route_table_len, in_addr_t daddr);

/**
 * @brief Handles IP packets
 * 
 * @param interface the interface from which the packet was received
 * @param buf the packet's payload
 * @param len the packet's size
 * @param int_ip the interface's IP address
 * @param ip_hdr the IP header
 * @param eth_hdr the Ethernet header
 * @param route_table the routing table
 * @param route_table_len the routing table's size
 * @param cache the cache in which ARP entries are stored
 * @param cache_len the cache's size
 * @param q the queue in which unsent packets are stored
 * @param q_len the queue's size
 */
void ip(int interface, char buf[MAX_PACKET_LEN], size_t len, in_addr_t int_ip,
	struct iphdr *ip_hdr, struct ether_header *eth_hdr,
	struct route_table_entry *route_table, int route_table_len,
	struct arp_entry *cache, uint cache_len, queue q, uint *q_len);

#endif /* _IP_H_ */
