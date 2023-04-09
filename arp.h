/* SPDX-License-Identifier: EUPL-1.2 */
/* Copyright Mitran Andrei-Gabriel 2023 */

#ifndef _ARP_H_
#define _ARP_H_

#include "queue.h"
#include "lib.h"
#include "utils.h"

/**
 * @brief Sends ARP replies
 * 
 * @param interface the interface from which the packet was received
 * @param buf the packet's payload
 * @param len the packet's size
 * @param eth_hdr the Ethernet header
 * @param arp_hdr the ARP header
 */
void arp_send_reply(int interface, char buf[MAX_PACKET_LEN], size_t len,
                    struct ether_header *eth_hdr, struct arp_header *arp_hdr);

/**
 * @brief Handles receiving ARP replies
 * 
 * @param cache the cache in which ARP entries are stored
 * @param cache_len the cache's size
 * @param q the queue in which unsent packets are stored
 * @param q_len the queue's size
 * @param arp_hdr the ARP header
 * @param route_table the routing table
 * @param route_table_len the routing table's size
 */
void arp_reply_handle(struct arp_entry *cache, uint *cache_len, queue q, uint *q_len,
                        struct arp_header *arp_hdr, struct route_table_entry *route_table,
                        uint route_table_len);

/**
 * @brief Sends ARP requests when the destination's MAC address of a packet
 * was not found in the cache
 * 
 * @param next_hop the routing table entry that does not have a MAC address
 * associated with the IP of its interface
 */
void arp_send_req(struct route_table_entry *next_hop);

#endif /* _ARP_H_ */
