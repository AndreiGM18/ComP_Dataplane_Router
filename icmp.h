/* SPDX-License-Identifier: EUPL-1.2 */
/* Copyright Mitran Andrei-Gabriel 2023 */

#ifndef _ICMP_H_
#define _ICMP_H_

#include "include/queue.h"
#include "include/lib.h"
#include "utils.h"

/**
 * @brief Updates the ICMP header checksum
 * 
 * @param icmp_hdr the ICMP header
 */
void update_checksum_icmp(struct icmphdr *icmp_hdr);

/**
 * @brief Sends an ICMP error message
 * 
 * @param interface the interface from which the packet was received
 * @param buf the packet's payload
 * @param len the packet's size
 * @param type ICMP header's type field
 * @param code ICMP header's code field
 */
void icmp_msg(int interface, char buf[MAX_PACKET_LEN], size_t *len, uint8_t type, uint8_t code);

/**
 * @brief Sends an ICMP echo reply
 * 
 * @param interface the interface from which the packet was received
 * @param buf the packet's payload
 * @param len the packet's size
 */
void icmp_echoreply(int interface, char buf[MAX_PACKET_LEN], size_t *len);

#endif /* _ICMP_H_ */
