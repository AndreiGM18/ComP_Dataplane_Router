/* SPDX-License-Identifier: EUPL-1.2 */
/* Copyright Mitran Andrei-Gabriel 2023 */

#ifndef _ETHER_H_
#define _ETHER_H_

#include "lib.h"
#include "utils.h"

/**
 * @brief Sets the MAC address as broadcast (ff:ff:ff:ff:ff:ff)
 * 
 * @param mac the MAC address
 */
void set_broadcast(mac_t *mac);

/**
 * @brief Swaps two MAC addresses
 * 
 * @param mac_1 the first MAC address
 * @param mac_2 the second MAC address
 */
void swap_mac(mac_t *mac_1, mac_t *mac_2);

/**
 * @brief Searches for the corresponding MAC address of the given IP address
 * in the cache
 * 
 * @param ip the IP
 * @param cache stores ARP entries
 * @param cache_len the cache's size
 * 
 * @return the MAC address found or NULL otherwise
 */
mac_t *find_mac(in_addr_t ip, struct arp_entry *cache, uint cache_len);

/**
 * @brief Checks if two MAC addresses are equal
 * 
 * @param mac_1 the first MAC address
 * @param mac_2 the second MAC address
 * 
 * @return true or false
 */
bool is_equal_mac(mac_t *mac_1, mac_t *mac_2);

/**
 * @brief Checks if two MAC addresses are equal
 * 
 * @param mac_1 the first MAC address
 * @param mac_2 the second MAC address
 * 
 * @return true or false
 */
bool is_broadcast(mac_t* mac);

/**
 * @brief Checks if a MAC address is valid for this router
 * 
 * @param d_mac the destination's MAC address
 * @param int_mac the interface's (from which the packet was received) MAC address
 * 
 * @return true or false
 */
bool check_mac(mac_t *d_mac, mac_t *int_mac);

#endif /* _ETHER_H_ */
