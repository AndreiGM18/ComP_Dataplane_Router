// SPDX-License-Identifier: EUPL-1.2
/* Copyright Mitran Andrei-Gabriel 2023 */

#include "ether.h"

#include "queue.h"
#include "lib.h"
#include "utils.h"

void set_broadcast(mac_t *mac)
{
	for (uint i = 0; i < ETH_ALEN; ++i) {
		mac[i] = MAX_BYTE_VAL;
	}
}

void swap_mac(mac_t *mac_1, mac_t *mac_2)
{
	mac_t *aux = (mac_t *)malloc(ETH_ALEN * sizeof(mac_t));

	memcpy(aux, mac_1, ETH_ALEN);
	memcpy(mac_1, mac_2, ETH_ALEN);
	memcpy(mac_2, aux, ETH_ALEN);

	free(aux);
}

mac_t *find_mac(in_addr_t ip, struct arp_entry *cache, uint cache_len)
{
	for (uint i = 0; i < cache_len; ++i) {
		if ((in_addr_t)cache[i].ip == ip) {
			return cache[i].mac;
		}
	}

	return NULL;
}

bool is_equal_mac(mac_t *mac_1, mac_t *mac_2)
{
	for (int i = 0; i < ETH_ALEN; ++i) {
		if (*(mac_1 + i) != *(mac_2 + i)) {
			return false;
		}
	}

	return true;
}

bool is_broadcast(mac_t* mac)
{
	for (int i = 0; i < ETH_ALEN; ++i) {
		if (*(mac + i) != MAX_BYTE_VAL) {
			return false;
		}
	}

	return true;
}

bool check_mac(mac_t *dest_mac, mac_t *int_mac)
{
	if (!is_equal_mac(dest_mac, int_mac) && !is_broadcast(dest_mac)) {
		free(int_mac);
		return false;        
	}

	free(int_mac);
	return true;
}
