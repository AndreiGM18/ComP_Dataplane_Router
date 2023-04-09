// SPDX-License-Identifier: EUPL-1.2
/* Copyright Mitran Andrei-Gabriel 2023 */

#include "ip.h"

#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "ether.h"
#include "icmp.h"
#include "arp.h"

void update_checksum_ip(struct iphdr *ip_hdr)
{
	// Puts 0 in the field to recalculate it
	ip_hdr->check = htons(0);

	// Puts the new checksum in the field
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
}

int route_table_cmp(const void *x, const void *y)
{
	const struct route_table_entry *rt_1 = x;
	const struct route_table_entry *rt_2 = y;

	// Gets the common mask
	mask_t common = ntohl(rt_1->mask) & ntohl(rt_2->mask);

	// Checks if equal
	bool equal = ((ntohl(rt_1->prefix) & common) == (ntohl(rt_2->prefix) & common));

	if (equal) {
		// The greater mask should be first
		if (ntohl(rt_1->mask) < ntohl(rt_2->mask)) {
			return 1;
		} else {
			return -1;
		}
	} else {
		if ((ntohl(rt_1->prefix) & common) < (ntohl(rt_2->prefix) & common)) {
			return -1;
		} else {
			return 1;
		}
	}
}

struct route_table_entry *bin_search(struct route_table_entry *route_table, uint route_table_len, in_addr_t daddr)
{
	uint l = 0, r = route_table_len;

	while (l < r) {
		uint mid = (l + r) / 2;

		if (ntohl(route_table[mid].prefix) < (ntohl(daddr) & ntohl(route_table[mid].mask))) {
			l = ++mid;
		} else {
			r = mid;
		}
	}

	// If it is found, returns a pointer to the entry
	if ((ntohl(daddr) & ntohl(route_table[l].mask)) == ntohl(route_table[l].prefix)) {
		return &route_table[l];
	}

	// Returns NULL if not
	return NULL;
}

void ip(int interface, char buf[MAX_PACKET_LEN], size_t len, in_addr_t int_ip,
		struct iphdr *ip_hdr, struct ether_header *eth_hdr,
		struct route_table_entry *route_table, int route_table_len,
		struct arp_entry *cache, uint cache_len, queue q, uint *q_len)
{
	// The current checksum
	checksum_t old = ntohs(ip_hdr->check);

	// Puts 0 in the field to recalculate it
	ip_hdr->check = htons(0);

	// Checks if the checksum is correct
	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != old) {
		// If it is not, the packet is dropped
		return;
	}

	// Puts it back
	ip_hdr->check = htons(old);

	// Packet's TTL expired
	if (ip_hdr->ttl <= 1) {
		// ICMP message: time exceeded and TTL exceeded in transit
		icmp_msg(interface, buf, &len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		return;
	}

	// Decreases the TTL
	--ip_hdr->ttl;

	/* Destination's MAC address matches the interface's and the protocol is ICMP,
	so an ICMP reply is sent */
	if (ip_hdr->daddr == int_ip && ip_hdr->protocol == IPPROTO_ICMP) {
		icmp_echoreply(interface, buf, &len);
		return;
	} else {
		// Searches in route_table for the next hop
		struct route_table_entry *next_hop = bin_search(route_table, route_table_len, ip_hdr->daddr);;

		// If it is not found
		if (!next_hop) {
			// ICMP message: destination unreachable and network unreachable
			icmp_msg(interface, buf, &len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
			return;
		}

		update_checksum_ip(ip_hdr);

		// Searches for the MAC in the cache
		mac_t *d_mac = find_mac(next_hop->next_hop, cache, cache_len);

		// If it is not found, then sends ARP request, else forwards the packet
		if (!d_mac) {
			// Stores the packet
			pack_t *pack = (pack_t *)malloc(sizeof(pack_t));
			memcpy(pack, buf, len);
			pack->len = len;

			// Puts it in the queue
			queue_enq(q, pack);

			// The queue's size is increased
			++(*(q_len));

			// Sends an ARP request
			arp_send_req(next_hop);
		} else {
			// Puts the destination's MAC in the Ethernet header
			memcpy(eth_hdr->ether_dhost, d_mac, ETH_ALEN);

			// Puts the source's MAC in the Ethernet header
			get_interface_mac(next_hop->interface, eth_hdr->ether_shost);

			// Forwards the packet
			send_to_link(next_hop->interface, buf, len);
		}
	}
}
