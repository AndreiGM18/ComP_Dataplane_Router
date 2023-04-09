// SPDX-License-Identifier: EUPL-1.2
/* Copyright Mitran Andrei-Gabriel 2023 */

#include "arp.h"

#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "ether.h"
#include "ip.h"

void arp_send_reply(int interface, char buf[MAX_PACKET_LEN], size_t len,
					struct ether_header *eth_hdr, struct arp_header *arp_hdr)
{
	// Sets the opcode to ARP reply
	arp_hdr->op = htons(ARP_REPLY);

	// Copies the sender's MAC address in the target address field
	memcpy(arp_hdr->tha, arp_hdr->sha, ETH_ALEN);

	// Sets the sender's MAC address as the interface's MAC address
	get_interface_mac(interface, arp_hdr->sha);

	// Swaps the target and sender's IP addresses
	in_addr_t aux = arp_hdr->tpa;
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = aux;

	// Sets the destination's MAC address as the source's MAC address (in the Ethernet header)
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
 
	/* Sets the source's MAC address (in the Ethernet header) the same as the
	source's MAC address (in the ARP header) */
	memcpy(eth_hdr->ether_shost, arp_hdr->sha, ETH_ALEN);

	// Forwards the packet
	send_to_link(interface, buf, len);
}

void arp_reply_handle(struct arp_entry *cache, uint *cache_len, queue q, uint *q_len,
						struct arp_header *arp_hdr, struct route_table_entry *route_table,
						uint route_table_len)
{
	/* Adds a new entry to the cache, setting the entrie's IP address as the sender's
	IP address (specified in the ARP header). */
	cache[*cache_len].ip = arp_hdr->spa;

	/* Copies the source's MAC address (specified in the ARP header) in the ARP
	entry's MAC field. Also increases the size of the cache (after copying) */
	memcpy(cache[(*cache_len)++].mac, arp_hdr->sha, ETH_ALEN);

	// Goes through all packets in the queue and sends the ones that can now be sent
	for (uint i = 0; i < *q_len; ++i) {
		// Gets a packet from the queue
		pack_t *pack = (pack_t *)queue_deq(q);

		// The packet's Ethernet header
		struct ether_header *eth_hdr_pack = (struct ether_header *)pack->payload;

		// The packet's IP header
		struct iphdr *ip_hdr_pack = (struct iphdr *)(pack->payload + sizeof(struct ether_header));

		// Finds the next hop
		struct route_table_entry *next_hop = bin_search(route_table, route_table_len, ip_hdr_pack->daddr);

		// Gets the corresponding MAC address of the next hop's next hop
		mac_t *d_mac = find_mac(next_hop->next_hop, cache, *cache_len);

		if (!d_mac) {
			// If it not found, puts the packet back in the queue
			queue_enq(q, pack);
		} else {
			// If it is found, copies the destination's MAC address in the Ethernet header
			memcpy(eth_hdr_pack->ether_dhost, d_mac, ETH_ALEN);

			// Sets the source's MAC address as the interface's MAC address
			get_interface_mac(next_hop->interface, eth_hdr_pack->ether_shost);

			// Forwards the packet
			send_to_link(next_hop->interface, pack->payload, pack->len);

			// Frees the structure
			free(pack);

			// Decreases the queue's size
			--(*q_len);
		}
	}
}

void arp_send_req(struct route_table_entry *next_hop)
{
	// The ARP packet's payload
	char payload[MAX_PACKET_LEN];

	// The Ethernet header
	struct ether_header *eth_hdr = (struct ether_header *)payload;

	// Sets the destination's MAC address as broadcast
	set_broadcast(eth_hdr->ether_dhost);

	// Sets the source's MAC address as the interface's MAC address
	get_interface_mac(next_hop->interface, eth_hdr->ether_shost);

	// Sets the Ethernet type to ARP
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// The ARP header
	struct arp_header *arp_hdr = (struct arp_header *)(payload + sizeof(struct ether_header));

	// Sets the format of the hardware address to Ethernet
	arp_hdr->htype = htons(ETHERNET);

	// Sets the format of the protocol address to IPv4
	arp_hdr->ptype = htons(ETHERTYPE_IP);

	// Sets the length of the hardware address to 6 bytes (the MAC address' length)
	arp_hdr->hlen = ETH_ALEN;

	// Sets the length of the protocol address to 4 bytes (the IPv4 address' length)
	arp_hdr->plen = IP_V4_LEN;

	// Sets the opcode to ARP request
	arp_hdr->op = htons(ARP_REQUEST);

	// Copies the source's MAC address in the sender MAC address field
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, ETH_ALEN);

	// Sets the sender's IP address as the IP address of the interface
	arp_hdr->spa = inet_addr(get_interface_ip(next_hop->interface));

	// Sets the target's MAC address as 00:00:00:00:00:00
	memset(arp_hdr->tha, 0, ETH_ALEN);

	// Sets the target's IP address as the next hop's next hop
	arp_hdr->tpa = next_hop->next_hop;

	// Forwards the packet
	send_to_link(next_hop->interface, payload, sizeof(struct ether_header) + sizeof(struct arp_header));
}
