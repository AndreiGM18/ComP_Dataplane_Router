// SPDX-License-Identifier: EUPL-1.2
/* Copyright Mitran Andrei-Gabriel and ComP team 2023 */

#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "ether.h"
#include "ip.h"
#include "arp.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Routing table
	struct route_table_entry *route_table =
		(struct route_table_entry *)malloc(sizeof(struct route_table_entry) * MAX_ROUTE_TABLE_ENTRIES);
	DIE(!route_table, "Route table malloc() failed!");

	// Reading the routing table and getting its length
	uint route_table_len = read_rtable(argv[1], route_table);

	// Sorting it using the comparator
	qsort(route_table, route_table_len, sizeof(struct route_table_entry), route_table_cmp);

	// The cache in which to store ARP entries
	struct arp_entry *cache = (struct arp_entry *)malloc(sizeof(struct arp_entry) * MAX_CACHE_ENTRIES);
	DIE(!cache, "Cache malloc() failed");

	// The cache's size is initially 0
	uint cache_len = 0;

	/* Creating a queue in which to store packets that cannot be currently sent due to
	not knowing the destination's MAC address */ 
	queue q = queue_create();

	// The queue's size is initially 0
	uint q_len = 0;

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// The interface's MAC
		mac_t *int_mac = (mac_t *)malloc(ETH_ALEN * sizeof(mac_t));
		DIE(!int_mac, "Interface MAC malloc() failed!");

		// Getting it
		get_interface_mac(interface, int_mac);

		/* Checking if the destination's MAC address matches the interface's MAC address
		or if it was a broadcast */
		if (!check_mac(eth_hdr->ether_dhost, int_mac)) {
			// If it is neither, the packet is dropped
			continue;
		}

		// The interface's IP address
		in_addr_t int_ip = inet_addr(get_interface_ip(interface));

		// ARP handling
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// The ARP header
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			// The ARP is meant for the router
			if (arp_hdr->tpa == int_ip) {
				if (ntohs(arp_hdr->op) == ARP_REQUEST) {
					// Sends an ARP Reply
					arp_send_reply(interface, buf, len, eth_hdr, arp_hdr);
				}

				if (ntohs(arp_hdr->op) == ARP_REPLY) {
					// Does ARP Reply handling
					arp_reply_handle(cache, &cache_len, q, &q_len, arp_hdr, route_table, route_table_len);
				}
			}

			// Drops the packet if it is not meant for this router
			continue;
		}

		// IP handling
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			// The IP header
			struct iphdr *ip_hdr =  (struct iphdr *)(buf + sizeof(struct ether_header));
		
			// Does IP handling
			ip(interface, buf, len, int_ip, ip_hdr, eth_hdr, route_table, route_table_len, cache, cache_len, q, &q_len);
		}
	}

	// Frees the allocated structures
	free(q);
	free(cache);
	free(route_table);
}
