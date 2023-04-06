#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "ip.h"
#include "arp.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *route_table = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * MAX_ROUTE_TABLE_ENTRIES);
	DIE(!route_table, "Route table malloc() failed!");

	uint route_table_len = read_rtable(argv[1], route_table);
	qsort(route_table, route_table_len, sizeof(struct route_table_entry), route_table_cmp);

	struct arp_entry *cache = (struct arp_entry *)malloc(sizeof(struct arp_entry) * MAX_ROUTE_TABLE_ENTRIES);
	DIE(!cache, "Cache malloc() failed");
	uint cache_len = 0;

	queue q = queue_create();
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

		mac_t *int_mac = (mac_t *)malloc(ETH_ALEN * sizeof(mac_t));
		DIE(!int_mac, "Interface MAC malloc() failed!");

		get_interface_mac(interface, int_mac);

		if (!check_mac(eth_hdr->ether_dhost, int_mac)) {
			continue;
		}
		
		in_addr_t int_ip = inet_addr(get_interface_ip(interface));

		// ARP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (arp_hdr->tpa == int_ip) {
				if (ntohs(arp_hdr->op) == ARP_REQUEST) {
					// do arp reply
					arp_reply(interface, buf, len, eth_hdr, arp_hdr);
				}

				if (ntohs(arp_hdr->op) == ARP_REPLY) {
					// do arp request
					arp_request(cache, &cache_len, q, &q_len, arp_hdr, route_table, route_table_len);
				}
			}

			continue;
		}

		// IP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr =  (struct iphdr *)(buf + sizeof(struct ether_header));
		
			// do ip
			ip(interface, buf, len, int_ip, ip_hdr, eth_hdr, route_table, route_table_len, cache, cache_len, q, &q_len);

			continue;
		}
	}

	free(q);
	free(cache);
	free(route_table);
}

