// SPDX-License-Identifier: EUPL-1.2
/* Copyright Mitran Andrei-Gabriel 2023 */

#include "icmp.h"

#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "ether.h"
#include "ip.h"

void update_checksum_icmp(struct icmphdr *icmp_hdr)
{
	// Puts 0 in the field to recalculate it
	icmp_hdr->checksum = htons(0);

	// Puts the new checksum in the header
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
}

void icmp_msg(int interface, char buf[MAX_PACKET_LEN], size_t *len, uint8_t type, uint8_t code)
{
	// Making a copy of the IP header and 64 bits (8 bytes), as per the standard RFC 792 (page 6)
	void *aux = (void *)malloc((sizeof(struct iphdr) + 8));
	memcpy(aux, buf + sizeof(struct ether_header), sizeof(struct iphdr) + 8);

	// The Ethernet header
	struct ether_header *eth_hdr = (struct ether_header *)buf;

	// Swaps the destination and source MAC addresses
	swap_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost);

	// The IP header
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Sets the protocol as ICMP
	ip_hdr->protocol = IPPROTO_ICMP;

	// Resets the TTL if it expired
	if (type == ICMP_TIME_EXCEEDED) {
		ip_hdr->ttl = 64;
	}

	// Recalculates the total length field
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

	// The destination's IP address is now the source's IP address
	ip_hdr->daddr = ip_hdr->saddr;

	// The source's IP address becomes the interface's IP address
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));

	update_checksum_ip(ip_hdr);

	// The ICMP header
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Setting the type and code
	icmp_hdr->type = type;
	icmp_hdr->code = code;

	update_checksum_icmp(icmp_hdr);

	// Copies the old IP header and 64 of the original bits
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
			aux, sizeof(struct iphdr) + 8);

	// Frees the memory used to store the old IP header and 64 of the original bits
	free(aux);

	// Recalculates the size of the packet
	*len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

	// Forwards the packet
	send_to_link(interface, buf, *len);
}

void icmp_echoreply(int interface, char buf[MAX_PACKET_LEN], size_t *len)
{
	// The ICMP header
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	
	// If the type of packet received is not echo, or the code is not 0, then drops the packet
	if (icmp_hdr->type != ICMP_ECHO || icmp_hdr->code) {
		return;
	}

	// The Ethernet header
	struct ether_header *eth_hdr = (struct ether_header *)buf;

	// Swaps the destination and source MAC adresses in Ethernet header
	swap_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost);

	// The IP header
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Recalculates the total length field
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	// The destination's IP address is now the source's IP address
	ip_hdr->daddr = ip_hdr->saddr;

	// The source's IP address becomes the interface's IP address
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));

	update_checksum_ip(ip_hdr);

	// Sets the type to an echo reply and the code to 0
	icmp_hdr->type = ICMP_ECHOREPLY;
	icmp_hdr->code = 0;

	update_checksum_icmp(icmp_hdr);

	// Forwards the packet
	send_to_link(interface, buf, *len);
}
