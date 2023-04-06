#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "icmp.h"
#include "arp.h"

uint bin_search(struct route_table_entry *route_table, uint route_table_len, in_addr_t daddr)
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

    return l;
}

void ip(int interface, char buf[MAX_PACKET_LEN], size_t len, in_addr_t int_ip,
        struct iphdr *ip_hdr, struct ether_header *eth_hdr,
        struct route_table_entry *route_table, int route_table_len,
        struct arp_entry *cache, uint cache_len, queue q, uint *q_len)
{
    checksum_t old = ntohs(ip_hdr->check);
    ip_hdr->check = htons(0);
    if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != old) {
        return;
    }

    ip_hdr->check = old;

    if (ip_hdr->ttl <= 1) {
        // ICMP
        icmp_msg(interface, buf, &len, ICMP_TIME_EXCEEDED, ICMP_NET_UNREACH);
        return;
    } else {
        --ip_hdr->ttl;
    }

    if (ip_hdr->daddr == int_ip) {
        // ICMP
        icmp_echo(interface, buf, &len);
        return;
    } else {
        // Search in route_table
        uint longest_pref_idx = bin_search(route_table, route_table_len, ip_hdr->daddr);

        struct route_table_entry *next_hop = NULL;

        if ((ip_hdr->daddr & route_table[longest_pref_idx].mask) == route_table[longest_pref_idx].prefix) {
            next_hop = &(route_table[longest_pref_idx]);
        }

        if (!next_hop) {
            // ICMP
            icmp_msg(interface, buf, &len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
            return;
        }

        ip_hdr->check = htons(0);
        ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

        // Search for MAC in the cache
        mac_t *d_mac = find_mac(next_hop->next_hop, cache, cache_len);

        if (!d_mac) {
            pack_t *pack = (pack_t *)malloc(sizeof(pack_t));
            memcpy(pack, buf, len);
            pack->len = len;
            queue_enq(q, pack);
            ++(*(q_len));

            // ARP
            arp_send_req(next_hop);
        } else {
            memcpy(eth_hdr->ether_dhost, d_mac, ETH_ALEN);
            get_interface_mac(next_hop->interface, eth_hdr->ether_shost);
            send_to_link(next_hop->interface, buf, len);
        }
    }
}