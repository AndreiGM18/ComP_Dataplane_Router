#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "icmp.h"

uint bin_search(struct route_table_entry *route_table, uint route_table_len, in_addr_t daddr)
{
    uint l = 0, r = route_table_len;

    while (l < r) {
        uint mid = (l + (r - l) / 2);

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
        mac_ip_t *cache, uint cache_len, queue q, uint *q_len)
{
    checksum_t old = ip_hdr->check;
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

        ttl_t old_ttl = ip_hdr->ttl;
        checksum_t old_check = ip_hdr->check;

        ++ip_hdr->ttl;

        ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

        // Search for MAC in the cache
        mac_t *d_mac = find_mac(next_hop->next_hop, cache, cache_len);

        if (!d_mac) {
            char payload[MAX_PACKET_LEN];
            memcpy(payload, buf, len);
            queue_enq(q, payload);
            ++(*(q_len));

            // ARP
        } else {
            memcpy(eth_hdr->ether_dhost, d_mac, ETH_ALEN);
            get_interface_mac(next_hop->interface, eth_hdr->ether_shost);
            send_to_link(next_hop->interface, buf, len);
        }
    }
}