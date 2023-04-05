#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

void ip(char buf[MAX_PACKET_LEN], size_t len, in_addr_t int_ip,
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
        return;
    } else {
        --ip_hdr->ttl;
    }

    if (ip_hdr->daddr == int_ip) {
        // ICMP
        return;
    } else {
        // Search in route_table
        uint longest_pref_idx = 0;

        struct route_table_entry *next_hop = NULL;

        if ((ip_hdr->daddr & route_table[longest_pref_idx].mask) == route_table[longest_pref_idx].prefix) {
            next_hop = &(route_table[longest_pref_idx]);
        }

        if (!next_hop) {
            // ICMP
            return;
        }

        ++ip_hdr->ttl;
        ip_hdr->check = htons(0);
        ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

        // Search for MAC in the cache
        mac_t *d_mac = NULL;

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