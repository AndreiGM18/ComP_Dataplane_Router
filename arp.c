#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "ip.h"

void arp_reply(int interface, char buf[MAX_PACKET_LEN], size_t len, struct ether_header *eth_hdr, struct arp_header *arp_hdr)
{
    arp_hdr->op = htons(ARP_REPLY);
    memcpy(arp_hdr->tha, arp_hdr->sha, ETH_ALEN);
    in_addr_t aux = arp_hdr->tpa;
    arp_hdr->tpa = arp_hdr->spa;
    arp_hdr->spa = aux;
    get_interface_mac(interface, arp_hdr->sha);

    swap_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_shost, arp_hdr->sha, ETH_ALEN);

    send_to_link(interface, buf, len);
}

void arp_request(mac_ip_t *cache, uint *cache_len, queue q, uint *q_len, struct arp_header *arp_hdr, struct route_table_entry *route_table, uint route_table_len)
{
    cache[*cache_len].ip = arp_hdr->spa;
    memcpy(cache[*cache_len].mac, arp_hdr->sha, ETH_ALEN);
    ++(*cache_len);

    for (uint i = 0; i < *q_len; ++i) {
        void *payload = queue_deq(q);
        struct ether_header *eth_hdr_pay = (struct ether_header *)payload;
        struct iphdr *ip_hdr_pay = (struct iphdr *)(payload + sizeof(struct ether_header));

        uint longest_pref_idx = bin_search(route_table, route_table_len, ip_hdr_pay->daddr);
        if ((ip_hdr_pay->daddr & route_table[longest_pref_idx].mask) != route_table[longest_pref_idx].prefix) {
            continue;
        }
        struct route_table_entry *next_hop = &route_table[longest_pref_idx];

        mac_t *d_mac = find_mac(next_hop->next_hop, cache, *cache_len);

        if (!d_mac) {
            queue_enq(q, payload);
        } else {
            memcpy(eth_hdr_pay->ether_dhost, d_mac, ETH_ALEN);
            get_interface_mac(next_hop->interface, eth_hdr_pay->ether_shost);

            send_to_link(next_hop->interface, payload, MAX_PACKET_LEN);
            free(payload);
            --(*q_len);
        }
    }
}

void arp_send_req(struct route_table_entry *next_hop)
{
    char payload[MAX_PACKET_LEN];

    struct ether_header *eth_hdr = (struct ether_header *)payload;
    // set mac
    set_broadcast(eth_hdr->ether_dhost);
    get_interface_mac(next_hop->interface, eth_hdr->ether_shost);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    struct arp_header *arp_hdr = (struct arp_header *)(payload + sizeof(struct ether_header));
    arp_hdr->htype = htons(1);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = ETH_ALEN;
    arp_hdr->plen = IP_V4_LEN;
    arp_hdr->op = htons(ARP_REQUEST);
    memcpy(arp_hdr->sha, eth_hdr->ether_shost, ETH_ALEN);
    arp_hdr->spa = inet_addr(get_interface_ip(next_hop->interface));
    memset(arp_hdr->tha, 0, ETH_ALEN);
    arp_hdr->tpa = next_hop->next_hop;

    send_to_link(next_hop->interface, payload, sizeof(struct ether_header) + sizeof(struct arp_header));
}