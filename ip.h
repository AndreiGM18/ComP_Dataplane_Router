#ifndef _IP_H_
#define _IP_H_

#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

uint bin_search(struct route_table_entry *route_table, uint route_table_len, in_addr_t daddr);
void ip(int interface, char buf[MAX_PACKET_LEN], size_t len, in_addr_t int_ip,
        struct iphdr *ip_hdr, struct ether_header *eth_hdr,
        struct route_table_entry *route_table, int route_table_len,
        mac_ip_t *cache, uint cache_len, queue q, uint *q_len);


#endif