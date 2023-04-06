#ifndef _ARP_H_
#define _ARP_H_

#include "queue.h"
#include "lib.h"
#include "utils.h"

void arp_reply(int interface, char buf[MAX_PACKET_LEN], size_t len, struct ether_header *eth_hdr, struct arp_header *arp_hdr);
void arp_request(struct arp_entry *cache, uint *cache_len, queue q, uint *q_len, struct arp_header *arp_hdr, struct route_table_entry *route_table, uint route_table_len);
void arp_send_req(struct route_table_entry *next_hop);

#endif