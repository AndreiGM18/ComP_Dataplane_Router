#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

void icmp_msg(int interface, char buf[MAX_PACKET_LEN], size_t *len, uint8_t type, uint8_t code)
{
    void *aux = (void *)malloc(64 * sizeof(char));
    memcpy(aux, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 64);

    struct ether_header *eth_hdr = (struct ether_header *)buf;
    swap_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost);

    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    ip_hdr->protocol = IPPROTO_ICMP;

    if (type == ICMP_TIME_EXCEEDED) {
        ip_hdr->ttl = 64;
    }

    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = inet_addr(get_interface_ip(interface));
    ip_hdr->check = htons(0);
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    icmp_hdr->type = type;
    icmp_hdr->code = code;
    memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), aux, 64);
    free(aux);

    *len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
    icmp_hdr->checksum = htons(0);
    icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + 64);

    send_to_link(interface, buf, *len);
}

void icmp_echo(int interface, char buf[MAX_PACKET_LEN], size_t *len)
{
    struct ether_header *eth_hdr = (struct ether_header *)buf;
    swap_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost);

    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = inet_addr(get_interface_ip(interface));
    ip_hdr->check = htons(0);
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    if (icmp_hdr->type != ICMP_ECHO || icmp_hdr->code) {
        return;
    }

    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = htons(0);
    icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

    send_to_link(interface, buf, *len);
}