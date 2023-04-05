#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

void swap_mac(mac_t *mac_1, mac_t *mac_2)
{
    mac_t *aux = (mac_t *)malloc(ETH_ALEN * sizeof(mac_t));

    memcpy(aux, mac_1, ETH_ALEN);
    memcpy(mac_1, mac_2, ETH_ALEN);
    memcpy(mac_2, aux, ETH_ALEN);

    free(aux);
}

mac_t *find_mac(in_addr_t ip, mac_ip_t *cache, uint cache_len)
{
    for (uint i = 0; i < cache_len; ++i) {
        if (cache[i].ip == ip) {
            return cache[i].mac;
        }
    }

    return NULL;
}

int route_table_cmp(const void *x, const void *y)
{
    const struct route_table_entry *rt_1 = x;
    const struct route_table_entry *rt_2 = y;

    mask_t common = ntohl(rt_1->mask) & ntohl(rt_2->mask);

    bool equal = ((ntohl(rt_1->prefix) & common) == (ntohl(rt_2->prefix) & common));
    if (equal) {
        if (ntohl(rt_1->mask) < ntohl(rt_2->mask)) {
            return 1;
        } else {
            return -1;
        }
    } else {
        if ((ntohl(rt_1->prefix) & common) < (ntohl(rt_2->prefix) & common)) {
            return 1;
        } else {
            return -1;
        }
    }
}

bool is_equal_mac(mac_t *mac_1, mac_t *mac_2)
{
    for (int i = 0; i < ETH_ALEN; ++i) {
        if (*(mac_1 + i) != *(mac_2 + i)) {
            return false;
        }
    }

    return true;
}

bool is_broadcast(mac_t* mac)
{
    for (int i = 0; i < ETH_ALEN; ++i) {
        if (*(mac + i) != MAX_BYTE_VAL) {
            return false;
        }
    }

    return true;
}

bool check_mac(mac_t *dest_mac, mac_t *int_mac)
{
    if (!is_equal_mac(dest_mac, int_mac) && !is_broadcast(dest_mac)) {
        free(int_mac);
        return false;        
    }

    free(int_mac);
    return true;
}