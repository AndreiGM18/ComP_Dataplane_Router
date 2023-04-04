#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

int route_table_cmp(const void *x, const void *y)
{
    const struct route_table_entry *rt_1 = x;
    const struct route_table_entry *rt_2 = y;

    mask_t common = ntohl(rt_1->mask) & ntohl(rt_2->mask);

    bool equal = (ntohl(rt_1->prefix) & common == (ntohl(rt_2->prefix)) & common);
    if (equal) {
        if (ntohl(rt_1->mask) < ntohl(rt_2->mask)) {
            return 1;
        } else {
            return -1;
        }
    } else {
        if (ntohl(rt_1->prefix) & common < (ntohl(rt_2->prefix)) & common) {
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