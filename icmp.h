#ifndef _ICMP_H_
#define _ICMP_H_

#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

void icmp_msg(int interface, char buf[MAX_PACKET_LEN], size_t *len, uint8_t type, uint8_t code);
void icmp_echo(int interface, char buf[MAX_PACKET_LEN], size_t *len);

#endif