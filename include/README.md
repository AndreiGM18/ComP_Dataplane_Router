**Name: Mitran Andrei-Gabriel**
**Group: 323CA**

## Homework #1 (Dataplane Router)

### Organization:
* This project aims to implement the dataplane part of a router.
The control plane part is not implemented in this project.

#### ARP
* ARP packets could be either Requests or Replies.
* When receiving an ARP Request, if it is intended for the router,
it responds accordingly, by sending an ARP Reply back.
* When receiving an ARP Reply, the router stores the new information
(the correspondence between the MAC and IP of the sender) in an ARP
entry cache. Additionally, all the packets that are stored in the
waiting queue are sent are now forwarded if they now have a valid
destination MAC address due to this new entry. If not, they are
put back in the queue.
* When dealing with the forwarding process, if the router does not
have the next hop's MAC address, an ARP Request is broadcasted, so
that this issues may be resolved. In the meantime, the packet is
stored in the waiting queue, so that further packets may be received.

#### IP
* Firstly, the checksum and TTL are checked. If either the
checksum or the TTL expired, the packet is thrown.
* In the case of an expired TTL (TTL <= 1), then a Time Exceeded ICMP
message is sent back to the source.
* If the final destination is the router, the protocol is ICMP and it
is an Echo request, then an ICMP Echo reply is sent back.
* Afterwards, the forwarding process starts. The checksum is
recalculated (due to decreasing the TTL) and the search for the next
hop starts.
* If it is not found, then a Host Unreachable ICMP message is sent back.
* If it is found, then the search for the hardware address starts.
* If it is not present in the cache, then an ARP Request is broadcasted
and the packet is put in the waiting queue (as explained in the ARP
section).
* If it is present, the packet is forwarded to the next hop.

#### ICMP
* The router only send ICMP Echo Replies and error messages.
* The Echo Reply is sent when an Echo Request intended for the router is
received.
* The error messages (as explained in the IP section) are sent when
needed. They also contain the original packet's IP header and 64 bits
of the original packet's data.

#### Efficient Longest Prefix Match
* As the routing table is static and contains up to 100000 entries, a
linear aproach to searching is inefficient.
* Initially, the routing table is sorted ascending by prefix and
descending by mask length (using the qsort function).
* For any query, binary search is used in order to efficiently find
the next hop.
* The complexity is thus reduced from O(n) (for each search) to
O(n * (log n)) (the sorting - qsort), then O(log n) for each search.

### Implementation:
* Every functionality required for this homework was implemented.

### Compilation:
* In order to compile, we use:
```
make
```

### Resources:
* Everything provided by the ComP team
* [Linux Manual](https://www.man7.org/linux/man-pages/index.html)