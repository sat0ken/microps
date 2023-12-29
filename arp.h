#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include "ip.h"
#include "net.h"
#include "ether.h"

#define ARP_HRD_ETHER 0x0001

#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32
#define ARP_CACHE_TIMEOUT 30

#define ARP_CACHE_STATE_FREE        0
#define ARP_CACHE_STATE_INCOMPLETE  1
#define ARP_CACHE_STATE_RESOLVED    2
#define ARP_CACHE_STATE_STATIC      3

#define ARP_RESOLVE_ERROR       -1
#define ARP_RESOLVE_INCOMPLETE  0
#define ARP_RESOLVE_FOUND       1

// ARPヘッダ構造体
struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t  hln;
    uint8_t  pln;
    uint16_t op;
};

// APRメッセージ構造体
struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];
    uint8_t spa[IP_ADDR_LEN];
    uint8_t tha[ETHER_ADDR_LEN];
    uint8_t tpa[IP_ADDR_LEN];
};

// ARPキャッシュを保持する構造体
struct arp_cache {
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETHER_ADDR_LEN];
    struct timeval timestamp;
};

extern int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha);

extern int
arp_init(void);

#endif