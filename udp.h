#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"
#include "sched.h"

#define UDP_PCB_SIZE 16
#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct udp_pseudo_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t sum;
};

struct udp_pcb {
    int state;
    struct ip_endpoint local;
    struct queue_head queue;
    // int wc;     // waitカウント(PCBを使用中のスレッド数)
    struct sched_ctx ctx;
};

struct udp_query_entry {
    struct ip_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

extern ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *buf, size_t len);

extern int
udp_init(void);

extern int
udp_open(void);

extern int
udp_bind(int id, struct ip_endpoint *local);

extern int
udp_close(int id);

extern ssize_t
udp_sendto(int fd, uint8_t *buf, size_t len, struct ip_endpoint *foreign);

extern ssize_t
udp_recvfrom(int fd, uint8_t *buf, size_t len, struct ip_endpoint *foreign);

#endif
