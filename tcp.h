#ifndef TCP_H
#define TCP_H

#include <stdint.h>

// ダミーヘッダの構造体
struct tcp_pseudo_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

// TCPヘッダの構造体
struct tcp_hdr {
    uint16_t src_addr;
    uint16_t dst_addr;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

extern int
tcp_init(void);

#endif