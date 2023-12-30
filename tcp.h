#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include "sched.h"

#define TCP_STATE_FREE          0
#define TCP_STATE_CLOSED        1
#define TCP_STATE_LISTEN        2
#define TCP_STATE_SYN_SENT      3
#define TCP_STATE_SYN_RECEIVED  4
#define TCP_STATE_ESTABLISHED   5
#define TCP_STATE_FIN_WAIT1     6
#define TCP_STATE_FIN_WAIT2     7
#define TCP_STATE_CLOSING       8
#define TCP_STATE_TIME_WAIT     9
#define TCP_STATE_CLOSE_WAIT    10
#define TCP_STATE_LAST_ACK      11

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
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

struct tcp_segment_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

struct tcp_pcb {
    int state;  // TCPコネクションの状態
    struct ip_endpoint local;
    struct ip_endpoint foreign;
    // 送信時に必要な情報
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss;
    // 受信時に必要な情報
    struct {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    uint8_t buf[65535];
    struct sched_ctx ctx;
};

extern int
tcp_init(void);

#endif