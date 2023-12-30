#include <stdio.h>

#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == y)
#define TCP_FLG_ISSET(x, y) ((x & 0x3f & (y) ? 1 : 0))

static char *
tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');

    return str;
}

static void
tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;
    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, " src: %u\n", ntoh16(hdr->src_addr));
    fprintf(stderr, " dst: %u\n", ntoh16(hdr->dst_addr));
    fprintf(stderr, " seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, " ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, " off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, " flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, " wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, " sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, " up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src_addr, ip_addr_t dst_addr, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct tcp_pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;
    pseudo.src_addr = src_addr;
    pseudo.dst_addr = dst_addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    if (src_addr == IP_ADDR_BROADCAST || src_addr == iface->broadcast || dst_addr == IP_ADDR_BROADCAST || dst_addr == iface->broadcast) {
        errorf("only supports unicast, src=%s, dst=%s",
               ip_addr_ntop(src_addr, addr1, sizeof(addr1)), ip_addr_ntop(dst_addr, addr2, sizeof(addr2)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src_addr, addr1, sizeof(addr1)), ntoh16(hdr->src_addr),
           ip_addr_ntop(dst_addr, addr2, sizeof(addr2)), ntoh16(hdr->dst_addr),
           len, len - sizeof(*hdr));
    tcp_dump(data, len);
}

int
tcp_init(void)
{
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}