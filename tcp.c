#include <stdio.h>
#include <string.h>

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

static mutex_t mutex = MUTEX_INITIALIZER;

#define TCP_PCB_SIZE 16
static struct tcp_pcb tcp_pcb_list[TCP_PCB_SIZE];

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
    fprintf(stderr, " src: %u\n", ntoh16(hdr->src_port));
    fprintf(stderr, " dst: %u\n", ntoh16(hdr->dst_port));
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

static struct tcp_pcb *
tcp_pcb_alloc(void)
{
    struct tcp_pcb *pcb;

    for (pcb = tcp_pcb_list; pcb < tailof(tcp_pcb_list); pcb++) {
        if (pcb->state == TCP_STATE_FREE) {
            pcb->state = TCP_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
    debugf("released, local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb));
}

static struct tcp_pcb *
tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *listen_pcb = NULL;
//    char ep1[IP_ENDPOINT_STR_LEN];
//    char ep2[IP_ENDPOINT_STR_LEN];

    for (pcb = tcp_pcb_list; pcb < tailof(tcp_pcb_list); pcb++) {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port) {
            if (!foreign) {
//                debugf("return local pcb");
//                debugf("%s => %s",
//                       ip_endpoint_ntop(local, ep1, sizeof(ep1)),
//                       ip_endpoint_ntop(foreign, ep2, sizeof(ep2)));
                return pcb;
            }
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
                debugf("return foreign pcb");
                return pcb;
            }
            if (pcb->state == TCP_STATE_LISTEN) {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
                    debugf("return listen_pcb");
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

static struct tcp_pcb *
tcp_pcb_get(int id)
{
    struct tcp_pcb *pcb;

    if (id < 0 || id >= (int) countof(tcp_pcb_list)) {
        return NULL;
    }
    pcb = &tcp_pcb_list[id];
    if (pcb->state == TCP_STATE_FREE) {
        return NULL;
    }
    return pcb;
}

static int
tcp_pcb_id(struct tcp_pcb *pcb)
{
    return indexof(tcp_pcb_list, pcb);
}

static ssize_t
tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct tcp_pseudo_hdr pseudo;
    uint16_t  psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;
    // TCPヘッダの生成
    hdr->src_port = local->port;
    hdr->dst_port = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) <<4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    // ペイロードをヘッダの後ろにセット
    memcpy(hdr+1, data, len);
    // TCPダミーヘッダの生成
    pseudo.src_addr = local->addr;
    pseudo.dst_addr = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);
    // チェックサムを計算
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    // IPから送信
    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
           total, len);
    tcp_dump((uint8_t *)hdr, len);
    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1) {
        errorf("ip_output() failure");
        return -1;
    }
    return len;
}

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;
    seq = pcb->snd.nxt;
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) {
        seq = pcb->iss;
    }
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        // Todo: add retransmission queue
    }
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;
    pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        // 使用していないポートにパケットが飛んできたらRSTを返す
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        } else{
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
    }
    debugf("pcb state is %d", pcb->state);
    switch (pcb->state) {
        case TCP_STATE_LISTEN:
            // 1st check for RST
            if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
                return;
            }
            // 2nd check for ACK
            if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            // 3rd check for SYN
            if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
                pcb->local = *local;
                pcb->foreign = *foreign;
                pcb->rcv.wnd = sizeof(pcb->buf);
                pcb->rcv.nxt = seg->seq + 1;
                pcb->irs = seg->seq;
                pcb->iss = random();
                // SYNACKを送信
                debugf("send synack !!!!!!!!!");
                tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                pcb->snd.nxt = pcb->iss + 1;
                pcb->snd.una = pcb->iss;
                pcb->state = TCP_STATE_SYN_RECEIVED;
                return;
            }
            // 4th is other text or control
            return;
        case TCP_STATE_SYN_SENT:
            // 1st check ACK bit
            // 2nd check RST bit
            // 3rd check security and precedure
            // 4th check SYN bit
            // 5th if neither of the SYN or RST bits is set then drop the segment and return
            // drop segment
            return;
    }
    // Otherwise
    // 1st check sequence number
    // 2nd check RST bit
    // 3rd check security and precedure
    // 4th check SYN bit
    // 5th check ACK field
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
        return;
    }
    switch (pcb->state) {
        case TCP_STATE_SYN_RECEIVED:
            if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) {
                pcb->state = TCP_STATE_ESTABLISHED;
                sched_wakeup(&pcb->ctx);
            } else {
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            }
            break;
    }
    // 6th check URG bit
    // 7th process the segment text
    // 8th check FIN bit
    return;
}


static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src_addr, ip_addr_t dst_addr, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct tcp_pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;

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
           ip_addr_ntop(src_addr, addr1, sizeof(addr1)), ntoh16(hdr->src_port),
           ip_addr_ntop(dst_addr, addr2, sizeof(addr2)), ntoh16(hdr->dst_port),
           len, len - sizeof(*hdr));
    tcp_dump(data, len);

    local.addr = dst_addr;
    local.port = hdr->dst_port;
    foreign.addr = src_addr;
    foreign.port = hdr->src_port;
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        // SYNパケットだったらSequenceを1増やす
        seg.len++;
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        // FINパケットだったらSequenceを1増やす
        seg.len++;
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);
    return;
}

static void
event_handler(void *arg)
{
    struct tcp_pcb *pcb;
    mutex_lock(&mutex);
    for (pcb = tcp_pcb_list; pcb < tailof(tcp_pcb_list); pcb++) {
        if (pcb->state != TCP_STATE_FREE) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int
tcp_init(void)
{
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    net_event_subscribe(event_handler, NULL);
    return 0;
}

int
tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
    struct tcp_pcb *pcb;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb) {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    if (active) {
        errorf("active open does not implement");
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    } else {
        debugf("passive open: local=%s, waiting connection...", ip_endpoint_ntop(local, addr1, sizeof(addr1)));
        pcb->local = *local;
        if (foreign) {
            pcb->foreign = *foreign;
        } else {
            debugf("local listen...");
        }
        pcb->state = TCP_STATE_LISTEN;
    }
AGAIN:
    state = pcb->state;
    while (pcb->state == state) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            pcb->state == TCP_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    if (pcb->state != TCP_STATE_ESTABLISHED) {
        if (pcb->state == TCP_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, addr1, sizeof(addr1)),
           ip_endpoint_ntop(&pcb->foreign, addr2, sizeof(addr2)));
    mutex_unlock(&mutex);
    return id;
}

int
tcp_close(int id)
{
    struct tcp_pcb *pcb;
    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    tcp_output(pcb, TCP_FLG_RST, NULL, 0);
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}