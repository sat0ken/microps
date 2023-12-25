#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct icmp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    // 入力データの長さ確認
    if (len < sizeof(*hdr)) {
        errorf("icmp message length is too short");
        return;
    }
    hdr = (struct icmp_hdr *)data;
    // チェックサムの検証
    if (cksum16((uint16_t *)data, len, 0) != 0) {
        errorf("checksum err, sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)data, len, -hdr->sum)));
        return;
    }

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    debugdump(data, len);
    icmp_dump(data, len);

    switch (hdr->type) {
        case ICMP_TYPE_ECHO:
            // ECHO Replyを返す
            icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values, (uint8_t *)(hdr + 1), len - sizeof(*hdr), dst, src);
            break;
        default:
            break;
    }
}

int
icmp_init(void)
{
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}

static char *
icmp_type_ntoa(uint8_t type)
{
    switch (type) {
        case ICMP_TYPE_ECHOREPLY:
            return "EchoReply";
        case ICMP_TYPE_DEST_UNREACH:
            return "DestinationUnreachable";
        case ICMP_TYPE_SOURCE_QUENCH:
            return "SourceQuench";
        case ICMP_TYPE_REDIRECT:
            return "Redirct";
        case ICMP_TYPE_ECHO:
            return "Echo";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "TimeExceeded";
        case ICMP_TYPE_PARAM_PROBLEM:
            return "ParamProblem";
        case ICMP_TYPE_TIMESTAMP:
            return "Timestamp";
        case ICMP_TYPE_TIMESTAMPREPLY:
            return "TimestampReply";
        case ICMP_TYPE_INFO_REQUEST:
            return "InformationRequest";
        case ICMP_TYPE_INFO_REPLY:
            return "InformationReply";
    }
    return "Unknown";
}

static void
icmp_dump(const uint8_t *data, size_t len)
{
    struct icmp_hdr *hdr;
    struct icmp_echo *echo;

    flockfile(stderr);
    hdr = (struct icmp_hdr *)data;

    fprintf(stderr, " type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, " code: %u\n", hdr->code);
    fprintf(stderr, " sum: 0x%04x\n", ntoh16(hdr->sum));

    switch (hdr->type) {
        case ICMP_TYPE_ECHOREPLY:
        case ICMP_TYPE_ECHO:
            echo = (struct icmp_echo *)hdr;
            fprintf(stderr, " id: %u\n", ntoh16(echo->id));
            fprintf(stderr, "seq: %u\n", ntoh16(echo->seq));
            break;
        default:
            fprintf(stderr, "values: 0x%08x\n", ntoh32(hdr->values));
    }
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

int
icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    uint8_t buf[ICMP_BUFSIZE];
    struct icmp_hdr *hdr;
    size_t msg_len;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    // ICMPヘッダに値を設定
    hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->sum  = 0;
    hdr->values = values;
    // ヘッダの直後にデータをコピー
    memcpy(hdr + 1, data, len);
    // ICMPメッセージ全体の長さを計算
    msg_len = sizeof(*hdr) + len;
    // チェックサムを計算
    hdr->sum = cksum16((uint16_t *)data, msg_len, 0);

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(src, addr2, sizeof(addr2)), msg_len);
    icmp_dump((uint8_t *)hdr, msg_len);

    // IPから出力
    return ip_output(IP_PROTOCOL_ICMP, (uint8_t *)hdr, msg_len, src, dst);
}
