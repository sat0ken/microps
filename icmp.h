#ifndef ICMP_H
#define ICMP_H

#define ICMP_HDR_SIZE 8

#define ICMP_BUFSIZE IP_PAYLOAD_SIZE_MAX

#define ICMP_TYPE_ECHOREPLY         0
#define ICMP_TYPE_DEST_UNREACH      3
#define ICMP_TYPE_SOURCE_QUENCH     4
#define ICMP_TYPE_REDIRECT          5
#define ICMP_TYPE_ECHO              8
#define ICMP_TYPE_TIME_EXCEEDED     11
#define ICMP_TYPE_PARAM_PROBLEM     12
#define ICMP_TYPE_TIMESTAMP         13
#define ICMP_TYPE_TIMESTAMPREPLY    14
#define ICMP_TYPE_INFO_REQUEST      15
#define ICMP_TYPE_INFO_REPLY        16

// ICMPヘッダ構造体
struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint8_t  sum;
    uint32_t values;
};

// Echo/EchoReplyメッセージ用構造体
struct icmp_echo {
    uint8_t  type;
    uint8_t  code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

extern int
icmp_init(void);

extern void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);

extern char *
icmp_type_ntoa(uint8_t);

extern void
icmp_dump(const uint8_t *data, size_t len);

extern int
icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst);

#endif