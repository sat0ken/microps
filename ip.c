#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform/linux/platform.h"
#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"

static struct ip_iface *interfaces;
static struct ip_protocol *ip_protocols;

const ip_addr_t IP_ADDR_ANY       = 0x00000000;
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff;

// IPアドレスを文字列からバイナリ値へ変換
int
ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

// IPアドレスをバイナリ値から文字列に変換
char *
ip_addr_ntop(const ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl &0xf0) >> 4;
    hl = hdr->vhl &0x0f;
    hlen = hl << 2;
    fprintf(stderr, " vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, " tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, " total: %u (payload:%u)\n", total, total - hlen);
    fprintf(stderr, " id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, " offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, " ttl: %u\n", hdr->ttl);
    fprintf(stderr, " protocol: %u\n", hdr->protocol);
    fprintf(stderr, " sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, " src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, " dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v, hl;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    struct ip_protocol *entry;
    // 入力データがIPヘッダの最小サイズ以下はエラー
    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    // パケットデータを構造体のポインタへキャスト
    hdr = (struct ip_hdr *)data;
    // IPv4バージョンと一致しない場合はエラー
    v = (hdr->vhl &0xf0) >>4;
    if (v != IP_VERSION_IPV4) {
        errorf("not much IP_VERSION_IPV4");
        return;
    }
    // 入力データの長さがヘッダ長より小さい場合はエラー
    hl = hdr->vhl &0x0f;
    hlen = hl << 2;
    if (len < hlen) {
        errorf("header length err");
        return;
    }
    // 入力データの長さがトータル長より小さい場合はエラー
    total = ntoh16(hdr->total);
    if (len < total) {
        errorf("total length err");
        return;
    }
    // チェックサムの検証に失敗したらエラー
    if (cksum16((uint16_t *)hdr, hlen, 0 ) != 0) {
        errorf("checksum err");
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset &0x1fff) {
        errorf("fragments does not support");
        return;
    }
    // デバイスに紐づくIPインタフェースを取得
    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface == NULL) {
        errorf("iface is NULL");
        return;
    }
    // 宛先IPアドレスの検証
    if (hdr->dst != iface->unicast) {
        if (hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST){
            errorf("dst addr is error");
            return;
        }
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, len);

    // 上位プロトコルを検索して登録されたハンドラを呼ぶ
    for (entry = ip_protocols; entry; entry = ip_protocols->next) {
        if (hdr->protocol == entry->type) {
            entry->handler((uint8_t *)hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
}

int
ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}

struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*interfaces));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;
    infof("set family is %d", NET_IFACE(iface)->family);
    // IPインターフェイスにアドレス情報を設定
    // IPアドレスを変換してセット
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", unicast);
        memory_free(iface);
        return NULL;
    }
    // サブネットマスクを変換してセット
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", netmask);
        memory_free(iface);
        return NULL;
    }
    // ブロードキャストアドレスを算出してセット
    iface->broadcast = (iface->unicast & iface->netmask) | ~iface->netmask;
    return iface;
}

int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    // IPインターフェイスの登録
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    // IPインターフェイスのリストの先頭にifaceを挿入する
    iface->next = interfaces;
    interfaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

    return 0;
}

struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    struct ip_iface *entry;
    // インターフェイスリストを巡回して引数のIPアドレスと一致するインターフェイスを返す
    for (entry = interfaces; entry; entry = interfaces->next) {
        if (entry->unicast == addr) {
            break;
        }
    }
    return entry;
}

static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;

    // ARPで宛先IPアドレスのMACアドレスを取得
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
            if (ret != ARP_RESOLVE_FOUND) {
                return ret;
            }
        }
    }
    // デバイスから送信
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;
    hlen = sizeof(*hdr);
    // IPヘッダの生成
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    total = hlen + len;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff;
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    // IPヘッダの後ろにデータをコピー
    memcpy(hdr+1, data, len);
    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
           NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, dst);
}

static uint16_t
ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

// IPの出力関数
ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY) {
        errorf("ip routing does not implement");
        return -1;
    } else {
        // ソースのIPアドレスを持つインターフェイスを検索
        iface = ip_iface_select(src);
        if (!iface) {
            errorf("src ip interface not found");
            return -1;
        }
        // 宛先IPアドレスが到達可能かチェック
        if (dst != IP_ADDR_BROADCAST && ((iface->unicast & iface->netmask) != (dst & iface->netmask))) {
            ip_addr_ntop(dst, addr, sizeof(addr));
            errorf("can't reach to dst: %s", addr);
            return -1;
        }
    }

    // フラグメンテーションをサポートしていないのでMTUを超えるパケットはエラー
    debugf("ip_iface_select() is success");
    debugf("iface unicast=%s", ip_addr_ntop(iface->unicast, addr, sizeof(addr)));
    debugf("dev.name is %d", NET_IFACE(iface)->dev->mtu);
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("packet is too long, dev=%s, mtu=%u < %zu",
               NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    debugf("ip_iface_select() is success");
    // IPデータグラムのIDを採番
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
}

int
ip_protocol_register(uint8_t type, void(*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    struct ip_protocol *entry;
    // 重複登録の確認
    for (entry = ip_protocols; entry; entry = ip_protocols->next) {
        if (type == entry->type) {
            errorf("already registered type=%u", type);
            return -1;
        }
    }
    // プロトコルの登録
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        memory_free(entry);
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    entry->next = ip_protocols;
    ip_protocols = entry;
    infof("registered type=%u", entry->type);
    return 0;
}