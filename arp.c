#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "platform.h"

static mutex_t mutex = MUTEX_INITIALIZER;
// ARPキャッシュの配列
static struct arp_cache arp_cache_list[ARP_CACHE_SIZE];

static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, " hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, " pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, " hln: %u\n", message->hdr.hln);
    fprintf(stderr, " pln: %u\n", message->hdr.pln);
    fprintf(stderr, " op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, " sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, " spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, " tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, " tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif

    funlockfile(stderr);
}

static void
arp_cache_delete(struct arp_cache *cache)
{
    char ip[IP_ADDR_STR_LEN];
    char mac[ETHER_ADDR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, ip, sizeof(ip)), ether_addr_ntop(cache->ha, mac, sizeof(mac)));
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

static struct arp_cache *
arp_cache_alloc(void)
{
    struct arp_cache *entry, *oldest = NULL;
    // ARPキャッシュのリストを巡回
    for (entry = arp_cache_list; entry< tailof(arp_cache_list); entry++) {
        // 使用されていないエントリを返す
        if (entry->state == ARP_CACHE_STATE_FREE) {
            return entry;
        }
        // 空きがなかったときのために一番古いエントリを探す
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = entry;
        }
    }
    // 空きがなかったら一番古いエントリを削除して返す
    arp_cache_delete(oldest);
    return oldest;
}

static struct arp_cache *
arp_cache_select(ip_addr_t pa)
{
    struct arp_cache *entry;
    // ARPキャッシュのリストを巡回
    for (entry = arp_cache_list; entry< tailof(arp_cache_list); entry++) {
        if (entry->pa == pa && entry->state != ARP_CACHE_STATE_FREE) {
            return entry;
        }
    }
    return NULL;
}

static struct arp_cache *
arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char ip[IP_ADDR_STR_LEN];
    char mac[ETHER_ADDR_LEN];
    // エントリを検索
    cache = arp_cache_select(pa);
    if (!cache) {
        return NULL;
    }
    // エントリ情報を更新
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, ip, sizeof(ip)), ether_addr_ntop(cache->ha, mac, sizeof(mac)));
    return cache;
}

static struct arp_cache *
arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char ip[IP_ADDR_STR_LEN];
    char mac[ETHER_ADDR_LEN];

    cache = arp_cache_alloc();
    if (!cache) {
        return NULL;
    }
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(cache->pa, ip, sizeof(ip)), ether_addr_ntop(cache->ha, mac, sizeof(mac)));
    return cache;
}

static int
arp_request(struct net_iface *iface, ip_addr_t tpa)
{
    struct arp_ether_ip request;
    // ARPリクエストの生成
    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(request.tha, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
    memcpy(request.tpa, &tpa, IP_ADDR_LEN);
    debugf("dev=%s, opcode=%s(0x%04x), len=%zu", iface->dev->name, arp_opcode_ntoa(request.hdr.op), ntoh16(request.hdr.op), sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));

    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;

    // ARPヘッダ領域の設定
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    // 可変領域の設定
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, opcode=%s(0x%04x), len=%zu", iface->dev->name, arp_opcode_ntoa(reply.hdr.op), ntoh16(reply.hdr.op), sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));

    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;
    int is_update;

    // 期待するARPメッセージのサイズより小さかったらエラーを返す
    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }

    msg = (struct arp_ether_ip *)data;

    // ハードウェアアドレスのチェック
    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("does not match hardware address: 0x%04x or hardware length: %u", ntoh16(msg->hdr.hrd), msg->hdr.hln);
        return;
    }

    // プロトコルアドレスのチェック
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("does not match protocol: 0x%04x or address length: %u", ntoh16(msg->hdr.pro), msg->hdr.pln);
        return;
    }
    debugf("dev=%s, opcode=%s(0x%04x), len=%zu", dev->name, arp_opcode_ntoa(msg->hdr.op), ntoh16(msg->hdr.op), len);
    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);

    // spa/tpaをmemcpy()でip_addr_tの変数へ取り出す
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    // キャッシュへのアクセスをmutexで排他制御
    mutex_lock(&mutex);
    if (arp_cache_update(spa, msg->sha)) {
        is_update = 1;
    } else {
        is_update = 0;
    }
    mutex_unlock(&mutex);

    debugf("ARPキャッシュ is_update = %d", is_update);

    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);

    // ARP要求のターゲットプロトコルアドレスと一致するか確認
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        if (!is_update) {
            mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
    struct arp_cache *cache;
    char ip[IP_ADDR_STR_LEN];
    char mac[ETHER_ADDR_STR_LEN];

    // インターフェイスがEthernetであることを確認
    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        errorf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    // インターフェイスがIPであることを確認
    if (iface->family != NET_IFACE_FAMILY_IP) {
        errorf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }
    mutex_lock(&mutex);
    cache = arp_cache_select(pa);
    if (!cache) {
        // 新しいエントリのメモリを確保
        cache = arp_cache_alloc();
        if (!cache) {
            return ARP_RESOLVE_ERROR;
        }
        cache->state = ARP_CACHE_STATE_INCOMPLETE;
        cache->pa = pa;
        gettimeofday(&cache->timestamp, NULL);
        errorf("cache not found, pa=%s", ip_addr_ntop(pa, ip, sizeof(ip)));
        mutex_unlock(&mutex);
        arp_request(iface, pa);
        return ARP_CACHE_STATE_INCOMPLETE;
    }
    // INCOMPELETEのままなら念のため再送
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
        mutex_unlock(&mutex);
        arp_request(iface, pa);
        return ARP_CACHE_STATE_INCOMPLETE;
    }
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("cache hit pa=%s, ha=%s", ip_addr_ntop(pa, ip, sizeof(ip)), ether_addr_ntop(ha, mac, sizeof(mac)));

    return ARP_RESOLVE_FOUND;
}

static void
arp_timmer_handler(void)
{
    struct arp_cache *entry;
    struct timeval now, diff;
    mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    for (entry = arp_cache_list; entry < tailof(arp_cache_list); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->state != ARP_CACHE_STATE_STATIC) {
            timersub(&now, &entry->timestamp, &diff);
            if (diff.tv_sec > ARP_CACHE_TIMEOUT) {
                arp_cache_delete(entry);
            }
        }
    }
    mutex_unlock(&mutex);
}

int
arp_init(void)
{
    struct timeval interval = {1, 0};
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1){
        errorf("net_protocol_register() failure");
        return -1;
    }
    // タイマーを登録
    if (net_timer_register(interval, arp_timmer_handler) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }

    return 0;
}
