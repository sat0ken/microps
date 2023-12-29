#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform/linux/platform.h"
#include "platform/linux/intr.h"
#include "util.h"
//#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"

static struct net_device *devices;
static struct net_protocol *protocols;

struct net_device *
net_device_alloc(void)
{
    struct net_device *dev;
    dev = memory_alloc(sizeof(*dev));
    if (!dev) {
        errorf("memoay_alloc() failure");
        return NULL;
    }
    return dev;
}

int
net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;
    devices = dev;
    infof("registerd, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

int
net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    struct net_iface *entry;

    // 重複登録のチェック
    for(entry = dev->ifaces; entry; entry = entry->next) {
        if (iface->family == entry->family) {
            errorf("already exist, dev=%s, family=%d", dev->name, entry->family);
            return -1;
        }
    }
    // デバイスのインターフェイスリストの先頭にifaceを挿入
    iface->next = dev->ifaces;
    iface->dev = dev;
    dev->ifaces = iface;
    return 0;
}

struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{
    // デバイスのインターフェイスリストを検索しfamilyが一致するインターフェイスを返す
    struct net_iface *entry;
    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == family) {
            break;
        }
    }
    return  entry;
}

static int
net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;
    // 重複登録の確認
    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }
    // 構造体のメモリ確保
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }
    // プロトコルタイプと入力関数を設定
    proto->type = type;
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registered, type =0x%04x", type);
    return 0;
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            // キューに格納するエントリのメモリを確保
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry) {
                errorf("memory_alloc() failure");
                return -1;
            }
            // メタデータの設定
            entry->dev = dev;
            entry->len = len;
            // データをコピー
            memcpy(entry+1, data, len);
            // キューに新しいエントリを挿入
            if (!queue_push(&proto->queue, entry)) {
                errorf("queue_push() failure");
                memory_free(entry);
                return -1;
            }

            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
                   proto->queue.num, dev->name, type, len);
            debugdump(data, len);
            // ソフトウェア割り込みを発生させる
            int_raise_irq(INTR_IRQ_SOFTIRQ);
        }
    }
    //infof("unsupported protocol type=0x%04x", type);
    return 0;
}

// ソフトウェア割り込み時に呼ばれる関数
int
net_softirq_handler(void)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    // プロトコルリストを巡回
    for (proto = protocols; proto; proto = proto->next) {
        while (1) {
            // 受信キューからエントリを取り出す
            entry = queue_pop(&proto->queue);
            if (!entry) {
                // エントリがなければ抜ける
                break;
            }
            debugf("queue poped (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            // プロトコルの入力関数を呼び出す
            proto->handler(entry->data, entry->len, entry->dev);
            // memoryを解放
            memory_free(entry);
        }
    }
    return 0;
}

int
net_run(void)
{
    struct net_device *dev;
    // 割り込み機構の起動
    if (intr_run() == -1) {
        errorf("intr_run() failure");
        return -1;
    }
    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("running...");
    return 0;
}

void
net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    // 割り込み機構の終了
    intr_shutdown();
    debugf("shutting down");
}

int
net_init(void)
{
    // 割り込み機能の初期化
    if (intr_init() == -1) {
        errorf("intr_init() failure");
        return -1;
    }
    // ARPを登録
    if (arp_init() == -1) {
        errorf("arp_init() failure");
        return -1;
    }
    // IPを初期化
    if (ip_init() == -1) {
        errorf("ip_init() failure");
        return -1;
    }
    // ICMPを登録
    if (icmp_init() == -1) {
        errorf("icmp_init() failure");
        return -1;
    }
    infof("initialized");
    return 0;
}