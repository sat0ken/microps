#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../platform/linux/platform.h"
#include "../platform/linux/intr.h"
#include "../util.h"
#include "../net.h"

#define LOOPBACK_MTU UINT16_MAX
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE+1)

#define PRIV(x) ((struct  loopback *)x->priv)

struct loopback {
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

// キューのエントリの構造体
struct loopback_queue_entry {
    uint16_t type;
    size_t len;
    uint8_t data[];
};

static int
loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    struct loopback_queue_entry *entry;
    unsigned int num;

    // キューへのアクセスをmutexで保護する
    mutex_lock(&PRIV(dev)->mutex);
    if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT) {
        // キューの上限を超えていたらエラーを返す
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("qeueu is full");
        return -1;
    }
    // キューに格納するエントリのメモリを確保
    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry) {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("memory_alloc() failure");
        return -1;
    }
    // メタデータの設定
    entry->type = type;
    entry->len = len;
    // データ本体のコピー
    memcpy(entry->data, data, len);
    // エントリをキューへ格納
    queue_push(&PRIV(dev)->queue, entry);
    num = PRIV(dev)->queue.num;
    mutex_unlock(&PRIV(dev)->mutex);
    debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num, dev->name, type, len);
    debugdump(data, len);
    // 割り込みを発生
    int_raise_irq(PRIV(dev)->irq);
    return 0;
}

static int
loopback_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    struct loopback_queue_entry *entry;

    dev = (struct net_device *)id;
    // キューへのアクセスをmutexで保護
    mutex_lock(&PRIV(dev)->mutex);
    while (1) {
        // キューからエントリを取り出す
        entry = queue_pop(&PRIV(dev)->queue);
        if (!entry) {
            // 取り出すエントリがなくなったらキューを抜ける
            break;
        }
        debugf("queue poped (num:%u), dev=%s, type=0x%04x, len=%zd", PRIV(dev)->queue.num, dev->name, entry->type, entry->len);
        debugdump(entry->data, entry->len);
        // 受信データ本体と付随情報を渡す
        net_input_handler(entry->type, entry->data, entry->len, dev);
        // エントリのメモリを解放する
        memory_free(entry);
    }
    mutex_unlock(&PRIV(dev)->mutex);
    return 0;
}

static struct net_device_ops loopback_ops = {
        .transmit = loopback_transmit,
};

struct net_device *
loopback_init(void)
{
    struct net_device *dev;
    struct loopback *lo;

    // デバイスの生成とパラメータの設定
    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops  = &loopback_ops;
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }

    lo = memory_alloc(sizeof(*lo));
    if (!lo) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    lo->irq = LOOPBACK_IRQ;
    mutex_init(&lo->mutex);
    queue_init(&lo->queue);
    dev->priv = lo;

    // デバイスと登録と割り込みハンドラの設定
    intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized, dev=%s", dev->name);
    return dev;
};