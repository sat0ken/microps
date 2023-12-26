#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "../platform.h"

#include "../../../util.h"
#include "../../../net.h"
#include "../../../ether.h"

#include "../../../driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE+2)

#define PRIV(x) ((struct ether_tap *)x->priv)

struct ether_tap {
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

static int
ether_tap_addr(struct net_device *dev)
{
    int soc;
    // ioctlで使うリクエスト・レスポンス兼用の構造体
    struct ifreq ifr = {};
    // socketをopenする
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket :%s, dev=%s", strerror(errno), dev->name);
        return -1;
    }
    // MACアドレスを取得したいデバイスの名前を設定
    strncpy(ifr.ifr_name,PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    // MACアドレスの取得を要求
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    // 取得したアドレスを構造体にコピー
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int
ether_tap_open(struct net_device *dev)
{
    struct ether_tap *tap;
    // ioctlで使うリクエスト・レスポンス兼用の構造体
    struct ifreq ifr = {};

    tap = PRIV(dev);
    // TUN/TAPデバイスをopen
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1) {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }
    // TAPデバイスの名前を設定
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name)-1);
    // フラグの設定
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    // TAPデバイスの登録を要求
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }
    // IOの設定
    // シグナルの配送先を設定
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // シグナル駆動IOを有効にする
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // 送信するシグナルを指定
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        if (ether_tap_addr(dev) == -1) {
            errorf("ether_tap_addr() failure, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }
    return 0;
}

static int
ether_tap_close(struct net_device *dev)
{
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t
ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

int
ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

static ssize_t
ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;
    len = read(PRIV(dev)->fd, buf, size);
    if (len < 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

static int
ether_tap_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    struct pollfd pfd;
    int ret;

    dev = (struct net_device *)id;
    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;

    while (1) {
        // timeoutの時間を0にセットしたpoll()で読み込み可能なデータの存在を確認
        ret = poll(&pfd, 1, 0);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        }
        if (ret == 0) {
            // 戻り値が0だったらtimeout(読み込み可能なデータがない)
            break;
        }
        // 読み込み可能なデータがあったら入力のヘルパー関数を渡す、引数にreadの関数アドレスを渡す
        ether_input_helper(dev, ether_tap_read);
    }
    return 0;
}

struct net_device_ops ether_tap_ops = {
        .open = ether_tap_open,
        .close = ether_tap_close,
        .transmit = ether_tap_transmit,
};

struct net_device *
ether_tap_init(const char *name, const char *addr)
{
    struct net_device *dev;
    struct ether_tap *tap;

    // デバイスを生成
    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    ether_setup_helper(dev);
    if (addr) {
        if (ether_addr_pton(addr, dev->addr) == -1) {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    // ドライバに関数群を設定
    dev->ops = &ether_tap_ops;
    // ドライバ内部で使用するデータを生成してセット
    tap = memory_alloc(sizeof(*tap));
    if (!tap) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name)-1);
    tap->fd = -1;
    tap->irq = ETHER_TAP_IRQ;
    dev->priv = tap;
    // デバイスを登録
    if (net_device_register(dev) == 1) {
        errorf("net_device_register() failure");
        memory_free(tap);
        return NULL;
    }
    // 割り込みハンドラの登録
    intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}