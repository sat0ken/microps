#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "../util.h"
#include "../net.h"
#include "../ip.h"

#include "../driver/loopback.h"
#include "test.h"

static volatile __sig_atomic_t terminate;

static void
os_signal(int s)
{
    (void)s;
    terminate = 1;
}

int main(int argc, char *argv[])
{
    struct net_device *dev;
    struct ip_iface *iface;
    // Ctrl+cで止まるようにシグナルハンドラを設定
    signal(SIGINT, os_signal);
    // プロトコルスタックの初期化
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    // Loopbackの初期化
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    // プロトコルスタックの起動
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    // 1秒おきにダミーデバイスにテストデータを書き込む
    while (!terminate) {
        if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1) {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }
    // プロトコルスタックの停止
    net_shutdown();
    return 0;
}