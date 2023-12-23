#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "platform.h"
#include "intr.h"
#include "../../util.h"
#include "../../net.h"

struct irq_query {
    struct irq_query *next;
    unsigned int irq;
    int (*handler)(unsigned int irq, void *dev);
    int flags;
    char name[16];
    void *dev;
};

static struct irq_query *irqs;

static sigset_t sigmask;
static pthread_t tid;
static pthread_barrier_t barrier;

// 割り込みの登録処理
int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *id), int flags, const char *name, void *dev)
{
    struct irq_query *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    // IRQ番号が既に登録されている場合は、IRQ番号の共有が許可されているかを確認し、どちらが共有を許可していない場合はエラーを返す
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf("conflicts with already registerd IRQs");
                return -1;
            }
        }
    }
    // メモリを確保
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    // IRQ構造体に値をセット
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name)-1);
    entry->dev = dev;
    // IRQリストの先頭へ挿入
    entry->next = irqs;
    irqs = entry;
    // シグナル集合へ新しいシグナルを追加
    sigaddset(&sigmask, irq);
    debugf("registerd: irq=%u, name=%s", irq, name);

    return 0;
}

int
int_raise_irq(unsigned int irq)
{
    return pthread_kill(tid, (int)irq);
}

static void *
intr_thread(void *arg)
{
    int terminate =0, sig, err;
    struct irq_query *entry;

    debugf("start...");
    pthread_barrier_wait(&barrier);
    while (!terminate) {
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig) {
            case SIGHUP:
                terminate = 1;
                break;
            case SIGUSR1:
                // ソフトウェア割り込み用のシグナルを補足したら割り込み関数を呼ぶ
                net_softirq_handler();
                break;
            default:
                for (entry = irqs; entry; entry =  entry->next) {
                    if (entry->irq == (unsigned int)sig) {
                        debugf("irq=%d, name=%s", entry->irq, entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

int
intr_run(void)
{
    int err;
    // シグナルマスクの設定
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    // 割り込み処理スレッドの起動
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    // スレッドの起動を待つ
    pthread_barrier_wait(&barrier);
    return 0;
}

void
intr_shutdown(void)
{
    // 割り込み処理スレッドが起動済みかどうか確認
    if (pthread_equal(tid, pthread_self()) != 0) {
        return;
    }
    // 割り込み処理スレッドにシグナルを送信
    pthread_kill(tid, SIGHUP);
    // 割り込み処理スレッドが終了するのを待つ
    pthread_join(tid, NULL);
}

int
intr_init(void)
{
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGUSR1);
    return 0;
}
