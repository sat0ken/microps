#ifndef SCHED_H
#define SCHED_H

#include <signal.h>
#include <stddef.h>
#include <sched.h>
#include <pthread.h>
#include <signal.h>

#include "platform.h"

#define SCHED_CTX_INITIALIZER {PTHREAD_COND_INITIALIZER, 0, 0}

struct sched_ctx {
    pthread_cond_t cond;
    int interrupted;
    int wc;
};

extern int
sched_ctx_init(struct sched_ctx *ctx);

extern int
sched_ctx_destroy(struct sched_ctx *ctx);

extern int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime);

extern int
sched_wakeup(struct sched_ctx *ctx);

extern int
sched_interrupt(struct sched_ctx *ctx);

#endif
