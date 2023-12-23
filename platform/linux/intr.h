#include <signal.h>

#define INTR_IRQ_BASE (SIGRTMIN+1)
#define INTR_IRQ_SHARED 0x0001
#define INTR_IRQ_SOFTIRQ SIGUSR1

extern int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *id), int flags, const char *name, void *dev);

extern int
int_raise_irq(unsigned int irq);

extern int
intr_run(void);

extern void
intr_shutdown(void);

extern int
intr_init(void);