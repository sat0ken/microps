#ifndef ETHER_TAP_H
#define ETHER_TAP_H

#include <stdio.h>

#include "../net.h"
#include "../platform/linux/intr.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE+2)

extern struct net_device *
ether_tap_init(const char *name, const char *addr);

//extern int
//ether_tap_addr(struct net_device *dev);
//
//extern int
//ether_tap_open(struct net_device *dev);
//
//extern int
//ether_tap_close(struct net_device *dev);
//
//extern ssize_t
//ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen);
//
//extern int
//ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst);
//
//extern ssize_t
//ether_tap_read(struct net_device *dev, uint8_t *buf, size_t len);
//
//extern int
//ether_tap_isr(unsigned int irq, void *id);

#endif