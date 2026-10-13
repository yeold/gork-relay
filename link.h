/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * link.h -- where frames come from and go to.
 *
 *   eth:IFACE        a network interface, Ethernet or token ring
 *                    (Linux packet socket; libpcap or Npcap with USE_PCAP)
 *   udp:[ADDR:]PORT  one frame per UDP datagram: QEMU's
 *                    -netdev socket,udp=HOST:PORT,localaddr=... / -netdev dgram
 *                    udp+tr: the same carrying token ring frames (tests)
 */
#ifndef LINK_H
#define LINK_H

#include "frame.h"

struct link {
    int           fd;           /* to poll; -1: call link_recv on a timer */
    int           medium;       /* MEDIUM_* */
    int           kind;
    unsigned char mac[6];       /* ours */
    int           have_mac;
    void         *pcap;
};

/* 0, or -1 with a message on stderr. */
int link_open(struct link *l, const char *spec);
/* One frame into buf; 0 if there is none now, -1 on error.  `from` gets
   what only the link knows about the sender (the udp link's address). */
int link_recv(struct link *l, unsigned char *buf, size_t cap,
              struct lladdr *from);
int link_send(struct link *l, const struct lladdr *to,
              const unsigned char *frame, size_t n);

#endif
