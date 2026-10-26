/* SPDX-License-Identifier: GPL-3.0-or-later */
/* link.c -- see link.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sys.h"
#ifndef WINSOCK
#include <sys/ioctl.h>
#include <net/if.h>
#endif
#ifdef USE_PCAP
#include <pcap.h>
#elif defined(__linux__)
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#endif
#include "link.h"

enum { KIND_ETH, KIND_UDP };

static int open_udp(struct link *l, const char *spec) {
    struct sockaddr_in a;
    const char        *colon = strrchr(spec, ':');
    char               host[64] = "0.0.0.0";

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    if (colon != NULL) {
        if ((size_t) (colon - spec) >= sizeof host)
            return -1;
        memcpy(host, spec, colon - spec);
        host[colon - spec] = '\0';
        spec = colon + 1;
    }
    a.sin_port = htons((unsigned short) atoi(spec));
    if (a.sin_port == 0 || inet_pton(AF_INET, host, &a.sin_addr) != 1) {
        say("bad udp link, want udp:[ADDR:]PORT\n");
        return -1;
    }
    l->fd = (int) socket(AF_INET, SOCK_DGRAM, 0);
    if (l->fd < 0 || bind(l->fd, (struct sockaddr *) &a, sizeof a) != 0) {
        say("udp link: %s\n",
                sock_strerror(sock_errno));
        return -1;
    }
    set_nonblock(l->fd);
    return 0;
}

#ifdef USE_PCAP
static int open_eth(struct link *l, const char *dev) {
    char    err[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_live(dev, 65535, 1, 10, err);

    if (p == NULL) {
        say("%s: %s\n", dev, err);
        return -1;
    }
    if (pcap_datalink(p) == DLT_IEEE802) {
        l->medium = MEDIUM_TOKENRING;
    } else if (pcap_datalink(p) != DLT_EN10MB) {
        say("%s is neither Ethernet nor token "
                        "ring\n", dev);
        return -1;
    }
    if (pcap_setnonblock(p, 1, err) != 0)
        say("%s: %s\n", dev, err);
    l->pcap = p;
#ifdef SIOCGIFHWADDR
    if (!l->have_mac) {         /* elsewhere it must be given with -m */
        struct ifreq ifr;
        int          s = socket(AF_INET, SOCK_DGRAM, 0);

        memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, dev, sizeof ifr.ifr_name - 1);
        if (s >= 0 && ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(l->mac, ifr.ifr_hwaddr.sa_data, 6);
            l->have_mac = 1;
        }
        if (s >= 0)
            close(s);
    }
#endif
#if defined(__CYGWIN__) || defined(WINSOCK)
    l->fd = -1;                 /* Npcap has nothing poll() can wait on */
#else
    l->fd = pcap_get_selectable_fd(p);
#endif
    return 0;
}
#elif defined(__linux__)
static int open_eth(struct link *l, const char *dev) {
    struct sockaddr_ll sll;
    struct ifreq       ifr;

    l->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (l->fd < 0) {
        say("packet socket (needs root or CAP_NET_RAW): %s\n", strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, dev, sizeof ifr.ifr_name - 1);
    if (ioctl(l->fd, SIOCGIFHWADDR, &ifr) != 0) {
        say("%s: %s\n", dev, strerror(errno));
        return -1;
    }
    /* 800 is ARPHRD_IEEE802_TR; kernels since 3.5 have no token ring, and
       their headers no longer name it */
    if (ifr.ifr_hwaddr.sa_family == 800) {
        l->medium = MEDIUM_TOKENRING;
    } else if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        say("%s is neither Ethernet nor token "
                        "ring\n", dev);
        return -1;
    }
    if (!l->have_mac)
        memcpy(l->mac, ifr.ifr_hwaddr.sa_data, 6);
    l->have_mac = 1;
    if (ioctl(l->fd, SIOCGIFINDEX, &ifr) != 0) {
        say("%s: %s\n", dev, strerror(errno));
        return -1;
    }
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(l->fd, (struct sockaddr *) &sll, sizeof sll) != 0) {
        say("%s: %s\n", dev, strerror(errno));
        return -1;
    }
    set_nonblock(l->fd);
    return 0;
}
#else
static int open_eth(struct link *l, const char *dev) {
    (void) l;
    say("no eth link for %s in this build: it needs "
                    "Linux, or PCAP=1 with libpcap or Npcap\n", dev);
    return -1;
}
#endif

int link_open(struct link *l, const char *spec) {
    l->fd = -1;
    l->medium = MEDIUM_ETHERNET;
    if (strncmp(spec, "eth:", 4) == 0) {
        l->kind = KIND_ETH;
        if (open_eth(l, spec + 4) != 0)
            return -1;
    } else if (strncmp(spec, "udp:", 4) == 0 ||
               strncmp(spec, "udp+tr:", 7) == 0) {
        l->kind = KIND_UDP;
        if (spec[3] == '+')
            l->medium = MEDIUM_TOKENRING;
        if (open_udp(l, strchr(spec, ':') + 1) != 0)
            return -1;
    } else {
        say("bad link '%s', want eth:IFACE or "
                        "udp:[ADDR:]PORT\n", spec);
        return -1;
    }
    if (!l->have_mac) {
        if (l->kind == KIND_ETH) {
            say("this build cannot ask the interface "
                            "for its address; give it with -m\n");
            return -1;
        }
        memcpy(l->mac, "\x02gork\x01", 6);      /* locally administered */
        l->have_mac = 1;
    }
    return 0;
}

int link_recv(struct link *l, unsigned char *buf, size_t cap,
              struct lladdr *from) {
    int n;

    memset(from, 0, sizeof *from);
    if (l->kind == KIND_UDP) {
        socklen_t len = sizeof from->udp;

        n = (int) recvfrom(l->fd, (char *) buf, (int) cap, 0,
                           (struct sockaddr *) &from->udp, &len);
    } else {
#ifdef USE_PCAP
        struct pcap_pkthdr  *h;
        const unsigned char *data;
        int                  r = pcap_next_ex(l->pcap, &h, &data);

        if (r < 0)
            return -1;
        if (r == 0 || h->caplen > cap)
            return 0;
        memcpy(buf, data, h->caplen);
        return (int) h->caplen;
#elif defined(__linux__)
        struct sockaddr_ll sll;
        socklen_t          len = sizeof sll;

        n = (int) recvfrom(l->fd, buf, cap, 0, (struct sockaddr *) &sll, &len);
        if (n > 0 && sll.sll_pkttype == PACKET_OUTGOING)
            return 0;                   /* our own frame, shown to us */
#else
        return -1;
#endif
    }
    if (n < 0)
        return sock_errno == SOCK_EAGAIN || sock_errno == SOCK_EINTR ? 0 : -1;
    return n;
}

int link_send(struct link *l, const struct lladdr *to,
              const unsigned char *frame, size_t n) {
    if (l->kind == KIND_UDP)
        return sendto(l->fd, (const char *) frame, (int) n, 0,
                      (const struct sockaddr *) &to->udp,
                      sizeof to->udp) < 0 ? -1 : 0;
#ifdef USE_PCAP
    return pcap_sendpacket(l->pcap, frame, (int) n) != 0 ? -1 : 0;
#elif defined(__linux__)
    return write(l->fd, frame, n) < 0 ? -1 : 0;
#else
    return -1;
#endif
}
