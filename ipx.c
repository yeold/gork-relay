/* SPDX-License-Identifier: GPL-3.0-or-later */
/* ipx.c -- see ipx.h. */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "ipx.h"

/* IPX header offsets */
enum { I_SUM = 0, I_LEN = 2, I_TC = 4, I_TYPE = 5, I_DNET = 6, I_DNODE = 10,
       I_DSOCK = 16, I_SNET = 18, I_SNODE = 22, I_SSOCK = 28 };
/* SPX header offsets, after the IPX header */
enum { S_CTL = 30, S_DST = 31, S_SRCID = 32, S_DSTID = 34, S_SEQ = 36,
       S_ACK = 38, S_ALLOC = 40 };

#define CTL_SYS 0x80            /* no data, takes no sequence number */
#define CTL_ACK 0x40            /* the sender wants an acknowledgement */
#define CTL_EOM 0x10
#define DST_END     0xfe        /* end of connection */
#define DST_END_ACK 0xff

#define SOCK_RIP 0x453
#define TYPE_SPX 5

#define WINDOW      8           /* packets we take, and keep unacknowledged */
#define RETRY_MS    700
#define RETRIES     12
#define IDLE_MS     (15 * 60 * 1000L)
#define LINGER_MS   3000        /* after our end-of-connection */

static unsigned get16(const unsigned char *p) { return p[0] << 8 | p[1]; }
static void put16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char) (v >> 8);
    p[1] = (unsigned char) v;
}

static long now_ms(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (long) (tv.tv_sec % 1000000) * 1000 + tv.tv_usec / 1000;
}

struct packet {                 /* sent, not yet acknowledged */
    unsigned      seq;
    unsigned char dst;          /* datastream type */
    size_t        len;
    unsigned char data[SPX_DATA];
};

struct conn {
    int           used;
    int           fd;           /* the pump; -1 once it has ended */
    unsigned      id, peer_id;
    unsigned char peer[12];     /* net, node, socket */
    unsigned char local_net[4]; /* the network the peer called us on */
    struct lladdr ll;
    unsigned      snd_seq;      /* next sequence number to use */
    unsigned      peer_alloc;   /* highest the peer will take */
    unsigned      rcv_seq;      /* next expected */
    struct packet q[WINDOW];
    int           qn;
    int           tries;
    long          sent_at, heard_at;
    int           ending;       /* our end-of-connection is in q, or sent */
};

static struct conn conns[SPX_CONNS];
static unsigned    next_id = 0x4a00;

static void ipx_send(struct ipx *x, const struct lladdr *ll,
                     unsigned char *pkt, size_t len) {
    unsigned char frame[FRAME_MAX];
    size_t        n;

    put16(pkt + I_SUM, 0xffff);
    put16(pkt + I_LEN, (unsigned) len);
    pkt[I_TC] = 0;
    n = frame_encap(x->link.medium, x->link.mac, ll, pkt, len, frame,
                    sizeof frame);
    if (n == 0 || link_send(&x->link, ll, frame, n) != 0)
        say("cannot send a frame\n");
}

/* An SPX packet on connection c. */
static void spx_send(struct ipx *x, struct conn *c, unsigned ctl, unsigned dst,
                     unsigned seq, const unsigned char *data, size_t len) {
    unsigned char pkt[IPX_HDR + SPX_HDR + SPX_DATA];

    pkt[I_TYPE] = TYPE_SPX;
    memcpy(pkt + I_DNET, c->peer, 12);
    memcpy(pkt + I_SNET, c->local_net, 4);
    memcpy(pkt + I_SNODE, x->link.mac, 6);
    put16(pkt + I_SSOCK, x->socket);
    pkt[S_CTL] = (unsigned char) ctl;
    pkt[S_DST] = (unsigned char) dst;
    put16(pkt + S_SRCID, c->id);
    put16(pkt + S_DSTID, c->peer_id);
    put16(pkt + S_SEQ, seq);
    put16(pkt + S_ACK, c->rcv_seq);
    put16(pkt + S_ALLOC, c->rcv_seq + WINDOW - 1);
    if (len)
        memcpy(pkt + IPX_HDR + SPX_HDR, data, len);
    ipx_send(x, &c->ll, pkt, IPX_HDR + SPX_HDR + len);
}

static void send_ack(struct ipx *x, struct conn *c) {
    spx_send(x, c, CTL_SYS, 0, c->snd_seq, NULL, 0);
}

static void send_queued(struct ipx *x, struct conn *c, struct packet *p) {
    spx_send(x, c, CTL_ACK | CTL_EOM, p->dst, p->seq, p->data, p->len);
    c->sent_at = now_ms();
}

static void conn_free(struct ipx *x, struct conn *c, const char *why) {
    if (x->verbose)
        say("spx %04x closed: %s\n", c->id, why);
    if (c->fd >= 0)
        closesocket(c->fd);
    c->used = 0;
}

/* Sequence numbers wrap at 16 bits: is a before b? */
static int seq_lt(unsigned a, unsigned b) {
    return ((a - b) & 0xffff) > 0x8000;
}

static void rip_input(struct ipx *x, const unsigned char *p, size_t len,
                      const struct lladdr *ll) {
    static const unsigned char zero[4], any[4] = {0xff, 0xff, 0xff, 0xff};
    unsigned char r[IPX_HDR + 10];

    /* a request for every network or for ours; we have a number to tell */
    if (len < IPX_HDR + 10 || get16(p + IPX_HDR) != 1 ||
        memcmp(x->net, zero, 4) == 0 ||
        (memcmp(p + IPX_HDR + 2, any, 4) != 0 &&
         memcmp(p + IPX_HDR + 2, x->net, 4) != 0))
        return;
    r[I_TYPE] = 1;
    memcpy(r + I_DNET, x->net, 4);
    memcpy(r + I_DNODE, p + I_SNODE, 8);
    memcpy(r + I_SNET, x->net, 4);
    memcpy(r + I_SNODE, x->link.mac, 6);
    put16(r + I_SSOCK, SOCK_RIP);
    put16(r + IPX_HDR, 2);                      /* response */
    memcpy(r + IPX_HDR + 2, x->net, 4);
    put16(r + IPX_HDR + 6, 1);                  /* hops */
    put16(r + IPX_HDR + 8, 2);                  /* ticks */
    ipx_send(x, ll, r, sizeof r);
}

static struct conn *conn_new(struct ipx *x, const unsigned char *p,
                             const struct lladdr *ll) {
    struct conn *c;
    int          i;

    /* the request again, because our answer was lost? */
    for (i = 0; i < SPX_CONNS; i++) {
        c = &conns[i];
        if (c->used && memcmp(c->peer, p + I_SNET, 12) == 0 &&
            c->peer_id == get16(p + S_SRCID))
            return c;
    }
    for (i = 0; i < SPX_CONNS && conns[i].used; i++)
        ;
    if (i == SPX_CONNS) {
        say("too many SPX connections\n");
        return NULL;
    }
    c = &conns[i];
    memset(c, 0, sizeof *c);
    c->fd = x->accept();
    if (c->fd < 0)
        return NULL;
    c->used = 1;
    c->id = next_id++;
    if (next_id >= 0xfff0)
        next_id = 0x100;
    c->peer_id = get16(p + S_SRCID);
    memcpy(c->peer, p + I_SNET, 12);
    memcpy(c->local_net, p + I_DNET, 4);
    c->ll = *ll;
    c->heard_at = now_ms();
    if (x->verbose)
        say("spx %04x opened from "
                "%02x%02x%02x%02x.%02x%02x%02x%02x%02x%02x\n", c->id,
                p[18], p[19], p[20], p[21], p[22], p[23], p[24], p[25],
                p[26], p[27]);
    return c;
}

static void spx_input(struct ipx *x, const unsigned char *p, size_t len,
                      const struct lladdr *ll) {
    struct conn *c = NULL;
    unsigned     ctl, dst, seq, ack;
    size_t       dlen;
    int          i;

    if (len < IPX_HDR + SPX_HDR)
        return;
    ctl = p[S_CTL];
    dst = p[S_DST];
    seq = get16(p + S_SEQ);
    ack = get16(p + S_ACK);
    dlen = len - IPX_HDR - SPX_HDR;

    if (get16(p + S_DSTID) == 0xffff) {         /* a connection request */
        if (!(ctl & CTL_SYS))
            return;
        c = conn_new(x, p, ll);
        if (c == NULL)
            return;
        c->peer_alloc = get16(p + S_ALLOC);
        send_ack(x, c);
        return;
    }
    for (i = 0; i < SPX_CONNS; i++)
        if (conns[i].used && conns[i].id == get16(p + S_DSTID) &&
            conns[i].peer_id == get16(p + S_SRCID) &&
            memcmp(conns[i].peer, p + I_SNET, 12) == 0)
            c = &conns[i];
    if (c == NULL)
        return;
    c->heard_at = now_ms();
    c->ll = *ll;

    /* what it acknowledges leaves the queue */
    while (c->qn > 0 && seq_lt(c->q[0].seq, ack)) {
        memmove(c->q, c->q + 1, (size_t) --c->qn * sizeof c->q[0]);
        c->tries = 0;
        if (c->qn > 0)
            c->sent_at = now_ms();
    }
    if (!seq_lt(get16(p + S_ALLOC), c->peer_alloc) ||
        seq_lt(c->peer_alloc, ack))
        c->peer_alloc = get16(p + S_ALLOC);

    if (ctl & CTL_SYS) {
        if (ctl & CTL_ACK)                      /* a watchdog, or a probe */
            send_ack(x, c);
        return;
    }
    if (dst == DST_END_ACK) {
        conn_free(x, c, "ended");
        return;
    }
    if (seq != c->rcv_seq) {                    /* a repeat, or a gap */
        send_ack(x, c);
        return;
    }
    c->rcv_seq = (c->rcv_seq + 1) & 0xffff;
    if (dst == DST_END) {
        spx_send(x, c, 0, DST_END_ACK, c->snd_seq, NULL, 0);
        conn_free(x, c, "ended by the client");
        return;
    }
    if (dlen > 0 && c->fd >= 0) {
        /* the pump always reads, so this does not wait for long */
        size_t off = 0;

        while (off < dlen) {
            int w = (int) send(c->fd,
                               (const char *) p + IPX_HDR + SPX_HDR + off,
                               (int) (dlen - off), 0);

            if (w < 0 && sock_errno == SOCK_EINTR)
                continue;
            if (w <= 0)
                break;
            off += (size_t) w;
        }
    }
    send_ack(x, c);
}

void ipx_input(struct ipx *x) {
    static const unsigned char bcast[6] = {255, 255, 255, 255, 255, 255};
    unsigned char        buf[FRAME_MAX];
    struct lladdr        ll, from;
    unsigned char        dmac[6];
    const unsigned char *p;
    size_t               len;
    int                  n, burst;

    for (burst = 0; burst < 64; burst++) {
        n = link_recv(&x->link, buf, sizeof buf, &from);
        if (n <= 0)
            return;
        p = frame_decap(x->link.medium, buf, (size_t) n, &len, &ll, dmac);
        if (p == NULL)
            continue;
        ll.udp = from.udp;
        if (memcmp(p + I_DNODE, x->link.mac, 6) != 0 &&
            memcmp(p + I_DNODE, bcast, 6) != 0)
            continue;
        if (memcmp(p + I_SNODE, x->link.mac, 6) == 0)
            continue;                           /* our own, echoed */
        if (get16(p + I_DSOCK) == SOCK_RIP)
            rip_input(x, p, len, &ll);
        else if (get16(p + I_DSOCK) == x->socket && p[I_TYPE] == TYPE_SPX)
            spx_input(x, p, len, &ll);
    }
}

int spx_pollfds(struct pollfd *p, int max) {
    int i, n = 0;

    for (i = 0; i < SPX_CONNS && n < max; i++) {
        struct conn *c = &conns[i];

        /* read from the pump only while the peer has room */
        if (c->used && c->fd >= 0 && c->qn < WINDOW &&
            !seq_lt(c->peer_alloc, c->snd_seq)) {
            p[n].fd = c->fd;
            p[n].events = POLLIN;
            p[n].revents = 0;
            n++;
        }
    }
    return n;
}

static void queue(struct ipx *x, struct conn *c, unsigned dst,
                  const unsigned char *data, size_t len) {
    struct packet *q = &c->q[c->qn++];

    q->seq = c->snd_seq;
    q->dst = (unsigned char) dst;
    q->len = len;
    if (len)
        memcpy(q->data, data, len);
    c->snd_seq = (c->snd_seq + 1) & 0xffff;
    if (c->qn == 1)
        c->tries = 0;
    send_queued(x, c, q);
}

void spx_service(struct ipx *x, struct pollfd *p, int n) {
    long t = now_ms();
    int  i, k;

    for (i = 0; i < SPX_CONNS; i++) {
        struct conn *c = &conns[i];

        if (!c->used)
            continue;
        for (k = 0; k < n; k++) {
            unsigned char data[SPX_DATA];
            int           r;

            if ((int) p[k].fd != c->fd || !(p[k].revents & (POLLIN | POLLHUP)) ||
                c->qn >= WINDOW)
                continue;
            r = (int) recv(c->fd, (char *) data, sizeof data, 0);
            if (r > 0) {
                queue(x, c, 0, data, (size_t) r);
            } else if (r == 0 || sock_errno != SOCK_EINTR) {
                closesocket(c->fd);             /* the reply is complete */
                c->fd = -1;
            }
            break;
        }
        if (c->fd < 0 && !c->ending && c->qn < WINDOW &&
            !seq_lt(c->peer_alloc, c->snd_seq)) {
            c->ending = 1;
            queue(x, c, DST_END, NULL, 0);
        }
        if (c->qn > 0 && t - c->sent_at > RETRY_MS) {
            if (++c->tries > RETRIES) {
                conn_free(x, c, c->ending ? "ended, unanswered"
                                          : "the client stopped answering");
                continue;
            }
            for (k = 0; k < c->qn; k++)
                send_queued(x, c, &c->q[k]);
        }
        if (c->ending && c->qn == 0)
            conn_free(x, c, "ended");
        else if (t - c->heard_at > (c->ending ? LINGER_MS + RETRY_MS * RETRIES
                                              : IDLE_MS))
            conn_free(x, c, "idle");
    }
}
