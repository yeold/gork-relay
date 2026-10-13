/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * ipx.h -- a small IPX node with an SPX listener, in user space.
 *
 * Current Linux has no IPX (it left the kernel in 4.18) and Windows none
 * since Vista, so the relay speaks it itself, on raw frames.  It is one
 * node with one SPX socket.  It answers RIP requests for its network
 * number, so that clients on the segment learn the number and the frame
 * type.  It routes nothing.
 */
#ifndef IPX_H
#define IPX_H

#include <poll.h>
#include "link.h"

#define IPX_HDR     30
#define SPX_HDR     12
#define SPX_DATA    534         /* 576, the size every IPX path carries */
#define SPX_CONNS   64

struct ipx {
    struct link   link;
    unsigned char net[4];
    unsigned      socket;       /* the SPX socket we listen on */
    int           verbose;
    /* A new connection: return a descriptor to copy its bytes to and from
       (the far end of a pump), or -1. */
    int         (*accept)(void);
};

/* Read the frames that are waiting and act on them. */
void ipx_input(struct ipx *x);
/* The connections' descriptors, for poll(); returns how many. */
int  spx_pollfds(struct pollfd *p, int max);
/* After poll(): bytes from the pumps, retransmissions, timeouts.  `p` is
   what spx_pollfds filled. */
void spx_service(struct ipx *x, struct pollfd *p, int n);

#endif
