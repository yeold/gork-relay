/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * frame.h -- IPX packets in and out of link-layer frames.
 *
 * Ethernet carries IPX four ways (Ethernet II, 802.2, "raw" 802.3, SNAP)
 * and token ring two (802.2, SNAP).  A reply goes out the way the request
 * came in, so the peer's encapsulation is remembered with its address.
 */
#ifndef FRAME_H
#define FRAME_H

#include <stddef.h>
#include "sys.h"

enum { MEDIUM_ETHERNET, MEDIUM_TOKENRING };
enum { FT_ETH2, FT_8022, FT_RAW, FT_SNAP };

#define FRAME_MAX 4600          /* a 4 Mbit/s token ring frame fits */
#define RIF_MAX   18

/* Where a packet came from at the link layer, and so where to answer. */
struct lladdr {
    unsigned char      mac[6];
    unsigned char      frame;           /* FT_* */
    unsigned char      riflen;          /* token ring source route */
    unsigned char      rif[RIF_MAX];
    struct sockaddr_in udp;             /* the udp link: the sender */
};

/* The IPX packet inside frame f[0..n), or NULL if there is none.  Fills
   *len with its length (from the IPX header), `peer` with the sender and
   `dst` with the destination MAC. */
const unsigned char *frame_decap(int medium, const unsigned char *f, size_t n,
                                 size_t *len, struct lladdr *peer,
                                 unsigned char dst[6]);

/* Build a frame from `src` to `peer` around an IPX packet.  Returns its
   length, or 0 if it does not fit in out[0..cap). */
size_t frame_encap(int medium, const unsigned char src[6],
                   const struct lladdr *peer, const unsigned char *ipx,
                   size_t len, unsigned char *out, size_t cap);

#endif
