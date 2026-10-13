/* SPDX-License-Identifier: GPL-3.0-or-later */
/* frame.c -- see frame.h. */
#include <string.h>
#include "frame.h"

#define IPX_HDR 30

static const unsigned char snap_ipx[8] = {0xaa, 0xaa, 3, 0, 0, 0, 0x81, 0x37};

/* After the MAC header: which encapsulation, and where IPX starts. */
static const unsigned char *llc_decap(const unsigned char *p, size_t n,
                                      struct lladdr *peer, size_t *left) {
    if (n >= 8 && memcmp(p, snap_ipx, 8) == 0) {
        peer->frame = FT_SNAP;
        *left = n - 8;
        return p + 8;
    }
    if (n >= 3 && p[0] == 0xe0 && p[1] == 0xe0 && p[2] == 3) {
        peer->frame = FT_8022;
        *left = n - 3;
        return p + 3;
    }
    return NULL;
}

const unsigned char *frame_decap(int medium, const unsigned char *f, size_t n,
                                 size_t *len, struct lladdr *peer,
                                 unsigned char dst[6]) {
    const unsigned char *p;
    size_t               left, want;

    memset(peer, 0, sizeof *peer);
    if (medium == MEDIUM_TOKENRING) {
        /* AC FC dst[6] src[6] [route] LLC.  The top bit of the source
           says a route follows; its first byte holds its length. */
        size_t rif = 0;

        if (n < 14 || (f[1] & 0xc0) != 0x40)    /* an LLC frame, not MAC */
            return NULL;
        memcpy(dst, f + 2, 6);
        memcpy(peer->mac, f + 8, 6);
        if (f[8] & 0x80) {
            if (n < 16)
                return NULL;
            rif = f[14] & 0x1f;
            if (rif < 2 || rif > RIF_MAX || (rif & 1) || 14 + rif > n)
                return NULL;
            peer->mac[0] &= 0x7f;
            peer->riflen = (unsigned char) rif;
            memcpy(peer->rif, f + 14, rif);
        }
        p = llc_decap(f + 14 + rif, n - 14 - rif, peer, &left);
        if (p == NULL)
            return NULL;
    } else {
        unsigned type;

        if (n < 14)
            return NULL;
        memcpy(dst, f, 6);
        memcpy(peer->mac, f + 6, 6);
        type = f[12] << 8 | f[13];
        p = f + 14;
        left = n - 14;
        if (type == 0x8137) {
            peer->frame = FT_ETH2;
        } else if (type > 1500) {
            return NULL;                        /* some other protocol */
        } else {
            if (type < left)
                left = type;                    /* drop the padding */
            if (left >= 2 && p[0] == 0xff && p[1] == 0xff) {
                peer->frame = FT_RAW;           /* the IPX checksum field */
            } else {
                p = llc_decap(p, left, peer, &left);
                if (p == NULL)
                    return NULL;
            }
        }
    }
    if (left < IPX_HDR)
        return NULL;
    want = (size_t) p[2] << 8 | p[3];
    if (want < IPX_HDR || want > left)
        return NULL;
    *len = want;
    return p;
}

size_t frame_encap(int medium, const unsigned char src[6],
                   const struct lladdr *peer, const unsigned char *ipx,
                   size_t len, unsigned char *out, size_t cap) {
    size_t n, llc = 0;
    int    frame = peer->frame;

    if (medium == MEDIUM_TOKENRING) {
        size_t rif = peer->riflen <= RIF_MAX ? peer->riflen : 0;

        if (frame != FT_SNAP)
            frame = FT_8022;
        llc = frame == FT_SNAP ? 8 : 3;
        n = 14 + rif + llc + len;
        if (n > cap)
            return 0;
        out[0] = 0x10;                          /* access control */
        out[1] = 0x40;                          /* frame control: LLC */
        memcpy(out + 2, peer->mac, 6);
        memcpy(out + 8, src, 6);
        if (rif) {
            /* the route back: same bridges, other direction, and no
               longer a broadcast */
            out[8] |= 0x80;
            memcpy(out + 14, peer->rif, rif);
            out[14] &= 0x1f;
            out[15] ^= 0x80;
        }
        out += 14 + rif;
    } else {
        size_t body;

        if (frame == FT_8022)
            llc = 3;
        else if (frame == FT_SNAP)
            llc = 8;
        body = llc + len;
        /* Novell's raw 802.3 drivers send an even number of bytes */
        if (frame == FT_RAW && (body & 1))
            body++;
        n = 14 + body;
        if (n < 60)
            n = 60;                             /* the Ethernet minimum */
        if (n > cap || body > 1500)
            return 0;
        memset(out, 0, n);
        memcpy(out, peer->mac, 6);
        memcpy(out + 6, src, 6);
        if (frame == FT_ETH2) {
            out[12] = 0x81;
            out[13] = 0x37;
        } else {
            out[12] = (unsigned char) (body >> 8);
            out[13] = (unsigned char) body;
        }
        out += 14;
    }
    if (llc == 8) {
        memcpy(out, snap_ipx, 8);
    } else if (llc == 3) {
        out[0] = out[1] = 0xe0;
        out[2] = 3;
    }
    memcpy(out + llc, ipx, len);
    return n;
}
