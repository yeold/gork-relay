/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * serial.h -- gork over a serial line, for machines with no network.
 *
 * The line carries frames, both ways, in SLIP's framing:
 *
 *     END  TYPE ID DATA SUM(2)  END
 *
 * where an END (0xC0) or ESC (0xDB) byte inside is sent as ESC 0xDC or
 * ESC 0xDD.  TYPE is 'O' (open), 'D' (data) or 'C' (close); ID is the
 * request's number; DATA is at most SERIAL_FRAME_MAX bytes; SUM is a
 * Fletcher-16 of TYPE to the end of DATA, big-endian.  gork sends an 'O'
 * and its request in 'D's; the reply goes back in 'D's of the same ID and
 * a 'C' ends it.  One request at a time: a new 'O' drops the one before.
 * A 'C' from gork abandons its request.  A damaged frame drops the
 * request in progress; nothing is sent again.  Damage ends at the next
 * END, so the line is back in step at the next frame.
 */
#ifndef SERIAL_H
#define SERIAL_H

#include "sys.h"

#define SERIAL_FRAME_MAX 1024

struct frame {
    int           esc, bad;
    size_t        n, len;               /* bytes so far; DATA of a whole one */
    unsigned char b[SERIAL_FRAME_MAX + 4];      /* type, id, data, sum */
};

struct serial {
    int           fd;                   /* the line */
    const char   *dev;
    int           pump;                 /* the request's, or -1 */
    unsigned char id;
    int           verbose;
    struct frame  rx;
    unsigned char out[2 * (SERIAL_FRAME_MAX + 4) + 2];
    size_t        out_len, out_off;     /* a frame on its way out */
    int           want_close;           /* a 'C' to send after it */
    unsigned      gen, polled_gen;      /* which pump poll() looked at */
    /* A new request: return a descriptor to copy its bytes to and from
       (the far end of a pump), or -1. */
    int         (*accept)(const char *from);
};

/* Open "DEVICE[:BAUD[:rtscts]]" (9600 unless given), raw, 8N1.  0, or -1
   with a message. */
int  serial_open(struct serial *s, const char *spec);
/* Its descriptors, for poll(): up to 2.  Returns how many. */
int  serial_pollfds(struct serial *s, struct pollfd *p);
/* After poll(); `p` is what serial_pollfds filled. */
void serial_service(struct serial *s, struct pollfd *p, int n);

#endif
