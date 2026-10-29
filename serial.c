/* SPDX-License-Identifier: GPL-3.0-or-later */
/* serial.c -- see serial.h.  POSIX terminals only: not in the Windows
   build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "serial.h"

#ifdef WINSOCK

int serial_open(struct serial *s, const char *spec) {
    (void) s;
    (void) spec;
    say("-S: no serial lines in the Windows build; use Cygwin's\n");
    return -1;
}
int serial_pollfds(struct serial *s, struct pollfd *p) {
    (void) s;
    (void) p;
    return 0;
}
void serial_service(struct serial *s, struct pollfd *p, int n) {
    (void) s;
    (void) p;
    (void) n;
}

#else

#include <fcntl.h>
#include <termios.h>

#define F_END     0xc0
#define F_ESC     0xdb
#define F_ESC_END 0xdc
#define F_ESC_ESC 0xdd

static unsigned fletcher(const unsigned char *p, size_t n) {
    unsigned a = 0, b = 0;

    while (n-- > 0) {
        a = (a + *p++) % 255;
        b = (b + a) % 255;
    }
    return b << 8 | a;
}

/* One byte from the line.  1: a whole frame is in f; 0: not yet; -1: a
   damaged frame. */
static int frame_byte(struct frame *f, int c) {
    size_t n = f->n;
    int    bad = f->bad;

    if (c == F_END) {
        f->n = 0;
        f->esc = f->bad = 0;
        if (n == 0 && !bad)
            return 0;                   /* between frames */
        if (bad || n < 4 ||
            fletcher(f->b, n - 2) != ((unsigned) f->b[n - 2] << 8 | f->b[n - 1]))
            return -1;
        f->len = n - 4;
        return 1;
    }
    if (bad)
        return 0;
    if (f->esc) {
        f->esc = 0;
        if (c == F_ESC_END)
            c = F_END;
        else if (c == F_ESC_ESC)
            c = F_ESC;
        else
            f->bad = 1;
    } else if (c == F_ESC) {
        f->esc = 1;
        return 0;
    }
    if (n == sizeof f->b)
        f->bad = 1;
    if (!f->bad)
        f->b[f->n++] = (unsigned char) c;
    return 0;
}

/* Put a frame in the outgoing buffer, which must be empty. */
static void queue(struct serial *s, int type, const unsigned char *p,
                  size_t n) {
    unsigned char raw[SERIAL_FRAME_MAX + 4], *o = s->out;
    unsigned      sum;
    size_t        i;

    raw[0] = (unsigned char) type;
    raw[1] = s->id;
    memcpy(raw + 2, p, n);
    sum = fletcher(raw, n + 2);
    raw[n + 2] = (unsigned char) (sum >> 8);
    raw[n + 3] = (unsigned char) sum;
    *o++ = F_END;
    for (i = 0; i < n + 4; i++) {
        if (raw[i] == F_END || raw[i] == F_ESC) {
            *o++ = F_ESC;
            *o++ = raw[i] == F_END ? F_ESC_END : F_ESC_ESC;
        } else {
            *o++ = raw[i];
        }
    }
    *o++ = F_END;
    s->out_len = (size_t) (o - s->out);
    s->out_off = 0;
}

static void drop_pump(struct serial *s) {
    if (s->pump >= 0)
        close(s->pump);
    s->pump = -1;
}

static const struct {
    long    baud;
    speed_t code;
} speeds[] = {
    { 1200, B1200 }, { 2400, B2400 }, { 4800, B4800 }, { 9600, B9600 },
    { 19200, B19200 }, { 38400, B38400 },
#ifdef B57600
    { 57600, B57600 },
#endif
#ifdef B115200
    { 115200, B115200 },
#endif
#ifdef B230400
    { 230400, B230400 },
#endif
    { 0, B0 }
};

int serial_open(struct serial *s, const char *spec) {
    static char    dev[256];
    char          *p, *q = NULL;
    long           baud = 9600;
    int            i, rtscts = 0;
    struct termios t;

    snprintf(dev, sizeof dev, "%s", spec);
    if ((p = strchr(dev, ':')) != NULL) {
        *p++ = '\0';
        if ((q = strchr(p, ':')) != NULL) {
            *q++ = '\0';
            if (strcmp(q, "rtscts") != 0) {
                say("-S %s: want rtscts after the speed\n", spec);
                return -1;
            }
            rtscts = 1;
        }
        baud = strtol(p, &q, 10);
        if (*q != '\0')
            baud = -1;
    }
    for (i = 0; speeds[i].baud != 0 && speeds[i].baud != baud; i++)
        ;
    if (speeds[i].baud == 0) {
        say("-S %s: not a speed this system has\n", spec);
        return -1;
    }
#ifndef CRTSCTS
    if (rtscts) {
        say("-S %s: no RTS/CTS flow control here\n", spec);
        return -1;
    }
#endif
    s->fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (s->fd < 0) {
        say("%s: %s\n", dev, strerror(errno));
        return -1;
    }
    if (tcgetattr(s->fd, &t) != 0) {
        say("%s: not a serial line: %s\n", dev, strerror(errno));
        return -1;
    }
    t.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR |
                   ICRNL | IXON | IXOFF);
    t.c_iflag |= IGNPAR;
    t.c_oflag &= ~OPOST;
    t.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.c_cflag &= ~(CSIZE | PARENB | CSTOPB | HUPCL);
    t.c_cflag |= CS8 | CREAD | CLOCAL;
#ifdef CRTSCTS
    if (rtscts)
        t.c_cflag |= CRTSCTS;
    else
        t.c_cflag &= ~CRTSCTS;
#endif
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    cfsetispeed(&t, speeds[i].code);
    cfsetospeed(&t, speeds[i].code);
    if (tcsetattr(s->fd, TCSANOW, &t) != 0) {
        say("%s: %s\n", dev, strerror(errno));
        return -1;
    }
    tcflush(s->fd, TCIOFLUSH);
    s->dev = dev;
    s->pump = -1;
    say("serial on %s at %ld baud%s\n", dev, baud,
        rtscts ? ", RTS/CTS" : "");
    return 0;
}

int serial_pollfds(struct serial *s, struct pollfd *p) {
    int n = 0;

    p[n].fd = s->fd;
    p[n++].events = (short) (POLLIN | (s->out_len > 0 ? POLLOUT : 0));
    /* the reply, a frame at a time, as fast as the line takes it */
    if (s->pump >= 0 && s->out_len == 0 && !s->want_close) {
        p[n].fd = s->pump;
        p[n++].events = POLLIN;
        s->polled_gen = s->gen;
    }
    return n;
}

static void take(struct serial *s, int rc) {
    struct frame *f = &s->rx;

    if (rc < 0) {
        if (s->pump >= 0) {
            say("serial: a damaged frame; the request is dropped\n");
            drop_pump(s);
            s->want_close = 1;
        }
        return;
    }
    switch (f->b[0]) {
    case 'O':
        /* whatever was going on is over: gork has given up on it.  A
           frame half sent is finished, so that the line stays in step. */
        drop_pump(s);
        if (s->out_off == 0)
            s->out_len = 0;
        s->id = f->b[1];
        s->gen++;
        s->pump = s->accept(s->dev);
        s->want_close = s->pump < 0;
        break;
    case 'D':
        if (f->b[1] == s->id && s->pump >= 0) {
            const unsigned char *p = f->b + 2;
            size_t               left = f->len;

            while (left > 0) {          /* the pump reads all the time */
                ssize_t w = write(s->pump, p, left);

                if (w < 0 && errno == EINTR)
                    continue;
                if (w <= 0) {
                    drop_pump(s);
                    break;
                }
                p += w;
                left -= (size_t) w;
            }
        }
        break;
    case 'C':
        if (f->b[1] == s->id)
            drop_pump(s);
        break;
    }
}

void serial_service(struct serial *s, struct pollfd *p, int n) {
    unsigned char buf[4096];
    ssize_t       r;
    int           i;

    if (n < 1)
        return;
    if (p[0].revents & POLLOUT) {
        r = write(s->fd, s->out + s->out_off, s->out_len - s->out_off);
        if (r > 0 && (s->out_off += (size_t) r) == s->out_len)
            s->out_len = 0;
    }
    if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
        r = read(s->fd, buf, sizeof buf);
        if (r < 0 && errno != EAGAIN && errno != EINTR) {
            say("%s: %s\n", s->dev, strerror(errno));
            exit(1);
        }
        for (i = 0; i < r; i++) {
            int rc = frame_byte(&s->rx, buf[i]);

            if (rc != 0)
                take(s, rc);
        }
    }
    if (n > 1 && s->pump >= 0 && s->polled_gen == s->gen &&
        s->out_len == 0 && !s->want_close &&
        (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
        r = read(s->pump, buf, SERIAL_FRAME_MAX);
        if (r > 0) {
            queue(s, 'D', buf, (size_t) r);
        } else if (r == 0 || errno != EINTR) {
            drop_pump(s);                /* the reply is complete */
            s->want_close = 1;
        }
    }
    if (s->out_len == 0 && s->want_close) {
        queue(s, 'C', NULL, 0);
        s->want_close = 0;
    }
}

#endif
