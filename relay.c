/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * gork-relay -- the relay gork talks to.
 *
 * gork sends plain HTTP; the relay passes it on over TLS, as
 *     socat TCP-LISTEN:8443,fork,reuseaddr OPENSSL:api.anthropic.com:443
 * does.  It also listens on SPX, for clients on an IPX network, over
 * Ethernet or token ring (ipx.h).
 *
 * Copyright (C) 2026 the gork authors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.  It is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE.
 */
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "sys.h"
#ifdef WINSOCK
#include <process.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ipx.h"
#include "version.h"

#define VERSION "0.3"
/* In a git checkout the Makefile names the build (version.h):
   v0.2-beta-<commits>, and -dirty with tracked files changed. */
#ifndef GIT_VERSION
#define GIT_VERSION VERSION
#endif

static const char *up_host;             /* where everything is passed on to */
static const char *up_port = "443";
static int         up_plain;            /* no TLS: a local server, tests */
static int         up_noverify;
static int         verbose;

static void usage(void) {
    fprintf(stderr,
"usage: gork-relay [options] HOST[:PORT]   (or --version)\n"
"Pass what gork sends on to HOST (port 443 unless given), over TLS.\n"
"  -t [ADDR:]PORT  listen for TCP there (default 8443; -t 0: no TCP)\n"
"  -x LINK         listen for SPX on this link:\n"
"                    eth:IFACE         a network interface\n"
"                    udp:[ADDR:]PORT   frames in UDP, as QEMU sends them\n"
"  -n NET          our IPX network number, hex (default 0: the local one)\n"
"  -s SOCKET       our SPX socket, hex (default 8443)\n"
"  -m MAC          our node address on the link, aa:bb:cc:dd:ee:ff\n"
"  -p              HOST speaks plain HTTP: no TLS\n"
"  -k              do not check HOST's certificate\n"
"  -v              say what happens\n");
    exit(2);
}

/* ------------------------------------------------------------- the pump */

/* One connection: the client's socket, and what -v calls it. */
struct job {
    int      client;
    unsigned id;
    char     from[64];
};

static unsigned jobs;                   /* connections so far, to number them */

static long now_ms(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (long) (tv.tv_sec % 1000000) * 1000 + tv.tv_usec / 1000;
}

/* Up to the line's end, at most size - 1 bytes, unprintables as '?'. */
static void copy_line(const char *p, size_t n, char *out, size_t size) {
    size_t i;

    for (i = 0; i < n && i + 1 < size && p[i] != '\r' && p[i] != '\n'; i++)
        out[i] = isprint((unsigned char) p[i]) ? p[i] : '?';
    out[i] = '\0';
}

/* What -v says of a request: its first line, without a query string
   (some APIs take the key there), and its Host.  No other header: they
   hold the key. */
static void describe_request(const char *p, size_t n, char *out,
                             size_t size) {
    char   host[128] = "", *q;
    size_t i;

    copy_line(p, n, out, size);
    if ((q = strchr(out, '?')) != NULL) {
        char *v = strrchr(out, ' ');    /* keep " HTTP/1.0" */

        if (v > q)
            memmove(q, v, strlen(v) + 1);
        else
            *q = '\0';
    }
    for (i = 0; i + 6 < n; i++) {
        if (p[i] != '\n')
            continue;
        if (p[i + 1] == '\r' || p[i + 1] == '\n')
            break;                      /* the end of the headers */
        if (tolower((unsigned char) p[i + 1]) == 'h' &&
            tolower((unsigned char) p[i + 2]) == 'o' &&
            tolower((unsigned char) p[i + 3]) == 's' &&
            tolower((unsigned char) p[i + 4]) == 't' && p[i + 5] == ':') {
            for (i += 6; i < n && p[i] == ' '; i++)
                ;
            copy_line(p + i, n - i, host, sizeof host);
            break;
        }
    }
    if (*host != '\0' && strlen(out) + strlen(host) + 9 < size) {
        strcat(out, ", Host: ");
        strcat(out, host);
    }
}

static int connect_upstream(unsigned id) {
    struct addrinfo hints, *res, *ai;
    char            addr[64];
    int             fd = -1, e;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    e = getaddrinfo(up_host, up_port, &hints, &res);
    if (e != 0) {
        say("#%u: %s: %s\n", id, up_host, gai_strerror(e));
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = (int) socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        e = sock_errno;
        if (fd >= 0)
            closesocket(fd);
        fd = -1;
    }
    if (fd >= 0 && verbose &&
        getnameinfo(ai->ai_addr, ai->ai_addrlen, addr, sizeof addr, NULL, 0,
                    NI_NUMERICHOST) == 0)
        say("#%u: connected to %s:%s (%s)\n", id, up_host, up_port, addr);
    freeaddrinfo(res);
    if (fd < 0)
        say("#%u: cannot connect to %s:%s: %s\n", id, up_host, up_port,
            sock_strerror(e));
    return fd;
}

static int write_all(int fd, const char *p, size_t n) {
    while (n > 0) {
        int w = (int) send(fd, p, (int) n, 0);

        if (w < 0 && sock_errno == SOCK_EINTR)
            continue;
        if (w <= 0)
            return -1;
        p += w;
        n -= (size_t) w;
    }
    return 0;
}

/* Why an SSL call failed, for -v. */
static const char *ssl_why(SSL *ssl, int r) {
    static char   buf[160];
    unsigned long e;

    switch (SSL_get_error(ssl, r)) {
    case SSL_ERROR_ZERO_RETURN:
        return "closed";
    case SSL_ERROR_SYSCALL:
        if ((e = ERR_peek_error()) == 0)
            return "closed without TLS close_notify";
        break;
    default:
        e = ERR_peek_error();
    }
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf;
}

/* Copy bytes between the client and the upstream server until both have
   finished, then close the client: in a process of its own, or on Windows
   a thread.  0, or 1 on failure. */
static int pump(const struct job *j) {
    char          buf[16384], line[320];
    struct pollfd p[2];
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;
    int           client = j->client, up;
    int           client_open = 1, rc = 1;
    unsigned long sent = 0, got = 0;
    long          start = now_ms();
    const char   *why = "failed";

    if (verbose)
        say("#%u: from %s\n", j->id, j->from);
    up = connect_upstream(j->id);
    if (up < 0)
        goto done;
    if (!up_plain) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL)
            goto done;
        if (!up_noverify) {
#ifdef WINSOCK
            /* the certificates Windows trusts; OpenSSL's default paths are
               the build machine's, so only when they are named */
            load_windows_roots(ctx);
            if (getenv("SSL_CERT_FILE") != NULL ||
                getenv("SSL_CERT_DIR") != NULL)
#endif
            SSL_CTX_set_default_verify_paths(ctx);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
        ssl = SSL_new(ctx);
        if (ssl == NULL)
            goto done;
        SSL_set_fd(ssl, up);
        SSL_set_tlsext_host_name(ssl, up_host);
        if (!up_noverify)
            SSL_set1_host(ssl, up_host);
        if (SSL_connect(ssl) != 1) {
            say("#%u: TLS with %s failed: ", j->id, up_host);
            ERR_print_errors_fp(stderr);
            if (SSL_get_verify_result(ssl) != X509_V_OK)
                say("#%u: certificate: %s\n", j->id,
                    X509_verify_cert_error_string(
                        SSL_get_verify_result(ssl)));
            SSL_free(ssl);
            ssl = NULL;
            goto done;
        }
        if (verbose)
            say("#%u: %s, %s%s\n", j->id, SSL_get_version(ssl),
                SSL_get_cipher_name(ssl),
                up_noverify ? ", certificate not checked" : "");
    }
    rc = 0;
    p[0].fd = client;
    p[1].fd = up;
    p[1].events = POLLIN;
    for (;;) {
        int r;

        p[0].events = client_open ? POLLIN : 0;
        p[0].revents = p[1].revents = 0;
        /* TLS may hold bytes it has read already */
        if (!(ssl != NULL && SSL_pending(ssl) > 0) &&
            poll(p, 2, -1) < 0 && sock_errno != SOCK_EINTR) {
            why = "poll failed";
            break;
        }
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            r = (int) recv(client, buf, sizeof buf, 0);
            if (r > 0) {
                if (verbose && sent == 0) {
                    describe_request(buf, (size_t) r, line, sizeof line);
                    say("#%u: > %s\n", j->id, line);
                }
                sent += (unsigned long) r;
                if (ssl != NULL ? SSL_write(ssl, buf, (int) r) <= 0
                                : write_all(up, buf, (size_t) r) != 0) {
                    why = "sending to the server failed";
                    break;
                }
            } else if (r == 0 || sock_errno != SOCK_EINTR) {
                /* gork sends its request and waits: keep the upstream
                   open for the reply */
                client_open = 0;
                if (ssl == NULL)
                    shutdown(up, SHUT_WR);
            }
        }
        if ((p[1].revents & (POLLIN | POLLHUP | POLLERR)) ||
            (ssl != NULL && SSL_pending(ssl) > 0)) {
            r = ssl != NULL ? SSL_read(ssl, buf, sizeof buf)
                            : (int) recv(up, buf, sizeof buf, 0);
            if (r <= 0) {               /* the reply is complete */
                why = ssl != NULL ? ssl_why(ssl, r)
                      : r == 0 ? "closed" : sock_strerror(sock_errno);
                break;
            }
            if (verbose && got == 0) {
                copy_line(buf, (size_t) r, line, sizeof line);
                say("#%u: < %s\n", j->id, line);
            }
            got += (unsigned long) r;
            if (write_all(client, buf, (size_t) r) != 0) {
                why = "the client went away";
                break;
            }
        }
    }
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
done:
    if (verbose)
        say("#%u: done, %lu bytes sent, %lu received, %ld ms: %s\n", j->id,
            sent, got, now_ms() - start, rc == 0 ? why : "failed");
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (up >= 0)
        closesocket(up);
    closesocket(client);
    return rc;
}

#ifdef WINSOCK
static unsigned __stdcall pump_thread(void *arg) {
    unsigned rc = (unsigned) pump((struct job *) arg);

    free(arg);
    return rc;
}
#endif

/* Start a pump for the connection `client`, from `from`; `other` is a
   descriptor the pump has no use for (-1: none).  0, or -1 with a
   message. */
static int start_pump(int client, const char *from, int other) {
    struct job j;
#ifdef WINSOCK
    struct job *copy;
    uintptr_t   t = 0;
#else
    pid_t       pid;
#endif

    j.client = client;
    j.id = ++jobs;
    snprintf(j.from, sizeof j.from, "%s", from);
#ifdef WINSOCK
    (void) other;
    if ((copy = malloc(sizeof *copy)) != NULL) {
        *copy = j;
        t = _beginthreadex(NULL, 0, pump_thread, copy, 0, NULL);
    }
    if (t == 0) {
        say("thread: %s\n", strerror(errno));
        free(copy);
        closesocket(client);
        return -1;
    }
    CloseHandle((HANDLE) t);
    return 0;
#else
    pid = fork();
    if (pid == 0) {
        if (other >= 0)
            close(other);
        _exit(pump(&j));
    }
    if (pid < 0)
        say("fork: %s\n", strerror(errno));
    close(client);
    return pid < 0 ? -1 : 0;
#endif
}

/* A pump for an SPX connection: our end of a socket pair. */
static int spx_accept(void) {
    int sv[2];

#ifdef WINSOCK
    if (socketpair_tcp(sv) != 0)
        return -1;
#else
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
#endif
    if (start_pump(sv[1], "SPX", sv[0]) != 0) {
        closesocket(sv[0]);
        return -1;
    }
    return sv[0];
}

/* ----------------------------------------------------------------- main */

static int tcp_listen(const char *spec) {
    struct sockaddr_in a;
    const char        *colon = strrchr(spec, ':');
    char               host[64] = "0.0.0.0";
    int                fd, one = 1;

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    if (colon != NULL) {
        if ((size_t) (colon - spec) >= sizeof host)
            usage();
        memcpy(host, spec, colon - spec);
        host[colon - spec] = '\0';
        spec = colon + 1;
    }
    a.sin_port = htons((unsigned short) atoi(spec));
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1)
        usage();
    fd = (int) socket(AF_INET, SOCK_STREAM, 0);
#ifndef WINSOCK
    /* on Windows it would let another program take the port from us */
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
    (void) one;
    if (fd < 0 || bind(fd, (struct sockaddr *) &a, sizeof a) != 0 ||
        listen(fd, 16) != 0) {
        say("cannot listen on %s:%s: %s\n", host,
                spec, sock_strerror(sock_errno));
        exit(1);
    }
    return fd;
}

static int hex_bytes(const char *s, unsigned char *out, int n) {
    unsigned long v = strtoul(s, NULL, 16);
    int           i;

    if (s[strspn(s, "0123456789abcdefABCDEF")] != '\0' || *s == '\0')
        return -1;
    for (i = n - 1; i >= 0; i--, v >>= 8)
        out[i] = (unsigned char) v;
    return v == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    static struct ipx x;
    struct pollfd     p[SPX_CONNS + 2];
    const char       *tcp = "8443", *linkspec = NULL;
    char             *colon;
    unsigned char     sock[2];
    unsigned          mac[6];
    int               o, i, lfd = -1;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("gork-relay %s\n", GIT_VERSION);
        return 0;
    }
    x.socket = 0x8443;
    while ((o = getopt(argc, argv, "t:x:n:s:m:pkv")) != -1) {
        switch (o) {
        case 't': tcp = optarg; break;
        case 'x': linkspec = optarg; break;
        case 'n':
            if (hex_bytes(optarg, x.net, 4) != 0)
                usage();
            break;
        case 's':
            if (hex_bytes(optarg, sock, 2) != 0)
                usage();
            x.socket = sock[0] << 8 | sock[1];
            break;
        case 'm':
            /* %hhx: not in the C library of Windows */
            if (sscanf(optarg, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1],
                       &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
                usage();
            for (i = 0; i < 6; i++)
                x.link.mac[i] = (unsigned char) mac[i];
            x.link.have_mac = 1;
            break;
        case 'p': up_plain = 1; break;
        case 'k': up_noverify = 1; break;
        case 'v': verbose = x.verbose = say_time = 1; break;
        default: usage();
        }
    }
    if (optind != argc - 1)
        usage();
    up_host = argv[optind];
    colon = strrchr(argv[optind], ':');
    if (colon != NULL) {
        *colon = '\0';
        up_port = colon + 1;
    } else if (up_plain) {
        up_port = "80";
    }

    if (net_init() != 0)
        return 1;
#ifndef WINSOCK
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);           /* the pumps are not waited for */
#endif

    if (strcmp(tcp, "0") != 0)
        lfd = tcp_listen(tcp);
    if (linkspec != NULL) {
        if (link_open(&x.link, linkspec) != 0)
            return 1;
        x.accept = spx_accept;
        say("SPX at "
                "%02X%02X%02X%02X.%02X%02X%02X%02X%02X%02X:%04X on %s%s\n",
                x.net[0], x.net[1], x.net[2], x.net[3], x.link.mac[0],
                x.link.mac[1], x.link.mac[2], x.link.mac[3], x.link.mac[4],
                x.link.mac[5], x.socket, linkspec,
                x.link.medium == MEDIUM_TOKENRING ? " (token ring)" : "");
    }
    if (lfd < 0 && linkspec == NULL) {
        say("nothing to listen on\n");
        return 2;
    }
    /* always: a console that stays blank looks like a relay that died */
    if (lfd >= 0)
        say("%s, TCP on %s, passing on to %s:%s%s\n",
                GIT_VERSION, tcp, up_host, up_port,
                up_plain ? " (no TLS)" : "");

    for (;;) {
        int n = 0, first, r;

        if (lfd >= 0) {
            p[n].fd = lfd;
            p[n++].events = POLLIN;
        }
        if (linkspec != NULL && x.link.fd >= 0) {
            p[n].fd = x.link.fd;
            p[n++].events = POLLIN;
        }
        first = n;
        if (linkspec != NULL)
            n += spx_pollfds(p + n, SPX_CONNS);
        /* wake for retransmissions, and for a link poll() cannot watch */
        r = poll(p, (nfds_t) n, linkspec == NULL ? -1
                                : x.link.fd < 0 ? 10 : 100);
        if (r < 0 && sock_errno != SOCK_EINTR) {
            say("poll: %s\n",
                    sock_strerror(sock_errno));
            return 1;
        }
        if (r < 0)
            continue;
        if (lfd >= 0 && (p[0].revents & POLLIN)) {
            struct sockaddr_storage a;
            socklen_t               alen = sizeof a;
            char                    host[64] = "?", port[8] = "?", from[80];
            int c = (int) accept(lfd, (struct sockaddr *) &a, &alen);

            if (c >= 0) {
                getnameinfo((struct sockaddr *) &a, alen, host, sizeof host,
                            port, sizeof port, NI_NUMERICHOST | NI_NUMERICSERV);
                snprintf(from, sizeof from, "%s:%s", host, port);
                start_pump(c, from, lfd);
            }
        }
        if (linkspec != NULL) {
            ipx_input(&x);
            spx_service(&x, p + first, n - first);
        }
    }
}
