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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sys.h"
#ifdef WINSOCK
#include <process.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ipx.h"

#define VERSION "0.1"

static const char *up_host;             /* where everything is passed on to */
static const char *up_port = "443";
static int         up_plain;            /* no TLS: a local server, tests */
static int         up_noverify;
static int         verbose;

static void usage(void) {
    fprintf(stderr,
"usage: gork-relay [options] HOST[:PORT]\n"
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

static int connect_upstream(void) {
    struct addrinfo hints, *res, *ai;
    int             fd = -1, e;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    e = getaddrinfo(up_host, up_port, &hints, &res);
    if (e != 0) {
        fprintf(stderr, "gork-relay: %s: %s\n", up_host, gai_strerror(e));
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
    freeaddrinfo(res);
    if (fd < 0)
        fprintf(stderr, "gork-relay: cannot connect to %s:%s: %s\n", up_host,
                up_port, sock_strerror(e));
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

/* Copy bytes between the client and the upstream server until both have
   finished, then close the client: in a process of its own, or on Windows
   a thread.  0, or 1 on failure. */
static int pump(int client) {
    char          buf[16384];
    struct pollfd p[2];
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;
    int           up = connect_upstream();
    int           client_open = 1, rc = 1;

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
            fprintf(stderr, "gork-relay: TLS with %s failed: ", up_host);
            ERR_print_errors_fp(stderr);
            if (SSL_get_verify_result(ssl) != X509_V_OK)
                fprintf(stderr, "gork-relay: certificate: %s\n",
                        X509_verify_cert_error_string(
                            SSL_get_verify_result(ssl)));
            SSL_free(ssl);
            ssl = NULL;
            goto done;
        }
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
            poll(p, 2, -1) < 0 && sock_errno != SOCK_EINTR)
            break;
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            r = (int) recv(client, buf, sizeof buf, 0);
            if (r > 0) {
                if (ssl != NULL ? SSL_write(ssl, buf, (int) r) <= 0
                                : write_all(up, buf, (size_t) r) != 0)
                    break;
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
            if (r <= 0)
                break;                  /* the reply is complete */
            if (write_all(client, buf, (size_t) r) != 0)
                break;
        }
    }
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
done:
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (up >= 0)
        closesocket(up);
    closesocket(client);
    return rc;
}

#ifdef WINSOCK
static unsigned __stdcall pump_thread(void *client) {
    return (unsigned) pump((int) (intptr_t) client);
}
#endif

/* Start a pump for the connection `client`; `other` is a descriptor the
   pump has no use for (-1: none).  0, or -1 with a message. */
static int start_pump(int client, int other) {
#ifdef WINSOCK
    uintptr_t t = _beginthreadex(NULL, 0, pump_thread,
                                 (void *) (intptr_t) client, 0, NULL);

    (void) other;
    if (t == 0) {
        perror("gork-relay: thread");
        closesocket(client);
        return -1;
    }
    CloseHandle((HANDLE) t);
    return 0;
#else
    pid_t pid = fork();

    if (pid == 0) {
        if (other >= 0)
            close(other);
        _exit(pump(client));
    }
    if (pid < 0)
        perror("gork-relay: fork");
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
    if (start_pump(sv[1], sv[0]) != 0) {
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
        fprintf(stderr, "gork-relay: cannot listen on %s:%s: %s\n", host,
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
        case 'v': verbose = x.verbose = 1; break;
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
        fprintf(stderr, "gork-relay: SPX at "
                "%02X%02X%02X%02X.%02X%02X%02X%02X%02X%02X:%04X on %s%s\n",
                x.net[0], x.net[1], x.net[2], x.net[3], x.link.mac[0],
                x.link.mac[1], x.link.mac[2], x.link.mac[3], x.link.mac[4],
                x.link.mac[5], x.socket, linkspec,
                x.link.medium == MEDIUM_TOKENRING ? " (token ring)" : "");
    }
    if (lfd < 0 && linkspec == NULL) {
        fprintf(stderr, "gork-relay: nothing to listen on\n");
        return 2;
    }
    if (verbose && lfd >= 0)
        fprintf(stderr, "gork-relay: TCP on %s, passing on to %s:%s%s\n",
                tcp, up_host, up_port, up_plain ? " (no TLS)" : "");

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
            fprintf(stderr, "gork-relay: poll: %s\n",
                    sock_strerror(sock_errno));
            return 1;
        }
        if (r < 0)
            continue;
        if (lfd >= 0 && (p[0].revents & POLLIN)) {
            int c = (int) accept(lfd, NULL, NULL);

            if (c >= 0)
                start_pump(c, lfd);
        }
        if (linkspec != NULL) {
            ipx_input(&x);
            spx_service(&x, p + first, n - first);
        }
    }
}
