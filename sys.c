/* SPDX-License-Identifier: GPL-3.0-or-later */
/* sys.c -- see sys.h. */
#include <stdio.h>
#include <string.h>
#include "sys.h"

#ifdef WINSOCK
#include <wincrypt.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

int net_init(void) {
    WSADATA w;

    /* msvcrt buffers stderr when it is a pipe or a file: a message must
       be out before the relay is stopped */
    setvbuf(stderr, NULL, _IONBF, 0);
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        fprintf(stderr, "gork-relay: no Winsock 2.2\n");
        return -1;
    }
    return 0;
}

int set_nonblock(int fd) {
    u_long on = 1;

    return ioctlsocket((SOCKET) fd, FIONBIO, &on) == 0 ? 0 : -1;
}

int win_poll(struct pollfd *p, nfds_t n, int ms) {
    if (n == 0) {               /* WSAPoll wants at least one socket */
        Sleep(ms < 0 ? INFINITE : (DWORD) ms);
        return 0;
    }
    return WSAPoll(p, n, ms);
}

int socketpair_tcp(int sv[2]) {
    struct sockaddr_in a;
    int                len = sizeof a;
    SOCKET             l, c = INVALID_SOCKET, s = INVALID_SOCKET;

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    l = socket(AF_INET, SOCK_STREAM, 0);
    if (l == INVALID_SOCKET)
        return -1;
    if (bind(l, (struct sockaddr *) &a, sizeof a) == 0 &&
        getsockname(l, (struct sockaddr *) &a, &len) == 0 &&
        listen(l, 1) == 0 &&
        (c = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET &&
        connect(c, (struct sockaddr *) &a, sizeof a) == 0)
        s = accept(l, NULL, NULL);
    closesocket(l);
    if (s == INVALID_SOCKET) {
        if (c != INVALID_SOCKET)
            closesocket(c);
        return -1;
    }
    sv[0] = (int) s;
    sv[1] = (int) c;
    return 0;
}

const char *sock_strerror(int e) {
    static char msg[256];
    DWORD       n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                                   (DWORD) e, 0, msg, sizeof msg, NULL);

    while (n > 0 && (msg[n - 1] == '\r' || msg[n - 1] == '\n' ||
                     msg[n - 1] == '.'))
        msg[--n] = '\0';
    if (n == 0)
        sprintf(msg, "Winsock error %d", e);
    return msg;
}

void load_windows_roots(struct ssl_ctx_st *ctx) {
    X509_STORE    *store = SSL_CTX_get_cert_store(ctx);
    HCERTSTORE     sys = CertOpenSystemStoreA(0, "ROOT");
    PCCERT_CONTEXT c = NULL;

    if (sys == NULL)
        return;
    while ((c = CertEnumCertificatesInStore(sys, c)) != NULL) {
        const unsigned char *p = c->pbCertEncoded;
        X509                *x = d2i_X509(NULL, &p, (long) c->cbCertEncoded);

        if (x != NULL) {
            X509_STORE_add_cert(store, x);
            X509_free(x);
        }
    }
    CertCloseStore(sys, 0);
}
#else
#include <fcntl.h>

int net_init(void) { return 0; }

int set_nonblock(int fd) {
    return fcntl(fd, F_SETFL, O_NONBLOCK);
}
#endif
