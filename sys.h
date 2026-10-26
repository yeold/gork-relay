/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * sys.h -- the system calls, as they differ on Windows.
 *
 * With MinGW the sockets are Winsock's: not file descriptors, poll() is
 * WSAPoll(), errors are not in errno, and there is no fork(), so each pump
 * is a thread.  Cygwin, and every Unix, have the POSIX calls.
 */
#ifndef SYS_H
#define SYS_H

#if defined(_WIN32) && !defined(__CYGWIN__)
#define WINSOCK 1
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600     /* WSAPoll and inet_pton: Vista */
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>
#include <unistd.h>             /* getopt: MinGW has it */

typedef unsigned long nfds_t;
#define poll(p, n, ms)  win_poll(p, n, ms)
#define sock_errno      WSAGetLastError()
#define SOCK_EINTR      WSAEINTR
#define SOCK_EAGAIN     WSAEWOULDBLOCK
#define SHUT_WR         SD_SEND

int         win_poll(struct pollfd *p, nfds_t n, int ms);
/* A connected pair of loopback TCP sockets: Winsock has no socketpair. */
int         socketpair_tcp(int sv[2]);
const char *sock_strerror(int e);
/* Add the certificates of Windows' own root store to OpenSSL's. */
struct ssl_ctx_st;
void        load_windows_roots(struct ssl_ctx_st *ctx);
#else
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define closesocket(fd) close(fd)
#define sock_errno      errno
#define SOCK_EINTR      EINTR
#define SOCK_EAGAIN     EAGAIN
#define sock_strerror   strerror
#endif

/* A message on stderr, after "gork-relay: ", in one write, so that the
   pumps' lines do not run into each other; with say_time set (-v), after
   the date and time as well. */
extern int say_time;
void say(const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)))
#endif
    ;

/* Start Winsock, and leave stderr unbuffered; nothing elsewhere.  0, or -1
   with a message. */
int net_init(void);
int set_nonblock(int fd);

#endif
