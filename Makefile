# gork-relay: needs a C99 compiler and OpenSSL 1.1 or later.
#   make                 Linux: the eth link is a packet socket
#   make PCAP=1          the eth link through libpcap (other Unix)
#   make PCAP=1 PCAPLIB=-lwpcap PCAPINC=-I/path/npcap-sdk/Include \
#        LDFLAGS=-L/path/npcap-sdk/Lib/x64        Cygwin, with Npcap
CC      ?= cc
CFLAGS  ?= -O2 -Wall -W
PCAPLIB ?= -lpcap
PREFIX  ?= /usr/local
ifdef PCAP
CFLAGS  += -DUSE_PCAP $(PCAPINC)
LIBS    += $(PCAPLIB)
endif
LIBS    += -lssl -lcrypto

OBJS = relay.o ipx.o link.o frame.o

gork-relay: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(OBJS): ipx.h link.h frame.h

check: gork-relay
	python3 test/relaytest.py ./gork-relay

install: gork-relay
	install -D gork-relay $(DESTDIR)$(PREFIX)/bin/gork-relay

clean:
	rm -f gork-relay *.o

.PHONY: check install clean
