# gork-relay: needs a C99 compiler and OpenSSL 1.1 or later.
#   make                 Linux: the eth link is a packet socket
#   make PCAP=1          the eth link through libpcap (other Unix)
#   make                 Cygwin: TCP and the udp link
#   make PCAP=1 PCAPLIB=-lwpcap PCAPINC=-I/path/npcap-sdk/Include \
#        LDFLAGS=-L/path/npcap-sdk/Lib/x64        Cygwin or MinGW, with Npcap
#   make WIN=1           Windows with MinGW-w64 (MSYS2, or a cross compiler:
#                        CC=x86_64-w64-mingw32-gcc).  For an .exe that needs
#                        no OpenSSL DLLs: LDFLAGS=-static \
#                        SSLLIBS="$(pkg-config --static --libs openssl)"
CC      ?= cc
CFLAGS  ?= -O2 -Wall -W
PCAPLIB ?= -lpcap
SSLLIBS ?= -lssl -lcrypto
PREFIX  ?= /usr/local
ifdef PCAP
CFLAGS  += -DUSE_PCAP $(PCAPINC)
LIBS    += $(PCAPLIB)
endif
LIBS    += $(SSLLIBS)
ifdef WIN
EXE      = .exe
LIBS    += -lws2_32 -lcrypt32 -lgdi32 -luser32 -ladvapi32
endif

OBJS = relay.o ipx.o link.o frame.o sys.o

gork-relay$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(OBJS): ipx.h link.h frame.h sys.h

check: gork-relay$(EXE)
	python3 test/relaytest.py ./gork-relay$(EXE)

install: gork-relay$(EXE)
	install -D gork-relay$(EXE) $(DESTDIR)$(PREFIX)/bin/gork-relay$(EXE)

clean:
	rm -f gork-relay gork-relay.exe *.o

.PHONY: check install clean
