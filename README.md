# gork-relay

The relay for [gork](https://github.com/yeold/gork), the AI agent harness
for old and obscure operating systems.

gork does not do TLS: it sends plain HTTP to a relay on your network, and
the relay passes it on to the API over TLS. Until now that relay was one
line of socat. gork-relay does the same job, and adds a second way in for
machines that have no TCP/IP at all: **SPX, over an IPX network**.

```
+----------+  plain HTTP   +------------+     TLS     +--------------+
|   gork   |-- TCP ------->| gork-relay |------------>| /v1/messages |
|          |-- SPX (IPX) ->|            |             +--------------+
+----------+               +------------+
```

**The relay sees everything in the clear, your API key included.** Run it
on a machine and a network you trust.

## Status

New. What has been tried:

| Part | State |
|---|---|
| TCP to TLS | Works; `make check`, and by hand against a real HTTPS server. |
| SPX | Works with two real IPX stacks, both in QEMU on Ethernet. Novell's IPX/SPX on DOS (PDIPX 1.10 on a packet driver, FreeDOS 1.3, Ethernet II frames): gork's `dostest.py` runs a round trip with a reply of many packets. And NWLink, the IPX of Windows (Windows Me): it asked for its network by RIP, took the number and the frame type from the relay's answer, and gork's Windows build ran its tool round trips over it, by hand. The test client in `test/relaytest.py` covers the other Ethernet encapsulations, lost packets and several connections at once. Not tried: `IPXODI`, and Windows versions other than Me. |
| The `eth:` link | Works on Linux, on a tap device, as a packet socket and through libpcap (`RELAYTEST_TAP=1 make check`, as root). Not run on Windows with Npcap. |
| Windows | A native `.exe` (MinGW-w64, 32 and 64 bit) passes `make check`, TLS included, under Wine. Cygwin builds use the POSIX code. Both are built and checked on Windows by GitHub Actions. |

## Build

A C99 compiler, make and OpenSSL 1.1 or later (`libssl-dev`,
`openssl-devel`).

```sh
make            # Linux
make check      # needs python3
```

`RELAYTEST_TAP=1 make check`, as root, also checks the `eth:` link, on a
tap device it makes.

On other Unix systems, and on Cygwin, the `eth:` link goes through libpcap
or [Npcap](https://npcap.com/):

```sh
make PCAP=1
make PCAP=1 PCAPLIB=-lwpcap PCAPINC=-I/path/npcap-sdk/Include \
     LDFLAGS=-L/path/npcap-sdk/Lib/x64        # Cygwin
```

Without `PCAP=1` a build that is not for Linux still has TCP and the
`udp:` link.

On Windows, either build with Cygwin (`gcc-core`, `make`, `libssl-devel`)
and plain `make`, or make a native `.exe` with MinGW-w64, in MSYS2 or
from Linux:

```sh
make WIN=1                                  # MSYS2 (UCRT64)
make WIN=1 CC=x86_64-w64-mingw32-gcc LDFLAGS="-static -s" \
     SSLLIBS="$(x86_64-w64-mingw32-pkg-config --static --libs openssl)"
```

The second needs no DLLs beyond Windows' own. The native build checks
certificates against the ones Windows trusts. `RELAYTEST_TLS=1 make check`
also checks TLS on the Internet.

## Run

In place of socat:

```sh
gork-relay api.anthropic.com
```

listens on TCP port 8443 and passes everything on to
`api.anthropic.com:443`, checking its certificate. gork's side is
unchanged: `relay = relayhost:8443`. It says so when it starts:

```
gork-relay: v0.3, TCP on 8443, passing on to api.anthropic.com:443
```

With SPX as well, on the network interface `eth0`:

```sh
sudo gork-relay -x eth:eth0 -n 1 api.anthropic.com
```

It prints its IPX address, `network.node:socket`, which is what a client
connects to:

```
gork-relay: SPX at 00000001.525400A1B2C3:8443 on eth:eth0
```

| Option | Default | |
|---|---|---|
| `-t [ADDR:]PORT` | `8443` | Listen for TCP there. `-t 0`: no TCP. |
| `-x LINK` | none | Listen for SPX on this link: `eth:IFACE`, or `udp:[ADDR:]PORT`. |
| `-n NET` | `0` | Our IPX network number, in hex. With a number, RIP requests are answered, and clients that find their network that way (NWLink does) learn it and the frame type. `0` is "this segment", which is enough when nothing routes. |
| `-s SOCKET` | `8443` | Our SPX socket, in hex. |
| `-m MAC` | the interface's | Our node address. |
| `-p` | | The upstream server speaks plain HTTP: no TLS. For a local model server, and for tests. |
| `-k` | | Do not check the upstream certificate. |
| `-v` | | Report each connection, and put the time on every line (see below). |

The packet socket needs root or `CAP_NET_RAW`
(`setcap cap_net_raw+ep gork-relay`).

With `-v` each connection is numbered and followed from start to end:
who connected, the upstream address and TLS, the request line and
`Host`, the reply's status line, and what happened at the end.

```
2026-10-26 08:18:08 gork-relay: #1: from 192.168.1.20:34326
2026-10-26 08:18:08 gork-relay: #1: connected to api.anthropic.com:443 (160.79.104.10)
2026-10-26 08:18:08 gork-relay: #1: TLSv1.3, TLS_AES_256_GCM_SHA384
2026-10-26 08:18:08 gork-relay: #1: > POST /v1/messages HTTP/1.0, Host: api.anthropic.com
2026-10-26 08:18:11 gork-relay: #1: < HTTP/1.1 200 OK
2026-10-26 08:18:11 gork-relay: #1: done, 2104 bytes sent, 1530 received, 2950 ms: closed
```

No other header is shown, nor a query string: they are where API keys
go. The report goes to stderr, so `2>relay.log` keeps it in a file.

### Links

- **`eth:IFACE`**: a network interface. Frames are read and written raw,
  so the kernel needs no IPX, which is as well: Linux has had none since
  4.18, Windows none since Vista. IPX is taken in Ethernet II, 802.2,
  raw 802.3 and SNAP frames, and each client is answered in the framing
  it used.
- **`udp:[ADDR:]PORT`**: one Ethernet frame per UDP datagram. This is
  what QEMU's `-netdev socket,udp=...` and `-netdev dgram` send, so an
  emulated machine's network card can be attached straight to the relay,
  with no root and no bridge:

  ```sh
  gork-relay -x udp:127.0.0.1:9000 api.anthropic.com
  qemu-system-i386 ... -netdev socket,id=n0,udp=127.0.0.1:9000,localaddr=127.0.0.1:9001 \
                       -device ne2k_isa,netdev=n0
  ```

### Other servers

The relay does not read what it passes on, so any server will do:
OpenAI, a hosted OpenAI-compatible service, or vLLM, LM Studio, Ollama
or llama.cpp. The API format is chosen in gork (`protocol = openai`).

```sh
gork-relay api.openai.com                     # HTTPS, port 443
gork-relay -k vllm.lan:8000                   # HTTPS, self-signed certificate
gork-relay -p -x eth:eth0 lmstudio.lan:1234   # plain HTTP, for SPX clients
```

The `Host` header goes on as gork wrote it, so gork's `host` should name
the upstream server, not the relay. A local server on plain HTTP needs
no relay over TCP: gork can reach it directly.

## What it implements

One IPX node with one SPX listener, in user space ([ipx.c](ipx.c)):

- SPX connections: establishment, sequenced data both ways with
  acknowledgement, retransmission and the allocation window, watchdog
  packets, and the end-of-connection exchange. No SPX II: a client that
  offers it is answered with plain SPX.
- RIP: requests for the relay's network number are answered. It does not
  route and does not advertise itself with SAP.
- Each connection is handed to a process of its own (on Windows, a
  thread), which does the TLS, as each TCP connection is.

| File | |
|---|---|
| [relay.c](relay.c) | Options, the TCP listener, the pump to the upstream server (TLS) |
| [ipx.c](ipx.c), [ipx.h](ipx.h) | IPX input, RIP, SPX |
| [frame.c](frame.c), [frame.h](frame.h) | IPX in and out of link-layer frames |
| [link.c](link.c), [link.h](link.h) | The links: packet socket, libpcap, UDP |
| [sys.c](sys.c), [sys.h](sys.h) | What differs on Windows: Winsock, threads, its certificates |
| [test/relaytest.py](test/relaytest.py) | The checks, with an SPX client of their own |

## Licence

gork-relay is free software: you can redistribute it and modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version. It comes with no warranty. The full text is in
[LICENSE](LICENSE).

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to send changes.
