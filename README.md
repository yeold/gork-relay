# gork-relay

The relay for [gork](https://github.com/yeold/gork), the AI agent harness
for old and obscure operating systems.

gork does not do TLS: it sends plain HTTP to a relay on your network, and
the relay passes it on to the API over TLS. Until now that relay was one
line of socat. gork-relay does the same job, and adds a second way in for
machines that have no TCP/IP at all: **SPX, over an IPX network**, on
Ethernet or token ring.

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
| SPX | Works with gork's DOS build over Novell's IPX/SPX (PDIPX 1.10 on a packet driver, FreeDOS 1.3 in QEMU, Ethernet II frames): gork's `dostest.py` runs a round trip with a reply of many packets. The test client in `test/relaytest.py` covers the other three Ethernet encapsulations, lost packets and several connections at once. **Not yet tried with NWLink**, the IPX of Windows 95 to XP, nor with `IPXODI`. |
| The `eth:` link | Works on Linux, on a tap device, as a packet socket and through libpcap (`RELAYTEST_TAP=1 make check`, as root). Not run on Cygwin with Npcap. |
| Token ring framing | Written from the specifications and checked only against frames the test builds. No emulator has a token ring card, and Linux dropped its drivers in 3.5, so it has met no real ring. |

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

## Run

In place of socat:

```sh
gork-relay api.anthropic.com
```

listens on TCP port 8443 and passes everything on to
`api.anthropic.com:443`, checking its certificate. gork's side is
unchanged: `relay = relayhost:8443`.

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
| `-v` | | Report connections. |

The packet socket needs root or `CAP_NET_RAW`
(`setcap cap_net_raw+ep gork-relay`).

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

### Token ring

Token ring is a kind of network, not a protocol: IP and IPX both run over
it, and the machine on the ring needs a driver for its card, nothing more.
What the relay adds is the framing: on an interface that is a token ring
(`eth:tr0`) it reads and writes 802.5 frames, with IPX in 802.2 or SNAP,
and it sends replies back along the source route the request came by.

The catch is the interface. Linux removed its token ring drivers in 3.5,
so a current machine cannot be put on a ring directly. The ways in:

- a bridge or router between the ring and an Ethernet (many Cisco routers
  do it): the relay then sees Ethernet frames, and needs nothing special;
- the relay on a Linux before 3.5, with a token ring card.

For gork itself over TCP/IP, a token ring is no different from an
Ethernet to anything but the driver.

## What it implements

One IPX node with one SPX listener, in user space ([ipx.c](ipx.c)):

- SPX connections: establishment, sequenced data both ways with
  acknowledgement, retransmission and the allocation window, watchdog
  packets, and the end-of-connection exchange. No SPX II: a client that
  offers it is answered with plain SPX.
- RIP: requests for the relay's network number are answered. It does not
  route and does not advertise itself with SAP.
- Each connection is handed to a process of its own, which does the TLS,
  as each TCP connection is.

| File | |
|---|---|
| [relay.c](relay.c) | Options, the TCP listener, the pump to the upstream server (TLS) |
| [ipx.c](ipx.c), [ipx.h](ipx.h) | IPX input, RIP, SPX |
| [frame.c](frame.c), [frame.h](frame.h) | IPX in and out of Ethernet and token ring frames |
| [link.c](link.c), [link.h](link.h) | The links: packet socket, libpcap, UDP |
| [test/relaytest.py](test/relaytest.py) | The checks, with an SPX client of their own |

## Licence

gork-relay is free software: you can redistribute it and modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version. It comes with no warranty. The full text is in
[COPYING](COPYING).

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to send changes.
