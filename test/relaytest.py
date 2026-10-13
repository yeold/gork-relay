#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Checks for gork-relay, against a fake upstream server.

Usage:  python3 test/relaytest.py ./gork-relay

The SPX side is played by a small client here that sends its frames in UDP
datagrams, as QEMU does (-x udp:PORT), in each Ethernet encapsulation and
in token ring framing.  Exits 0 only if every check passes.

To check the eth: link as well, on a real interface, set $RELAYTEST_TAP
and run as root on Linux: the test makes a tap device, the relay listens
on it, and the client is the other end of the tap.
"""
import fcntl, http.server, os, random, select, socket, struct, subprocess
import sys, threading, time

BINARY = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./gork-relay")
UP, TCP, LINK, LINK_TR = 18080, 18443, 18444, 18445
RELAY_MAC = bytes.fromhex("02676f726b01")
MAC = bytes.fromhex("525400123456")
SOCK = 0x8443
SNAP = bytes.fromhex("aaaa030000008137")
BIG = b"0123456789abcdef" * 4000            # 64000 bytes: over a hundred packets


class Upstream(http.server.BaseHTTPRequestHandler):
    """Answers a POST with its body turned round, or with BIG."""
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        out = BIG if self.path == "/big" else body[::-1]
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def request(path, body):
    return (b"POST %s HTTP/1.0\r\nHost: fake\r\nContent-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % (path, len(body))) + body


def reply_body(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.0 200"), raw[:80]
    return body


# ------------------------------------------------------- frames and IPX

def encap(frame, ipx, medium, rif=b""):
    """An IPX packet from us to the relay, in a link-layer frame."""
    llc = {"8022": b"\xe0\xe0\x03", "snap": SNAP}.get(frame, b"")
    if medium == "tr":
        src = bytes([MAC[0] | 0x80]) + MAC[1:] if rif else MAC
        return b"\x10\x40" + RELAY_MAC + src + rif + llc + ipx
    body = llc + ipx
    if frame == "eth2":
        return RELAY_MAC + MAC + b"\x81\x37" + body
    return RELAY_MAC + MAC + struct.pack(">H", len(body)) + body


def decap(frame, f, medium, rif=b""):
    """The IPX packet in a frame from the relay; checks its framing."""
    llc = {"8022": b"\xe0\xe0\x03", "snap": SNAP}.get(frame, b"")
    if medium == "tr":
        assert f[:2] == b"\x10\x40" and f[2:8] == MAC, f[:14].hex()
        if rif:
            # our route, turned round
            back = bytes([rif[0] & 0x1f, rif[1] ^ 0x80]) + rif[2:]
            assert f[8] & 0x80 and f[14:14 + len(rif)] == back, f[:32].hex()
            f = f[:14] + f[14 + len(rif):]
        assert f[8:14][1:] == RELAY_MAC[1:], f[:14].hex()
        p = f[14:]
    else:
        assert f[:6] == MAC and f[6:12] == RELAY_MAC, f[:14].hex()
        kind = struct.unpack(">H", f[12:14])[0]
        assert (kind == 0x8137) == (frame == "eth2"), (frame, hex(kind))
        assert len(f) >= 60, len(f)
        p = f[14:] if frame == "eth2" else f[14:14 + kind]
    assert p.startswith(llc), (frame, p[:8].hex())
    p = p[len(llc):]
    assert p[:2] == b"\xff\xff"
    return p[:struct.unpack(">H", p[2:4])[0]]


def ipx(ptype, dsock, ssock, payload, net=b"\0\0\0\0"):
    head = struct.pack(">HHBB4s6sH4s6sH", 0xffff, 30 + len(payload), 0, ptype,
                       net, RELAY_MAC, dsock, net, MAC, ssock)
    return head + payload


class Spx:
    """The client end of one SPX connection over the UDP link."""

    def __init__(self, port, frame="eth2", medium="eth", rif=b"", drop=0.0):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(0.3)
        self.to = ("127.0.0.1", port)
        self.tap = None                         # or the tap's descriptor
        self.frame, self.medium, self.rif, self.drop = frame, medium, rif, drop
        self.id, self.peer = random.randrange(1, 0xff00), 0xffff
        self.seq = self.ack = 0
        self.sock = random.randrange(0x4000, 0x7fff)
        self.sent = self.lost = 0

    def send(self, ctl, dst, seq, data=b""):
        head = struct.pack(">BBHHHHH", ctl, dst, self.id, self.peer, seq,
                           self.ack, (self.ack + 3) & 0xffff)
        self.sent += 1
        if random.random() < self.drop:
            self.lost += 1
            return
        f = encap(self.frame, ipx(5, SOCK, self.sock, head + data),
                  self.medium, self.rif)
        if self.tap is not None:
            os.write(self.tap, f.ljust(60, b"\0"))
        else:
            self.s.sendto(f, self.to)

    def recv(self):
        """One SPX packet from the relay: (ctl, dst, seq, ack, data)."""
        while True:
            if self.tap is not None:
                if not select.select([self.tap], [], [], 0.3)[0]:
                    return None
                f = os.read(self.tap, 8192)
                if f[:6] != MAC or f[6:12] != RELAY_MAC:
                    continue                    # the kernel's own chatter
            else:
                try:
                    f = self.s.recv(8192)
                except socket.timeout:
                    return None
            if random.random() < self.drop:
                continue
            p = decap(self.frame, f, self.medium, self.rif)
            assert p[5] == 5 and p[16:18] == struct.pack(">H", self.sock)
            ctl, dst, src, did, seq, ack, alloc = struct.unpack(">BBHHHHH",
                                                                p[30:42])
            assert did == self.id, (did, self.id)
            self.peer = src
            return ctl, dst, seq, ack, p[42:]

    def connect(self):
        for _ in range(20):
            self.send(0xc0, 0, 0)
            r = self.recv()
            if r is not None:
                assert r[0] & 0x80 and self.peer != 0xffff, r
                return
        raise AssertionError("no answer to the connection request")

    def write(self, data):
        for i in range(0, len(data), 534):
            for _ in range(40):
                self.send(0x40, 0, self.seq, data[i:i + 534])
                r = self.recv()
                while r is not None and not (r[0] & 0x80):
                    self.take(r)                # the reply has begun
                    r = self.recv()
                if r is not None and r[3] == (self.seq + 1) & 0xffff:
                    break
            else:
                raise AssertionError("data packet never acknowledged")
            self.seq = (self.seq + 1) & 0xffff

    def take(self, r):
        """A data packet from the relay: keep it if it is the next one."""
        ctl, dst, seq, ack, data = r
        if seq == self.ack:
            self.ack = (self.ack + 1) & 0xffff
            if dst == 0xfe:
                self.ended = True
                self.send(0, 0xff, self.seq)
                return
            self.got += data
        self.send(0x80, 0, self.seq)            # acknowledge

    got, ended = b"", False

    def read_all(self, secs=60):
        end = time.time() + secs
        while not self.ended and time.time() < end:
            r = self.recv()
            if r is not None and not (r[0] & 0x80):
                self.take(r)
        assert self.ended, "no end of connection; %d bytes" % len(self.got)
        return self.got


def spx_round_trip(port, body, path=b"/", tap=None, **kw):
    c = Spx(port, **kw)
    c.tap = tap
    c.connect()
    c.write(request(path, body))
    return c, reply_body(c.read_all())


# --------------------------------------------------------------- checks

def check_tcp():
    for path, body, want in ((b"/", b"hello", b"olleh"), (b"/big", b"x", BIG)):
        s = socket.create_connection(("127.0.0.1", TCP))
        s.sendall(request(path, body))
        raw = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            raw += d
        assert reply_body(raw) == want
    print("ok: TCP")


def check_spx_frames():
    for frame in ("eth2", "8022", "raw", "snap"):
        # odd and even lengths: raw 802.3 pads to an even one
        for body in (b"abc", b"abcd"):
            _, got = spx_round_trip(LINK, body, frame=frame)
            assert got == body[::-1], (frame, got)
    print("ok: SPX in Ethernet II, 802.2, raw 802.3 and SNAP frames")


def check_spx_big():
    body = bytes(range(256)) * 20               # ten packets up
    _, got = spx_round_trip(LINK, body)
    assert got == body[::-1]
    _, got = spx_round_trip(LINK, b"x", path=b"/big")
    assert got == BIG, len(got)
    print("ok: SPX, a request and a reply of many packets")


def check_spx_loss():
    random.seed(7)
    c, got = spx_round_trip(LINK, bytes(range(256)) * 8, path=b"/big",
                            drop=0.2)
    assert got == BIG, len(got)
    assert c.lost > 10, c.lost
    print("ok: SPX with one packet in five lost (%d of %d sent)"
          % (c.lost, c.sent))


def check_spx_parallel():
    out = {}

    def one(i):
        out[i] = spx_round_trip(LINK, b"%d" % i * 700)[1]
    ts = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert all(out.get(i) == (b"%d" % i * 700)[::-1] for i in range(8)), out
    print("ok: eight SPX connections at once")


def check_token_ring():
    rif = bytes.fromhex("c6200011002200")[:6]   # a broadcast route, 2 hops
    for frame in ("8022", "snap"):
        for r in (b"", rif):
            _, got = spx_round_trip(LINK_TR, b"ring", frame=frame,
                                    medium="tr", rif=r)
            assert got == b"gnir", (frame, r, got)
    print("ok: SPX in token ring frames, with and without a source route")


def check_eth():
    """The eth: link: a relay of its own on a tap device, and we are the
    other end of the tap."""
    global RELAY_MAC
    tap = os.open("/dev/net/tun", os.O_RDWR)
    # TUNSETIFF, IFF_TAP | IFF_NO_PI
    fcntl.ioctl(tap, 0x400454ca, struct.pack("16sH", b"gorkrelay0", 0x1002))
    subprocess.run(["ip", "link", "set", "gorkrelay0", "up"], check=True)
    with open("/sys/class/net/gorkrelay0/address") as f:
        mac = bytes.fromhex(f.read().strip().replace(":", ""))
    relay = subprocess.Popen([BINARY, "-p", "-t", "0", "-x", "eth:gorkrelay0",
                              "127.0.0.1:%d" % UP])
    saved, RELAY_MAC = RELAY_MAC, mac
    try:
        time.sleep(0.5)
        for frame in ("eth2", "8022", "raw", "snap"):
            _, got = spx_round_trip(0, b"wire", frame=frame, tap=tap)
            assert got == b"eriw", (frame, got)
        _, got = spx_round_trip(0, b"x", path=b"/big", tap=tap)
        assert got == BIG, len(got)
    finally:
        RELAY_MAC = saved
        relay.terminate()
        os.close(tap)
    print("ok: SPX on a network interface (a tap), all four encapsulations")


def check_rip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    ask = struct.pack(">H4sHH", 1, b"\xff" * 4, 0xffff, 0xffff)
    p = ipx(1, 0x453, 0x453, ask)
    p = p[:10] + b"\xff" * 6 + p[16:]           # to everyone on the segment
    s.sendto(b"\xff" * 6 + MAC + b"\x81\x37" + p, ("127.0.0.1", LINK))
    r = decap("eth2", s.recv(2048), "eth")
    op, net, hops, ticks = struct.unpack(">H4sHH", r[30:40])
    assert (op, net, hops) == (2, bytes.fromhex("00c0ffee"), 1), r.hex()
    assert r[18:22] == net and r[22:28] == RELAY_MAC
    print("ok: RIP request answered with the network number")


def main():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", UP), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    up = "127.0.0.1:%d" % UP
    relays = [subprocess.Popen([BINARY, "-p", "-n", "c0ffee", "-t", str(TCP),
                                "-x", "udp:127.0.0.1:%d" % LINK, up]),
              subprocess.Popen([BINARY, "-p", "-t", "0",
                                "-x", "udp+tr:127.0.0.1:%d" % LINK_TR, up])]
    try:
        time.sleep(0.5)
        check_tcp()
        check_spx_frames()
        check_spx_big()
        check_spx_loss()
        check_spx_parallel()
        check_token_ring()
        check_rip()
        if os.environ.get("RELAYTEST_TAP"):
            check_eth()
    finally:
        for r in relays:
            r.terminate()
        srv.shutdown()
    print("all relay checks passed")


if __name__ == "__main__":
    main()
