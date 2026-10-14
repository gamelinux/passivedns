#!/usr/bin/env python3
"""Pcap regression checks for passivedns.

Builds small captures with the standard library, reads them with
`passivedns -r`, and checks the log. Set PASSIVEDNS to the binary.
Otherwise this looks for src/passivedns next to the tests directory.
"""

import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def name(n):
    out = b""
    for part in n.rstrip(".").split("."):
        raw = part.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(tid, qname, qtype=1):
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return hdr + name(qname) + struct.pack(">HH", qtype, 1)


def dns_response(tid, qname, rdata, qtype=1, ttl=300):
    hdr = struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    question = name(qname) + struct.pack(">HH", qtype, 1)
    answer = name(qname) + struct.pack(">HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return hdr + question + answer


def txt_rdata(text):
    raw = text.encode()
    out = b""
    while raw:
        chunk = raw[:255]
        raw = raw[255:]
        out += bytes([len(chunk)]) + chunk
    return out


def ipv4(src, dst, proto, payload, ident=1, off=0, total=None):
    ver_ihl = (4 << 4) | 5
    if total is None:
        total = 20 + len(payload)
    return struct.pack(
        ">BBHHHBBH4s4s",
        ver_ihl, 0, total, ident, off, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def ipv6(src, dst, nxt, payload):
    return struct.pack(
        ">IHBB16s16s",
        6 << 28, len(payload), nxt, 64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    ) + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, payload, flags=0x18, doff=5):
    hdr = struct.pack(
        ">HHIIBBHHH", sport, dport, seq, 0, doff << 4, flags, 65535, 0, 0
    )
    return hdr + (b"\x00" * (doff * 4 - 20)) + payload


def eth(payload, etype=0x0800):
    return b"\x00" * 12 + struct.pack(">H", etype) + payload


def write_pcap(path, packets):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            fh.write(struct.pack("<IIII", 1700000000, i, len(pkt), len(pkt)))
            fh.write(pkt)


def find_binary():
    env = os.environ.get("PASSIVEDNS")
    if env:
        return env
    candidate = os.path.join(ROOT, "src", "passivedns")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    sys.exit("set PASSIVEDNS to the passivedns binary")


def run_case(binary, packets, args):
    tmp = tempfile.mkdtemp(prefix="pdns-regress-")
    try:
        pcap = os.path.join(tmp, "case.pcap")
        log = os.path.join(tmp, "case.log")
        write_pcap(pcap, packets)
        cmd = [binary, "-r", pcap, "-l", log, "-L", log] + args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        text = ""
        if os.path.exists(log):
            with open(log, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        return proc.returncode, text, proc.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def expect_logged(binary, label, packets, needle, args=None):
    code, text, err = run_case(binary, packets, args or [])
    lines = [ln for ln in text.splitlines() if needle in ln]
    if code != 0 or len(lines) != 1:
        return False, "%s: exit %s lines %d\n%s\n%s" % (
            label, code, len(lines), text, err)
    return True, lines[0]


def expect_quiet(binary, label, packets, args=None):
    code, text, err = run_case(binary, packets, args or [])
    if code != 0 or text.strip():
        return False, "%s: exit %s\n%s\n%s" % (label, code, text, err)
    return True, "quiet"


def cases():
    q = dns_query(0x1234, "a.example.com")
    a = dns_response(0x1234, "a.example.com", socket.inet_aton("9.9.9.9"))
    yield ("udp-a", [
        eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 53, q))),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, udp(53, 40000, a))),
    ], "a.example.com", None)

    udp_dg = udp(53, 40000, a)
    frag1, frag2 = udp_dg[:64], udp_dg[64:]
    yield ("ipv4-frag", [
        eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 53, q), ident=1)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag1, ident=9, off=0x2000)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag2, ident=9, off=64 // 8)),
    ], "a.example.com", None)

    # Same first fragment twice. Overlap drops the datagram.
    yield ("ipv4-overlap", [
        eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 53, q), ident=1)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag1, ident=9, off=0x2000)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag1, ident=9, off=0x2000)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag2, ident=9, off=64 // 8)),
    ], None, None)

    src6, dst6 = "2001:db8::1", "2001:db8::2"
    q6 = dns_query(0x2222, "v6.example.com")
    a6 = dns_response(0x2222, "v6.example.com", socket.inet_aton("8.8.8.8"))
    udp6 = udp(53, 40000, a6)
    f6a, f6b = udp6[:64], udp6[64:]
    frag_a = struct.pack(">BBHI", 17, 0, 0x0001, 7)
    frag_b = struct.pack(">BBHI", 17, 0, 8 << 3, 7)
    yield ("ipv6-frag", [
        eth(ipv6(src6, dst6, 17, udp(40000, 53, q6)), 0x86DD),
        eth(ipv6(dst6, src6, 44, frag_a + f6a), 0x86DD),
        eth(ipv6(dst6, src6, 44, frag_b + f6b), 0x86DD),
    ], "v6.example.com", None)

    hbh = bytes([44, 0]) + b"\x00" * 6
    qh = dns_query(0x4242, "hbhfrag.example.com")
    ah = dns_response(0x4242, "hbhfrag.example.com", socket.inet_aton("9.9.9.9"))
    udph = udp(53, 40000, ah)
    yield ("ipv6-hbh-frag", [
        eth(ipv6(src6, dst6, 17, udp(40000, 53, qh)), 0x86DD),
        eth(ipv6(dst6, src6, 0, hbh + frag_a + udph[:64]), 0x86DD),
        eth(ipv6(dst6, src6, 0, hbh + struct.pack(">BBHI", 17, 0, 8 << 3, 7) + udph[64:]), 0x86DD),
    ], "hbhfrag.example.com", None)

    hop = bytes([17, 0]) + b"\x00" * 6
    qhop = dns_query(0x3333, "hop.example.com")
    ahop = dns_response(0x3333, "hop.example.com", socket.inet_aton("1.2.3.4"))
    yield ("ipv6-hop", [
        eth(ipv6(src6, dst6, 0, hop + udp(40000, 53, qhop)), 0x86DD),
        eth(ipv6(dst6, src6, 0, hop + udp(53, 40000, ahop)), 0x86DD),
    ], "hop.example.com", None)

    qt = dns_query(0x4444, "tcp.example.com")
    at = dns_response(0x4444, "tcp.example.com", socket.inet_aton("5.6.7.8"))
    qmsg = struct.pack(">H", len(qt)) + qt
    amsg = struct.pack(">H", len(at)) + at
    yield ("tcp-split", [
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41000, 53, 1000, qmsg[:10]))),
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41000, 53, 1010, qmsg[10:]))),
        eth(ipv4("10.1.0.2", "10.1.0.1", 6, tcp(53, 41000, 5000, amsg))),
    ], "tcp.example.com", None)

    # Sequence gap in the query. The partial message is dropped.
    yield ("tcp-gap", [
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41001, 53, 1000, qmsg[:10]))),
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41001, 53, 1030, qmsg[10:]))),
        eth(ipv4("10.1.0.2", "10.1.0.1", 6, tcp(53, 41001, 5000, amsg))),
    ], None, None)

    long_txt = "A" * 1500
    qtxt = dns_query(0x5555, "txt.example.com", 16)
    atxt = dns_response(0x5555, "txt.example.com", txt_rdata(long_txt), qtype=16)
    yield ("long-txt", [
        eth(ipv4("10.2.0.1", "10.2.0.2", 17, udp(42000, 53, qtxt))),
        eth(ipv4("10.2.0.2", "10.2.0.1", 17, udp(53, 42000, atxt))),
    ], "txt.example.com", ["-X", "T"])

    short_tcp = tcp(43000, 53, 1, b"", doff=15)[:20]
    yield ("short-tcp-doff", [
        eth(ipv4("10.3.0.1", "10.3.0.2", 6, short_tcp, total=20 + 60)),
    ], None, None)

    raw = struct.pack(
        ">BBHHHBBH4s4s",
        0x40, 0, 40, 1, 0, 64, 4, 0,
        socket.inet_aton("10.4.0.1"), socket.inet_aton("10.4.0.2"),
    ) + (b"\x00" * 20)
    yield ("ihl-zero", [eth(raw)], None, ["-b", "ip"])


def main():
    binary = find_binary()
    failed = 0
    for label, packets, needle, args in cases():
        if needle:
            ok, detail = expect_logged(binary, label, packets, needle, args)
        else:
            ok, detail = expect_quiet(binary, label, packets, args)
        print("%s %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            failed += 1
            print(detail)
    if failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
