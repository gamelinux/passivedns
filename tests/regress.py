#!/usr/bin/env python3
"""Pcap regression checks for passivedns.

Builds small captures with the standard library, reads them with
`passivedns -r`, and checks the log. Set PASSIVEDNS to the binary.
Otherwise this looks for src/passivedns next to the tests directory.
"""

import os
import re
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


def ipv4(src, dst, proto, payload, ident=1, off=0, total=None, ttl=64):
    ver_ihl = (4 << 4) | 5
    if total is None:
        total = 20 + len(payload)
    return struct.pack(
        ">BBHHHBBH4s4s",
        ver_ihl, 0, total, ident, off, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def ipv6(src, dst, nxt, payload, hop=64):
    return struct.pack(
        ">IHBB16s16s",
        6 << 28, len(payload), nxt, hop,
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


def write_pcap(path, packets, linktype=1, times=None):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for i, pkt in enumerate(packets):
            sec, usec = (1700000000, i) if not times else times[i]
            fh.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
            fh.write(pkt)


def charstr(text):
    raw = text.encode()
    return bytes([len(raw)]) + raw


def dns_nxdomain(tid, qname):
    hdr = struct.pack(">HHHHHH", tid, 0x8183, 1, 0, 0, 0)
    return hdr + name(qname) + struct.pack(">HH", 1, 1)


def dns_nodata(tid, qname, qtype=1):
    hdr = struct.pack(">HHHHHH", tid, 0x8180, 1, 0, 0, 0)
    return hdr + name(qname) + struct.pack(">HH", qtype, 1)


def svc_param(key, value):
    return struct.pack(">HH", key, len(value)) + value


def svc_alpn(*labels):
    raw = b""
    for label in labels:
        piece = label.encode()
        raw += bytes([len(piece)]) + piece
    return svc_param(1, raw)


def svc_ipv4hint(*addrs):
    raw = b"".join(socket.inet_aton(addr) for addr in addrs)
    return svc_param(4, raw)


def https_rdata(priority, target, params):
    # A root target is one zero byte. name(".") would emit two.
    tname = b"\x00" if target in (".", "") else name(target)
    return struct.pack(">H", priority) + tname + params


def dns_answers(tid, qname, qtype, answers):
    hdr = struct.pack(">HHHHHH", tid, 0x8180, 1, len(answers), 0, 0)
    question = name(qname) + struct.pack(">HH", qtype, 1)
    body = b""
    for owner, typ, ttl, rdata in answers:
        body += name(owner) + struct.pack(">HHIH", typ, 1, ttl, len(rdata)) + rdata
    return hdr + question + body


def eth_vlan(payload, vid=100):
    tci = vid & 0x0FFF
    return b"\x00" * 12 + struct.pack(">HHH", 0x8100, tci, 0x0800) + payload


def qa(src, dst, sport, tid, qname, rdata, qtype=1, ipttl=64):
    q = dns_query(tid, qname, qtype)
    a = dns_response(tid, qname, rdata, qtype)
    return [
        eth(ipv4(src, dst, 17, udp(sport, 53, q))),
        eth(ipv4(dst, src, 17, udp(53, sport, a), ttl=ipttl)),
    ]


def find_binary():
    env = os.environ.get("PASSIVEDNS")
    if env:
        if os.path.isfile(env) and os.access(env, os.X_OK):
            return env
        sys.exit("PASSIVEDNS is not an executable file: %s" % env)
    for candidate in (os.path.join(ROOT, "src", "passivedns"),
                      "/tmp/pdns-build/passivedns"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    sys.exit("no passivedns binary. Run make, or set PASSIVEDNS.")


def run_case(binary, packets, args, linktype=1, times=None):
    tmp = tempfile.mkdtemp(prefix="pdns-regress-")
    try:
        pcap = os.path.join(tmp, "case.pcap")
        log = os.path.join(tmp, "case.log")
        write_pcap(pcap, packets, linktype, times)
        cmd = [binary, "-r", pcap, "-l", log, "-L", log] + args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return 124, "", "timeout", False, ""
        text = ""
        mode_ok = False
        if os.path.exists(log):
            mode_ok = (os.stat(log).st_mode & 0o777) == 0o640
            with open(log, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        return proc.returncode, text, proc.stderr, mode_ok, proc.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def expect_logged(binary, label, packets, needle, args=None, linktype=1, absent=(), times=None):
    code, text, err, mode_ok, _out = run_case(binary, packets, args or [], linktype, times)
    lines = [ln for ln in text.splitlines() if needle in ln]
    if code != 0 or not mode_ok or len(lines) != 1:
        return False, "%s: exit %s mode %s lines %d\n%s\n%s" % (
            label, code, mode_ok, len(lines), text, err)
    for item in absent:
        if item in lines[0]:
            return False, "%s: unexpected %r in %s" % (label, item, lines[0])
    return True, lines[0]


def expect_many(binary, label, packets, needles, args=None, linktype=1):
    code, text, err, mode_ok, _out = run_case(binary, packets, args or [], linktype)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    found = [n for n in needles if any(n in ln for ln in lines)]
    if code != 0 or not mode_ok or len(lines) != len(needles) or len(found) != len(needles):
        return False, "%s: exit %s mode %s lines %d found %s\n%s\n%s" % (
            label, code, mode_ok, len(lines), found, text, err)
    return True, "\n".join(lines)


def expect_quiet(binary, label, packets, args=None, linktype=1):
    code, text, err, mode_ok, _out = run_case(binary, packets, args or [], linktype)
    if code != 0 or not mode_ok or text.strip():
        return False, "%s: exit %s mode %s\n%s\n%s" % (label, code, mode_ok, text, err)
    return True, "quiet"


def open_count(stdout):
    match = re.search(r"Connections open at shutdown\s+:\s*(\d+)", stdout)
    if not match:
        return None
    return int(match.group(1))


def expect_open(binary, label, packets, count, needle=None, args=None):
    code, text, err, mode_ok, out = run_case(binary, packets, args or [])
    got = open_count(out)
    logged = needle is None or needle in text
    quiet = needle is not None or not text.strip()
    if code != 0 or not mode_ok or got != count or not logged or not quiet:
        return False, "%s: exit %s mode %s open %s\n%s\n%s\n%s" % (
            label, code, mode_ok, got, text, out, err)
    return True, "open %s" % got


def cases():
    q = dns_query(0x1234, "a.example.com")
    a = dns_response(0x1234, "a.example.com", socket.inet_aton("9.9.9.9"))
    yield ("udp-a", [
        eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 53, q))),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, udp(53, 40000, a))),
    ], "10.0.0.1||10.0.0.2||IN||a.example.com.||A||9.9.9.9||300||1", None)

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

    yield ("aaaa", qa("10.5.0.1", "10.5.0.2", 44000, 0x6111, "aaaa.example.com",
                      socket.inet_pton(socket.AF_INET6, "2001:db8::9"), 28),
           "aaaa.example.com.||AAAA||2001:db8::9", None)

    yield ("cname", qa("10.5.0.1", "10.5.0.2", 44001, 0x6222, "cname.example.com",
                       name("target.example.com"), 5),
           "cname.example.com.||CNAME||target.example.com.", None)

    cname_a = dns_answers(0x6333, "www.example.com", 1, [
        ("www.example.com", 5, 300, name("target.example.com")),
        ("target.example.com", 1, 300, socket.inet_aton("9.9.9.9")),
    ])
    qchain = dns_query(0x6333, "www.example.com")
    yield ("cname-a", [
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44002, 53, qchain))),
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44002, cname_a))),
    ], ("www.example.com.||CNAME||target.example.com.",
        "target.example.com.||A||9.9.9.9"), None)

    yield ("ptr", qa("10.5.0.1", "10.5.0.2", 44003, 0x6444,
                     "4.3.2.1.in-addr.arpa", name("host.example.com"), 12),
           "4.3.2.1.in-addr.arpa.||PTR||host.example.com.", None)

    naptr = (struct.pack(">HH", 100, 10) + charstr("u") + charstr("sip+E2U")
             + charstr("!^.*$!sip:ed@example.com!") + name("."))
    yield ("naptr", qa("10.5.0.1", "10.5.0.2", 44004, 0x6555, "naptr.example.com",
                       naptr, 35),
           "sip:ed@example.com", None)

    srv = struct.pack(">HHH", 10, 20, 5060) + name("sip.example.com")
    yield ("srv", qa("10.5.0.1", "10.5.0.2", 44005, 0x6666, "srv.example.com",
                     srv, 33),
           "srv.example.com.||SRV||sip.example.com.", None)

    mx = struct.pack(">H", 10) + name("mail.example.com")
    yield ("mx", qa("10.5.0.1", "10.5.0.2", 44006, 0x6777, "mx.example.com", mx, 15),
           "mail.example.com", ["-X", "M"])
    yield ("mx-off", qa("10.5.0.1", "10.5.0.2", 44007, 0x6778, "mxoff.example.com",
                        mx, 15), None, None)

    yield ("txt-off", qa("10.5.0.1", "10.5.0.2", 44008, 0x6888, "txtoff.example.com",
                         txt_rdata("hello"), 16), None, None)

    qnx = dns_query(0x6999, "nx.example.com")
    nx = dns_nxdomain(0x6999, "nx.example.com")
    nxpkts = [
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44009, 53, qnx))),
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44009, nx))),
    ]
    yield ("nxdomain", nxpkts, "nx.example.com.||A||NXDOMAIN", ["-X", "x"])
    yield ("nxdomain-off", nxpkts, None, None)

    qonly = dns_query(0x6aaa, "qonly.example.com")
    yield ("query-only", [
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44010, 53, qonly))),
    ], None, None)

    aonly = dns_response(0x6bbb, "aonly.example.com", socket.inet_aton("9.9.9.9"))
    yield ("answer-only", [
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44011, aonly))),
    ], None, None)

    qbad = dns_query(0x6ccc, "tid.example.com")
    abad = dns_response(0x6ccd, "tid.example.com", socket.inet_aton("9.9.9.9"))
    yield ("tid-mismatch", [
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44012, 53, qbad))),
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44012, abad))),
    ], None, None)

    qzero = dns_query(0, "zero.example.com")
    azero = dns_response(0, "zero.example.com", socket.inet_aton("9.9.9.9"))
    yield ("tid-zero", [
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44013, 53, qzero))),
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44013, azero))),
    ], None, None)

    qdup = dns_query(0x6ddd, "dup.example.com")
    adup = dns_response(0x6ddd, "dup.example.com", socket.inet_aton("9.9.9.9"))
    # Same timestamp on every packet. A newer timestamp is flushed again at shutdown.
    yield ("duplicate", [
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44014, 53, qdup))),
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44014, adup))),
        eth(ipv4("10.5.0.1", "10.5.0.2", 17, udp(44014, 53, qdup))),
        eth(ipv4("10.5.0.2", "10.5.0.1", 17, udp(53, 44014, adup))),
    ], "dup.example.com.||A||9.9.9.9", None, 1, (), ((1700000000, 0),) * 4)

    vlan_q = dns_query(0x7001, "vlan.example.com")
    vlan_a = dns_response(0x7001, "vlan.example.com", socket.inet_aton("9.9.9.9"))
    vlan_pkts = [
        eth_vlan(ipv4("10.6.0.1", "10.6.0.2", 17, udp(45000, 53, vlan_q))),
        eth_vlan(ipv4("10.6.0.2", "10.6.0.1", 17, udp(53, 45000, vlan_a))),
    ]
    # The default filter does not look inside a VLAN tag.
    yield ("vlan-bpf", vlan_pkts, None, None)
    yield ("vlan", vlan_pkts, "vlan.example.com.||A||9.9.9.9",
           ["-b", "vlan and port 53"])

    # Second fragment arrives before the first.
    yield ("ipv4-ooo", [
        eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 53, q), ident=1)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag2, ident=11, off=64 // 8)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, frag1, ident=11, off=0x2000)),
    ], "a.example.com.||A||9.9.9.9", None)

    short_frag = udp_dg[:20]
    yield ("ipv4-frag-unaligned", [
        eth(ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 53, q), ident=1)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, short_frag, ident=12, off=0x2000)),
        eth(ipv4("10.0.0.2", "10.0.0.1", 17, udp_dg[20:], ident=12, off=20 // 8)),
    ], None, None)

    yield ("port-80", [
        eth(ipv4("10.7.0.1", "10.7.0.2", 17, udp(40000, 80, q))),
        eth(ipv4("10.7.0.2", "10.7.0.1", 17, udp(80, 40000, a))),
    ], None, None)

    yield ("fields-qt", qa("10.8.0.1", "10.8.0.2", 46001, 0x7222, "fields.example.com",
                           socket.inet_aton("9.9.9.9")),
           "fields.example.com.||A", ["-f", "QT"], 1, ("10.8.0.1", "9.9.9.9"))

    yield ("fields-fallback", qa("10.8.0.1", "10.8.0.2", 46002, 0x7333,
                                 "fallback.example.com", socket.inet_aton("9.9.9.9")),
           "fallback.example.com.||A||9.9.9.9||300||1", ["-f", "Z"])

    yield ("flags-fallback", qa("10.8.0.1", "10.8.0.2", 46003, 0x7444,
                                "flagfall.example.com", socket.inet_aton("9.9.9.9")),
           "flagfall.example.com.||A||9.9.9.9", ["-X", "Z"])

    yield ("delim", qa("10.8.0.1", "10.8.0.2", 46004, 0x7555, "delim.example.com",
                       socket.inet_aton("9.9.9.9")),
           "delim.example.com.|A|9.9.9.9", ["-d", "|"])

    quoted = txt_rdata("o'brien\\path")
    yield ("txt-quote", qa("10.8.0.1", "10.8.0.2", 46005, 0x7666, "quote.example.com",
                           quoted, 16),
           "o'brien", ["-X", "T"])

    comp = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("9.9.9.9")
    qcomp = dns_query(0x7777, "comp.example.com")
    acomp = struct.pack(">HHHHHH", 0x7777, 0x8180, 1, 1, 0, 0) + name("comp.example.com") + struct.pack(">HH", 1, 1) + comp
    yield ("compressed", [
        eth(ipv4("10.9.0.1", "10.9.0.2", 17, udp(47000, 53, qcomp))),
        eth(ipv4("10.9.0.2", "10.9.0.1", 17, udp(53, 47000, acomp))),
    ], "comp.example.com.||A||9.9.9.9", None)

    raw_q = ipv4("10.9.0.1", "10.9.0.2", 17, udp(47001, 53, dns_query(0x7888, "raw.example.com")))
    raw_a = ipv4("10.9.0.2", "10.9.0.1", 17, udp(53, 47001,
                 dns_response(0x7888, "raw.example.com", socket.inet_aton("9.9.9.9"))))
    yield ("dlt-raw", [raw_q, raw_a], "raw.example.com.||A||9.9.9.9", None, 101)

    nq = ipv4("10.9.0.1", "10.9.0.2", 17, udp(47002, 53, dns_query(0x7999, "null.example.com")))
    na = ipv4("10.9.0.2", "10.9.0.1", 17, udp(53, 47002,
              dns_response(0x7999, "null.example.com", socket.inet_aton("9.9.9.9"))))
    yield ("dlt-null", [struct.pack("<I", socket.AF_INET) + nq,
                        struct.pack("<I", socket.AF_INET) + na],
           "null.example.com.||A||9.9.9.9", None, 0)

    sll = struct.pack(">HHH", 0, 1, 6) + b"\x00" * 8 + struct.pack(">H", 0x0800)
    yield ("dlt-sll", [sll + nq, sll + na], "null.example.com.||A||9.9.9.9", None, 113)

    rh = bytes([17, 0]) + b"\x00" * 6
    qdst = dns_query(0x7aaa, "dest.example.com")
    adst = dns_response(0x7aaa, "dest.example.com", socket.inet_aton("9.9.9.9"))
    yield ("ipv6-dest", [
        eth(ipv6(src6, dst6, 60, rh + udp(48000, 53, qdst)), 0x86DD),
        eth(ipv6(dst6, src6, 60, rh + udp(53, 48000, adst)), 0x86DD),
    ], "dest.example.com.||A||9.9.9.9", None)

    qrt = dns_query(0x7bbb, "route.example.com")
    art = dns_response(0x7bbb, "route.example.com", socket.inet_aton("9.9.9.9"))
    yield ("ipv6-route", [
        eth(ipv6(src6, dst6, 43, rh + udp(48001, 53, qrt)), 0x86DD),
        eth(ipv6(dst6, src6, 43, rh + udp(53, 48001, art)), 0x86DD),
    ], "route.example.com.||A||9.9.9.9", None)

    qat = dns_query(0x7abd, "atomic.example.com")
    aat = dns_response(0x7abd, "atomic.example.com", socket.inet_aton("9.9.9.9"))
    atomic = struct.pack(">BBHI", 17, 0, 0, 9) + udp(53, 48002, aat)
    yield ("ipv6-atomic", [
        eth(ipv6(src6, dst6, 17, udp(48002, 53, qat)), 0x86DD),
        eth(ipv6(dst6, src6, 44, atomic), 0x86DD),
    ], "atomic.example.com.||A||9.9.9.9", None)

    qre = dns_query(0x7ccc, "re.example.com")
    are = dns_response(0x7ccc, "re.example.com", socket.inet_aton("5.6.7.8"))
    qmsg2 = struct.pack(">H", len(qre)) + qre
    amsg2 = struct.pack(">H", len(are)) + are
    yield ("tcp-retransmit", [
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41002, 53, 1000, qmsg2[:10]))),
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41002, 53, 1000, qmsg2[:10]))),
        eth(ipv4("10.1.0.1", "10.1.0.2", 6, tcp(41002, 53, 1010, qmsg2[10:]))),
        eth(ipv4("10.1.0.2", "10.1.0.1", 6, tcp(53, 41002, 5000, amsg2))),
    ], "re.example.com.||A||5.6.7.8", None)

    yield ("short-eth", [b"\x00" * 10], None, None)

    tiny = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 10, 1, 0, 64, 17, 0,
                       socket.inet_aton("10.4.0.1"), socket.inet_aton("10.4.0.2"))
    yield ("ip-total-short", [eth(tiny)], None, None)

    yield ("empty-pcap", [], None, None)

    hr = https_rdata(1, ".", svc_alpn("h2", "h3") + svc_ipv4hint("104.18.39.85"))
    https_pkts = qa("10.10.0.1", "10.10.0.2", 50000, 0x7C01, "https.example.com", hr, 65)
    https_line = "https.example.com.||HTTPS||1 . alpn=h2,h3 ipv4hint=104.18.39.85"
    yield ("https", https_pkts, https_line, None)
    yield ("https-flag", https_pkts, https_line, ["-X", "h"])
    yield ("https-off", https_pkts, None, ["-X", "4"])

    sr = https_rdata(1, "target.example.com", svc_alpn("h2"))
    svcb_pkts = qa("10.10.0.1", "10.10.0.2", 50001, 0x7C02, "svcb.example.com", sr, 64)
    yield ("svcb", svcb_pkts, "svcb.example.com.||SVCB||1 target.example.com. alpn=h2", None)
    yield ("svcb-off", svcb_pkts, None, ["-X", "h"])

    qnd = dns_query(0x7D01, "nodata.example.com")
    nd = dns_nodata(0x7D01, "nodata.example.com")
    ndpkts = [
        eth(ipv4("10.10.1.1", "10.10.1.2", 17, udp(50010, 53, qnd))),
        eth(ipv4("10.10.1.2", "10.10.1.1", 17, udp(53, 50010, nd), ttl=53)),
    ]
    yield ("nodata", ndpkts, "nodata.example.com.||A||NOERROR", ["-X", "0"])
    yield ("nodata-off", ndpkts, None, None)
    yield ("nodata-ttl", ndpkts,
           "10.10.1.2||53||IN||nodata.example.com.||A||NOERROR",
           ["-X", "0", "-f", "SMcsCQTAtni"])

    ttl_pkts = qa("10.10.2.1", "10.10.2.2", 50020, 0x7E01, "ipttl.example.com",
                  socket.inet_aton("9.9.9.9"), ipttl=53)
    yield ("server-ttl", ttl_pkts, "10.10.2.2||53||IN||ipttl.example.com.||A||",
           ["-f", "SMcsCQTAtni"])
    yield ("server-ttl-off", ttl_pkts, "ipttl.example.com.||A||9.9.9.9", None, 1, ("||53||",))

    same = (1700000000, 0)
    dup_ttl = (
        qa("10.10.2.1", "10.10.2.2", 50021, 0x7E02, "ipttldup.example.com",
           socket.inet_aton("9.9.9.9"), ipttl=53)
        + qa("10.10.2.1", "10.10.2.2", 50021, 0x7E02, "ipttldup.example.com",
             socket.inet_aton("9.9.9.9"), ipttl=19)
    )
    yield ("server-ttl-dup", dup_ttl, "10.10.2.2||53||IN||ipttldup.example.com.||A||",
           ["-f", "SMcsCQTAtni"], 1, ("||19||",), [same, same, same, same])

    hop_q = dns_query(0x7E03, "hop.example.com")
    hop_a = dns_response(0x7E03, "hop.example.com", socket.inet_aton("9.9.9.9"))
    hop_pkts = [
        eth(ipv6("2001:db8:1::1", "2001:db8:1::2", 17, udp(50030, 53, hop_q)), 0x86DD),
        eth(ipv6("2001:db8:1::2", "2001:db8:1::1", 17, udp(53, 50030, hop_a), hop=41), 0x86DD),
    ]
    yield ("server-ttl6", hop_pkts, "2001:db8:1::2||41||IN||hop.example.com.||A||",
           ["-f", "SMcsCQTAtni"])

    free_q = dns_query(0x1401, "free.example.com")
    free_a = dns_response(0x1401, "free.example.com", socket.inet_aton("9.9.9.9"))
    yield ("udp-free", [
        eth(ipv4("10.14.0.1", "10.14.0.2", 17, udp(41400, 53, free_q))),
        eth(ipv4("10.14.0.2", "10.14.0.1", 17, udp(53, 41400, free_a))),
    ], ("open", 0, "free.example.com.||A||9.9.9.9"), None)

    yield ("udp-unanswered", [
        eth(ipv4("10.14.0.1", "10.14.0.2", 17, udp(41401, 53,
                 dns_query(0x1402, "wait.example.com")))),
    ], ("open", 1, None), None)

    again_q1 = dns_query(0x1403, "again.example.com")
    again_a1 = dns_response(0x1403, "again.example.com", socket.inet_aton("1.2.3.4"))
    again_q2 = dns_query(0x1404, "again.example.com")
    again_a2 = dns_response(0x1404, "again.example.com", socket.inet_aton("5.6.7.8"))
    yield ("udp-reuse", [
        eth(ipv4("10.14.0.1", "10.14.0.2", 17, udp(41402, 53, again_q1))),
        eth(ipv4("10.14.0.2", "10.14.0.1", 17, udp(53, 41402, again_a1))),
        eth(ipv4("10.14.0.1", "10.14.0.2", 17, udp(41402, 53, again_q2))),
        eth(ipv4("10.14.0.2", "10.14.0.1", 17, udp(53, 41402, again_a2))),
    ], ("open", 0, "5.6.7.8"), None)

    tq = dns_query(0x1405, "tcpstay.example.com")
    ta = dns_response(0x1405, "tcpstay.example.com", socket.inet_aton("9.9.9.9"))
    tqmsg = struct.pack(">H", len(tq)) + tq
    tamsg = struct.pack(">H", len(ta)) + ta
    yield ("tcp-stays", [
        eth(ipv4("10.14.1.1", "10.14.1.2", 6, tcp(41410, 53, 1000, tqmsg))),
        eth(ipv4("10.14.1.2", "10.14.1.1", 6, tcp(53, 41410, 5000, tamsg))),
    ], ("open", 1, "tcpstay.example.com.||A||9.9.9.9"), None)

    fq = dns_query(0x1406, "tcpfin.example.com")
    fa = dns_response(0x1406, "tcpfin.example.com", socket.inet_aton("9.9.9.9"))
    fqmsg = struct.pack(">H", len(fq)) + fq
    famsg = struct.pack(">H", len(fa)) + fa
    yield ("tcp-fin", [
        eth(ipv4("10.14.1.1", "10.14.1.2", 6, tcp(41411, 53, 1000, fqmsg))),
        eth(ipv4("10.14.1.2", "10.14.1.1", 6, tcp(53, 41411, 5000, famsg))),
        eth(ipv4("10.14.1.1", "10.14.1.2", 6, tcp(41411, 53, 1000 + len(fqmsg), b"", 0x11))),
        eth(ipv4("10.14.1.2", "10.14.1.1", 6, tcp(53, 41411, 5000 + len(famsg), b"", 0x11))),
    ], ("open", 0, "tcpfin.example.com.||A||9.9.9.9"), None)

    rq = dns_query(0x1407, "tcprst.example.com")
    ra = dns_response(0x1407, "tcprst.example.com", socket.inet_aton("9.9.9.9"))
    rqmsg = struct.pack(">H", len(rq)) + rq
    ramsg = struct.pack(">H", len(ra)) + ra
    yield ("tcp-rst", [
        eth(ipv4("10.14.1.1", "10.14.1.2", 6, tcp(41412, 53, 2000, rqmsg))),
        eth(ipv4("10.14.1.2", "10.14.1.1", 6, tcp(53, 41412, 6000, ramsg))),
        eth(ipv4("10.14.1.2", "10.14.1.1", 6, tcp(53, 41412, 6000 + len(ramsg), b"", 0x04))),
    ], ("open", 0, "tcprst.example.com.||A||9.9.9.9"), None)


def main():
    binary = find_binary()
    failed = 0
    for case in cases():
        label, packets, needle, args = case[:4]
        linktype = case[4] if len(case) > 4 else 1
        absent = case[5] if len(case) > 5 else ()
        times = case[6] if len(case) > 6 else None
        if needle is None:
            ok, detail = expect_quiet(binary, label, packets, args, linktype)
        elif isinstance(needle, tuple) and needle and needle[0] == "open":
            ok, detail = expect_open(binary, label, packets, needle[1], needle[2], args)
        elif isinstance(needle, tuple):
            ok, detail = expect_many(binary, label, packets, needle, args, linktype)
        else:
            ok, detail = expect_logged(
                binary, label, packets, needle, args, linktype, absent, times)
        print("%s %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            failed += 1
            print(detail)
    if failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
