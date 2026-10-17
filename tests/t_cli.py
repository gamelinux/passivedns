#!/usr/bin/env python3
"""Command-line checks: version, help, and fail-closed -u/-g/-T on -r."""

import errno
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

import regress

failed = 0


def report(ok, label, detail=""):
    global failed
    print("%s %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        failed += 1
        if detail:
            print(detail)


def run(args, pcap_packets=None):
    tmp = tempfile.mkdtemp(prefix="pdns-cli-")
    try:
        log = os.path.join(tmp, "case.log")
        cmd = [regress.find_binary()]
        if pcap_packets is not None:
            pcap = os.path.join(tmp, "case.pcap")
            regress.write_pcap(pcap, pcap_packets)
            cmd += ["-r", pcap, "-l", log, "-L", log]
        cmd += args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def pcap_bytes(packets):
    raw = bytearray()
    raw += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, pkt in enumerate(packets):
        raw += struct.pack("<IIII", 1700000000, i, len(pkt), len(pkt))
        raw += pkt
    return bytes(raw)


def split_packets(data, count):
    off = 24
    for _ in range(count):
        incl = struct.unpack_from("<I", data, off + 8)[0]
        off += 16 + incl
    return data[:off], data[off:]


def reopen_keeps_log():
    """SIGHUP that cannot create the new log must keep writing to the old one."""
    tmp = tempfile.mkdtemp(prefix="pdns-hup-")
    proc = None
    try:
        log = os.path.join(tmp, "pdns.log")
        rotated = log + ".1"
        fifo = os.path.join(tmp, "in.pcap")
        os.mkfifo(fifo)
        one = regress.qa("10.0.0.1", "8.8.8.8", 40000, 7,
                         "one.example.com", socket.inet_aton("1.1.1.1"))
        two = regress.qa("10.0.0.1", "8.8.8.8", 40001, 8,
                         "two.example.com", socket.inet_aton("2.2.2.2"))
        first, second = split_packets(pcap_bytes(one + two), 2)
        proc = subprocess.Popen(
            [regress.find_binary(), "-q", "-r", fifo, "-l", log, "-L", log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        writer_fd = None
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                writer_fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as exc:
                if exc.errno != errno.ENXIO:
                    raise
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
        if writer_fd is None:
            print("log-reopen: capture did not open the fifo")
            return False
        writer = os.fdopen(writer_fd, "wb", buffering=0)
        writer.write(first)
        writer.flush()
        seen = False
        deadline = time.time() + 5
        while time.time() < deadline:
            if os.path.isfile(log):
                with open(log, encoding="utf-8", errors="replace") as fh:
                    if "one.example.com" in fh.read():
                        seen = True
                        break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if not seen:
            print("log-reopen: first line did not appear")
            return False
        os.rename(log, rotated)
        os.mkdir(log)
        proc.send_signal(signal.SIGHUP)
        time.sleep(0.2)
        writer.write(second)
        writer.flush()
        writer.close()
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            print("log-reopen: timed out\n%s\n%s" % (out, err))
            return False
        body = open(rotated, encoding="utf-8", errors="replace").read()
        ok = (proc.returncode == 0 and "one.example.com" in body
              and "two.example.com" in body and "reopening" in err)
        if not ok:
            print("log-reopen: rc %s\n%s\n%s\nLOG:\n%s" % (
                proc.returncode, out, err, body))
        return ok
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        shutil.rmtree(tmp, ignore_errors=True)


def workers_daemon_missing():
    """A daemon fanout that cannot open the device must exit and drop its pid file."""
    tmp = tempfile.mkdtemp(prefix="pdns-wd-")
    try:
        log = os.path.join(tmp, "case.log")
        pidfile = os.path.join(tmp, "pdns.pid")
        proc = subprocess.run(
            [regress.find_binary(), "-q", "-D", "-W", "2", "-i", "nosuch-pdns0",
             "--fanout-group", "9", "-l", log, "-L", log, "-p", pidfile],
            capture_output=True, text=True, timeout=15)
        extra = ""
        if os.path.exists(pidfile):
            extra = "\npidfile still exists\n"
        ok = (proc.returncode != 0 and "pcap_open_live" in (proc.stdout + proc.stderr)
              and not os.path.exists(pidfile))
        return (0 if ok else 1), proc.stdout, proc.stderr + extra
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def workers_daemon_lives():
    """-D -W without -u must still be running after the parent exits.

    Needs CAP_NET_RAW. CI's sudo is passwordless. A workstation sudo
    prompt skips the check instead of hanging the suite.
    """
    sudo = []
    if os.geteuid() != 0:
        probe = subprocess.run(["sudo", "-n", "true"], capture_output=True)
        if probe.returncode != 0:
            return 2, "", ""
        sudo = ["sudo", "-n"]

    def alive(check):
        try:
            os.kill(check, 0)
        except OSError as exc:
            return exc.errno == errno.EPERM
        return True

    def signal_pid(check, sig):
        if sudo:
            subprocess.run(sudo + ["kill", "-%d" % sig, str(check)],
                           check=False)
        else:
            os.kill(check, sig)

    tmp = tempfile.mkdtemp(prefix="pdns-live-")
    pid = None
    try:
        log = os.path.join(tmp, "case.log")
        pidfile = os.path.join(tmp, "pdns.pid")
        proc = subprocess.Popen(
            sudo + [regress.find_binary(), "-q", "-D", "-W", "2", "-i", "lo",
                    "--fanout-group", "41991", "-l", log, "-L", log,
                    "-p", pidfile],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            err = proc.communicate(timeout=15)[1]
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return 1, "", "daemon parent did not exit"
        if proc.returncode != 0 or not os.path.exists(pidfile):
            return 1, "", "startup failed rc %s\n%s" % (proc.returncode, err)
        pid = int(open(pidfile, encoding="utf-8").read().strip())
        time.sleep(2)
        if not alive(pid):
            return 1, "", "daemon pid %s died after the parent exited" % pid
        signal_pid(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.1)
            if not alive(pid):
                pid = None
                break
        if pid is not None:
            signal_pid(pid, signal.SIGKILL)
            return 1, "", "daemon did not exit on SIGTERM"
        return 0, "", ""
    finally:
        if pid is not None:
            try:
                signal_pid(pid, signal.SIGKILL)
            except OSError:
                pass
        if sudo:
            subprocess.run(sudo + ["rm", "-rf", tmp], check=False)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


def run_live(args):
    """Live-option checks. -l stays in a temp dir and no pcap is read."""
    tmp = tempfile.mkdtemp(prefix="pdns-live-")
    try:
        log = os.path.join(tmp, "case.log")
        cmd = [regress.find_binary(), "-q", "-l", log, "-L", log] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    code, out, err = run(["-V"])
    report(code == 0 and "PassiveDNS 2.0.0" in out and "Edward Bjarte Fjellskål" in out,
           "version", out + err)

    code, out, err = run(["-h"])
    report(code == 0 and "ip6[6] = 44" in out and "-u <uid>" in out
           and "h:HTTPS" in out and "V:SVCB" in out and "0:NOERR" in out
           and "i: Server IP TTL" in out and "46CDNPRShV" in out
           and "-s <bytes>" in out and "4096" in out and "262144" in out
           and "ethtool -K <iface> gro off" in out
           and "--stats-file <file>" in out
           and "-W <n>" in out and "--fanout-group <id>" in out
           and "AF_PACKET" in out
           and "--format <json|text>" in out,
           "help", out + err)

    missing = tempfile.mkdtemp(prefix="pdns-missing-")
    try:
        log = os.path.join(missing, "case.log")
        code, out, err = run(["-r", os.path.join(missing, "nope.pcap"), "-l", log, "-L", log])
        report(code != 0 and "Unable to open" in (out + err), "missing-pcap", out + err)
    finally:
        shutil.rmtree(missing, ignore_errors=True)

    empty = []
    code, out, err = run(["-u", "nosuch-pdns-user"], empty)
    report(code != 0 and "not found" in (out + err), "user-missing", out + err)

    code, out, err = run(["-g", "nosuch-pdns-group"], empty)
    report(code != 0 and "does not exist" in (out + err), "group-missing", out + err)

    code, out, err = run(["-u", "1foo"], empty)
    report(code != 0 and "invalid user id" in (out + err), "user-prefix", out + err)

    code, out, err = run(["-g", "2bar"], empty)
    report(code != 0 and "invalid group id" in (out + err), "group-prefix", out + err)

    code, out, err = run(["-T", "/no/such/pdns-chroot"], empty)
    report(code != 0 and "failed to chroot" in (out + err), "chroot-missing", out + err)

    code, out, err = run([], empty)
    report(code == 0 and "Snapshot length: 65535" in out
           and "Record letters: 46CDNPRShV" in out
           and "-s " not in out,
           "startup-letters", out + err)

    code, out, err = run(["-q"], empty)
    report(code == 0 and "Snapshot length:" not in out
           and "Record letters:" not in out
           and "PassiveDNS" not in out,
           "quiet-startup", out + err)

    code, out, err = run(["-s", "4096"], empty)
    report(code == 0 and "-s 4096 does not apply when reading a pcap" in out
           and "Snapshot length: 65535" in out,
           "snaplen-ignored-on-read", out + err)

    code, out, err = run(["-s", "0"], empty)
    report(code == 0 and "-s 262144 does not apply when reading a pcap" in out,
           "snaplen-zero", out + err)

    code, out, err = run(["-s", "/var/log/passivedns.stats"], empty)
    report(code != 0 and "snapshot length" in (out + err)
           and "--stats-file" in (out + err),
           "snaplen-was-stats-file", out + err)

    code, out, err = run(["-s", "300000"], empty)
    report(code != 0 and "snapshot length" in (out + err),
           "snaplen-too-big", out + err)

    code, out, err = run(["--stats-file", "/tmp/pdns-stats"], empty)
    report(code == 0 and "Record letters: 46CDNPRShV" in out,
           "stats-file-long", out + err)

    code, out, err = run(["-X", "4nOMT"], empty)
    report(code == 0 and "Record letters: 4OTMn" in out,
           "record-letters-replace", out + err)

    code, out, err = run(["-X", "F"], empty)
    report(code == 0 and "Record letters: F" in out and "FT" not in out,
           "spf-does-not-enable-txt", out + err)

    code, out, err = run(["-S", "0"], empty)
    report(code != 0 and "memory limit" in (out + err), "mem-zero", out + err)
    code, out, err = run(["-S", "-1"], empty)
    report(code != 0 and "memory limit" in (out + err), "mem-negative", out + err)
    code, out, err = run(["-D", "-u", "nosuch-pdns-user", "-i", "lo"])
    report(code != 0 and "not found" in (out + err), "daemon-user-missing", out + err)
    code, out, err = run(["-S", "nope"], empty)
    report(code != 0 and "memory limit" in (out + err), "mem-text", out + err)
    code, out, err = run(["-C", "-5"], empty)
    report(code != 0 and "cache time" in (out + err), "cache-negative", out + err)
    code, out, err = run(["-P", "12x"], empty)
    report(code != 0 and "print interval" in (out + err), "print-text", out + err)
    code, out, err = run(["-S", "1", "-f", "h"], empty)
    report(code == 0 and "Record letters:" in out, "mem-and-hostname", out + err)

    report(reopen_keeps_log(), "log-reopen-keeps-fd")

    code, out, err = run(["-W", "1"], empty)
    report(code == 0 and "Snapshot length: 65535" in out, "workers-one", out + err)

    code, out, err = run(["--format", "nope"], empty)
    report(code != 0 and "--format needs json or text" in (out + err),
           "format-bad", out + err)

    code, out, err = run(["--format", "text"], empty)
    report(code == 0 and "Log format: text" in out, "format-text", out + err)

    code, out, err = run(["-W", "0"], empty)
    report(code != 0 and "worker count" in (out + err), "workers-zero", out + err)

    code, out, err = run(["-W", "65"], empty)
    report(code != 0 and "worker count" in (out + err), "workers-too-many", out + err)

    code, out, err = run(["-W", "2"], empty)
    report(code != 0 and "-W cannot be used with -r" in (out + err),
           "workers-with-read", out + err)

    code, out, err = run(["--fanout-group", "4"], empty)
    report(code != 0 and "--fanout-group requires -W" in (out + err),
           "fanout-group-needs-workers", out + err)

    code, out, err = run_live(["-W", "2", "--fanout-group", "0"])
    report(code != 0 and "1 to 65535" in (out + err), "fanout-group-zero", out + err)

    code, out, err = run_live(["-W", "2", "-i", "any"])
    report(code != 0 and "any" in (out + err), "workers-any", out + err)

    code, out, err = run_live(["-W", "2", "-i", "nosuch-pdns0"])
    report(code != 0 and "interface index" in (out + err),
           "workers-missing-iface", out + err)

    code, out, err = run_live(["-W", "2", "-i", "nosuch-pdns0", "--fanout-group", "9"])
    report(code != 0 and "pcap_open_live" in (out + err),
           "workers-missing-device", out + err)

    code, out, err = workers_daemon_missing()
    report(code == 0, "workers-daemon-missing", out + err)

    code, out, err = workers_daemon_lives()
    if code == 2:
        print("SKIP workers-daemon-lives (not root)")
    else:
        report(code == 0, "workers-daemon-lives", out + err)

    if os.geteuid() != 0:
        code, out, err = run(["-T", "/tmp"], empty)
        report(code != 0 and "failed to chroot" in (out + err), "chroot-unpriv", out + err)
        code, out, err = run(["-u", "59999"], empty)
        report(code != 0 and "Unable to set user ID" in (out + err), "user-unpriv", out + err)
    else:
        print("SKIP chroot-unpriv user-unpriv (running as root)")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
