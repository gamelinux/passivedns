#!/usr/bin/env python3
"""Command-line checks: version, help, and fail-closed -u/-g/-T on -r."""

import os
import shutil
import subprocess
import sys
import tempfile

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


def main():
    code, out, err = run(["-V"])
    report(code == 0 and "PassiveDNS 1.3.0" in out and "Edward Bjarte Fjellskål" in out,
           "version", out + err)

    code, out, err = run(["-h"])
    report(code == 0 and "ip6[6] = 44" in out and "-u <uid>" in out,
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
