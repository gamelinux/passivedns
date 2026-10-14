#!/usr/bin/env python3
"""Perl tool checks. A stub DBI records SQL and bound values. No database."""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PDNS2DB = os.path.join(ROOT, "tools", "pdns2db.pl")
SEARCH = os.path.join(ROOT, "tools", "search-pdns.pl")
failed = 0

STUBS = {
    "DateTime.pm": "package DateTime;\nsub import {}\n1;\n",
    "DBI.pm": r'''package DBI;
sub import {}
sub connect {
    my ($class, $dsn, $user, $pass, $attr) = @_;
    _rec("CONNECT", $dsn, defined $user ? $user : "", defined $pass ? $pass : "");
    return bless { err => 0 }, "DBI::db";
}
sub errstr { "stub" }
sub _rec {
    my $path = $ENV{PDNS_TEST_CAPTURE} or return;
    open my $fh, ">>", $path or return;
    foreach my $part (@_) {
        my $copy = defined $part ? "$part" : "";
        $copy =~ s/\n/\\n/g;
        $copy =~ s/\r/\\r/g;
        print $fh $copy, "\n";
    }
    print $fh "END\n";
}
package DBI::db;
sub err { 0 }
sub do {
    my ($self, $sql) = @_;
    DBI::_rec("DO", $sql);
    return 1;
}
sub prepare {
    my ($self, $sql) = @_;
    return bless { sql => $sql }, "DBI::st";
}
sub disconnect {}
package DBI::st;
sub execute {
    my ($self, @bind) = @_;
    DBI::_rec("EXEC", $self->{sql}, @bind);
    return 1;
}
sub fetchrow_array { return () }
sub finish {}
1;
''',
    "Date/Simple.pm": '''package Date::Simple;
use Exporter "import";
our @EXPORT_OK = qw(date today);
sub date { return $_[0] }
sub today { return "2026-10-14" }
1;
''',
}


def report(ok, label, detail=""):
    global failed
    print("%s %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        failed += 1
        if detail:
            sys.stdout.write(detail if detail.endswith("\n") else detail + "\n")


def perl_env(lib, capture, extra=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("PDNS_"):
            del env[key]
    env["PERL5LIB"] = lib
    env["PDNS_TEST_CAPTURE"] = capture
    if extra:
        env.update(extra)
    return env


def run(cmd, env, timeout=20, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=timeout, cwd=cwd)


def blocks(text):
    out = []
    cur = []
    for line in text.splitlines():
        if line == "END":
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(line)
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="pdns-tools-")
    try:
        lib = os.path.join(tmp, "lib")
        os.makedirs(os.path.join(lib, "Date"))
        for name, body in STUBS.items():
            with open(os.path.join(lib, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        capture = os.path.join(tmp, "capture.txt")
        env = perl_env(lib, capture)

        proc = run(["perl", "-c", PDNS2DB], env)
        report(proc.returncode == 0 and "syntax OK" in (proc.stdout + proc.stderr),
               "pdns2db-syntax", proc.stdout + proc.stderr)
        proc = run(["perl", "-c", SEARCH], env)
        report(proc.returncode == 0 and "syntax OK" in (proc.stdout + proc.stderr),
               "search-syntax", proc.stdout + proc.stderr)

        logfile = os.path.join(tmp, "pdns.log")
        alert = os.path.join(tmp, "alert.log")
        black = os.path.join(tmp, "black.txt")
        white = os.path.join(tmp, "white.txt")
        skip = os.path.join(tmp, "skip.txt")
        lines = [
            "1700000000.000001||10.0.0.1||10.0.0.2||IN||bad.example.com.||A||1.2.3.4||300||1",
            "1700000000.000002||10.0.0.1||10.0.0.2||IN||good.example.com.||A||1.2.3.4||300||1",
            "1700000000.000003||10.0.0.1||10.0.0.2||IN||skip.example.com.||A||1.2.3.4||300||1",
            "1700000000.000004||10.0.0.1||10.0.0.2||IN||evil' OR '1.example.com.||A||1.2.3.4||300||1",
            "not-a-valid-line",
            "1700000000.000005||10.0.0.1||10.0.0.2||IN||badttl.example.com.||A||1.2.3.4||nope||1",
        ]
        with open(logfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        with open(black, "w", encoding="utf-8") as fh:
            fh.write("bad.example.com\ngood.example.com\n")
        with open(white, "w", encoding="utf-8") as fh:
            fh.write("good.example.com\n")
        with open(skip, "w", encoding="utf-8") as fh:
            fh.write("skip.example.com\n")

        proc = run(["perl", PDNS2DB, "--batch", "--file", logfile], env)
        report(proc.returncode != 0 and "PDNS_DB_PASSWORD" in (proc.stdout + proc.stderr),
               "pdns2db-password", proc.stdout + proc.stderr)

        badname = perl_env(lib, capture, {"PDNS_DB_NAME": "bad-name", "PDNS_DB_PASSWORD": "x"})
        proc = run(["perl", PDNS2DB, "--batch", "--file", logfile], badname)
        report(proc.returncode != 0 and "identifier" in (proc.stdout + proc.stderr),
               "pdns2db-db-name", proc.stdout + proc.stderr)

        badtable = perl_env(lib, capture, {"PDNS_DB_TABLE": "pdns;drop", "PDNS_DB_PASSWORD": "x"})
        proc = run(["perl", PDNS2DB, "--batch", "--file", logfile], badtable)
        report(proc.returncode != 0 and "identifier" in (proc.stdout + proc.stderr),
               "pdns2db-table", proc.stdout + proc.stderr)

        nodb = perl_env(lib, capture)
        proc = run(["perl", PDNS2DB, "--nodb", "--batch", "--file", logfile,
                    "--alertlog", alert], nodb)
        report(proc.returncode == 0, "pdns2db-nodb", proc.stdout + proc.stderr)

        pipe_name = "|not-a-command"
        open(os.path.join(tmp, pipe_name), "w").close()
        proc = run(["perl", PDNS2DB, "--nodb", "--batch", "--file", pipe_name], nodb, cwd=tmp)
        report(proc.returncode == 0 and "Processing of |not-a-command is done" in (proc.stdout + proc.stderr),
               "pdns2db-pipe-file", proc.stdout + proc.stderr)
        proc = run(["perl", PDNS2DB, "--nodb", "--batch", "--file", logfile,
                    "--whitelist", white], nodb)
        report(proc.returncode == 0 and "Whitelist without Blacklist" in (proc.stdout + proc.stderr),
               "pdns2db-whitelist-only", proc.stdout + proc.stderr)

        open(capture, "w").close()
        if os.path.exists(alert):
            os.remove(alert)
        loaded = perl_env(lib, capture, {"PDNS_DB_PASSWORD": "s3cret"})
        proc = run(["perl", PDNS2DB, "--batch", "--file", logfile, "--alertlog", alert,
                    "--blacklist", black, "--whitelist", white, "--skiplist", skip], loaded)
        cap = open(capture, encoding="utf-8").read() if os.path.exists(capture) else ""
        alert_text = open(alert, encoding="utf-8").read() if os.path.exists(alert) else ""
        execs = [b for b in blocks(cap) if b and b[0] == "EXEC"]
        sqls = ["\n".join(b[1:2]) for b in execs]
        binds = ["\n".join(b[2:]) for b in execs]
        joined_sql = "\n".join(sqls)
        joined_bind = "\n".join(binds)
        report(proc.returncode == 0
               and all("?" in sql and "evil" not in sql and "bad.example" not in sql for sql in sqls)
               and "INSERT INTO pdns" in joined_sql
               and "bad.example.com" in joined_bind
               and "good.example.com" in joined_bind
               and "evil' OR '1.example.com" in joined_bind
               and "skip.example.com" not in joined_bind
               and "badttl.example.com" not in joined_bind,
               "pdns2db-binds", proc.stdout + proc.stderr + "\n" + cap)
        report("bad.example.com" in alert_text and "good.example.com" not in alert_text,
               "pdns2db-alert", alert_text)

        proc = run(["perl", SEARCH, "-s", ""], env)
        report(proc.returncode == 0 and "need to search" in (proc.stdout + proc.stderr),
               "search-empty", proc.stdout + proc.stderr)

        proc = run(["perl", SEARCH, "-s", "example"], env)
        report(proc.returncode != 0 and "PDNS_DB_PASSWORD" in (proc.stdout + proc.stderr),
               "search-password", proc.stdout + proc.stderr)

        proc = run(["perl", SEARCH, "-s", "example"], badname)
        report(proc.returncode != 0 and "identifier" in (proc.stdout + proc.stderr),
               "search-db-name", proc.stdout + proc.stderr)

        badtable = perl_env(lib, capture, {"PDNS_DB_TABLE": "pdns;drop", "PDNS_DB_PASSWORD": "x"})
        proc = run(["perl", SEARCH, "-s", "example"], badtable)
        report(proc.returncode != 0 and "PDNS_DB_TABLE" in (proc.stdout + proc.stderr),
               "search-table", proc.stdout + proc.stderr)
        badport = perl_env(lib, capture, {"PDNS_DB_PORT": "nope", "PDNS_DB_PASSWORD": "x"})
        proc = run(["perl", SEARCH, "-s", "example"], badport)
        report(proc.returncode != 0 and "PDNS_DB_PORT" in (proc.stdout + proc.stderr),
               "search-port", proc.stdout + proc.stderr)
        badport = perl_env(lib, capture, {"PDNS_DB_PORT": "nope"})
        proc = run(["perl", PDNS2DB, "--nodb", "--batch", "--file", logfile], badport)
        report(proc.returncode != 0 and "PDNS_DB_PORT" in (proc.stdout + proc.stderr),
               "pdns2db-port", proc.stdout + proc.stderr)

        dated = perl_env(lib, capture, {"PDNS_DB_PASSWORD": "s3cret"})
        proc = run(["perl", SEARCH, "-s", "example", "--first-seen", "yesterday"], dated)
        report(proc.returncode != 0 and "first-seen" in (proc.stdout + proc.stderr),
               "search-date", proc.stdout + proc.stderr)
        proc = run(["perl", SEARCH, "-s", "example", "-t", "A'OR"], dated)
        report(proc.returncode != 0 and "alphanumeric" in (proc.stdout + proc.stderr),
               "search-type", proc.stdout + proc.stderr)
        proc = run(["perl", SEARCH, "-s", "example", "--limit", "abc"], dated)
        report(proc.returncode != 0 and "limit must be a number" in (proc.stdout + proc.stderr),
               "search-limit-text", proc.stdout + proc.stderr)

        proc = run(["perl", SEARCH, "-d", "2", "-s", "example", "--limit", "0"], dated)
        report(proc.returncode == 0 and "LIMIT 1" in proc.stdout and "LIMIT 0" not in proc.stdout,
               "search-limit-floor", proc.stdout + proc.stderr)
        proc = run(["perl", SEARCH, "-d", "2", "-s", "example", "--limit", "99999"], dated)
        report(proc.returncode == 0 and "LIMIT 10000" in proc.stdout,
               "search-limit-cap", proc.stdout + proc.stderr)

        open(capture, "w").close()
        proc = run(["perl", SEARCH, "-s", "evil' OR 1=1_%",
                    "--first-seen", "2011-01-01", "--last-seen", "2011-01-01",
                    "-t", "A"], dated)
        cap = open(capture, encoding="utf-8").read()
        execs = [b for b in blocks(cap) if b and b[0] == "EXEC"]
        report(proc.returncode == 0 and len(execs) == 1, "search-exec",
               proc.stdout + proc.stderr + "\n" + cap)
        if execs:
            sql = execs[0][1]
            bind = execs[0][2:]
            report("evil" not in sql and sql.count("?") >= 6 and "LIMIT 100" in sql,
                   "search-sql", sql)
            report(bind.count("%evil' OR 1=1\\_\\%%") == 2
                   and "2011-01-01 00:00:01" in bind
                   and "2011-01-01 23:59:59" in bind
                   and bind.count("A") >= 1,
                   "search-bind", "\n".join(bind))

        open(capture, "w").close()
        proc = run(["perl", SEARCH, "-r", "-s", "%foo%"], dated)
        cap = open(capture, encoding="utf-8").read()
        execs = [b for b in blocks(cap) if b and b[0] == "EXEC"]
        raw_ok = bool(execs) and execs[0][2:].count("%foo%") == 2
        report(proc.returncode == 0 and raw_ok, "search-raw",
               proc.stdout + proc.stderr + "\n" + cap)

        custom = perl_env(lib, capture, {
            "PDNS_DB_PASSWORD": "s3cret",
            "PDNS_DB_PORT": "3307",
            "PDNS_DB_TABLE": "records",
        })
        open(capture, "w").close()
        proc = run(["perl", SEARCH, "-s", "example"], custom)
        cap = open(capture, encoding="utf-8").read()
        report(proc.returncode == 0 and "port=3307" in cap and "FROM pdns.records" in cap
               and "FIRST_SEEN" in cap and "first_seen" not in cap,
               "search-table-port", proc.stdout + proc.stderr + "\n" + cap)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
