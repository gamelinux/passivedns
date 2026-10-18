#!/usr/bin/env python3
# ----------------------------------------------------------------------
# PassiveDNS to DB
# Copyright (C) 2011-2026, Edward Fjellskål <edwardfjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# ----------------------------------------------------------------------
"""Load passivedns log lines into MySQL or MariaDB.

Reads the JSON log from PassiveDNS 2.x and the older || lines. One
answer becomes one table row. A non-zero response code with an empty
answer list is stored as that code, for example NXDOMAIN.
"""

import argparse
import calendar
import json
import os
import re
import signal
import sys
import time
from datetime import datetime

VERSION = "1.0"
IDENT = re.compile(r"^[A-Za-z0-9_]+$")
UNIX_TS = re.compile(r"^(\d+)(?:\.\d+)?$")
ISO_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$"
)

PIDFILE = "/var/run/pdns2db.pid"
RUNLOG = "/var/log/passivedns-run.log"
TIMEOUT = 1

INSERT_SQL = """
INSERT INTO {table} (
  QUERY,RR,MAPTYPE,ANSWER,TTL,COUNT,LAST_SEEN,FIRST_SEEN
) VALUES (
  %s,%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),FROM_UNIXTIME(%s)
) ON DUPLICATE KEY UPDATE
  TTL = IF(TTL < VALUES(TTL), VALUES(TTL), TTL),
  COUNT = COUNT + VALUES(COUNT),
  LAST_SEEN = IF(LAST_SEEN < VALUES(LAST_SEEN), VALUES(LAST_SEEN), LAST_SEEN),
  FIRST_SEEN = IF(FIRST_SEEN > VALUES(FIRST_SEEN), VALUES(FIRST_SEEN), FIRST_SEEN)
"""

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS {table} (
  ID            BIGINT(20) UNSIGNED  NOT NULL AUTO_INCREMENT,
  QUERY         varchar(255)         NOT NULL DEFAULT   '',
  MAPTYPE       varchar(10)          NOT NULL DEFAULT   '',
  RR            varchar(10)          NOT NULL DEFAULT   '',
  ANSWER        varchar(255)         NOT NULL DEFAULT   '',
  TTL           int(10)              NOT NULL DEFAULT  '0',
  COUNT         BIGINT(20) UNSIGNED  NOT NULL DEFAULT  '1',
  FIRST_SEEN    DATETIME             NOT NULL,
  LAST_SEEN     DATETIME             NOT NULL,
  PRIMARY KEY (ID),
  UNIQUE KEY MARQ (MAPTYPE,ANSWER,RR,QUERY),
  KEY query_idx (QUERY),
  KEY answer_idx (ANSWER)
)
"""


def logger(msg):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now} {msg}", flush=True)


def die(msg, code=1):
    sys.stderr.write(msg + "\n")
    raise SystemExit(code)


def strip_dot(value):
    if isinstance(value, str) and len(value) > 1 and value.endswith("."):
        return value[:-1]
    return value if isinstance(value, str) else ""


def db_text(value):
    # A NUL would cut the value off in a C database client.
    return value.replace("\x00", "\\000")


def unix_seconds(value):
    if not isinstance(value, str):
        return None
    match = UNIX_TS.fullmatch(value)
    if match:
        return int(match.group(1))
    match = ISO_TS.fullmatch(value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    try:
        return calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    except (OverflowError, ValueError):
        return None


def whole_number(value):
    if isinstance(value, bool) or isinstance(value, int):
        if isinstance(value, bool) or value < 0:
            return None
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


class CaptureDB:
    """Record SQL the way the tool tests expect. No database."""

    def __init__(self, path, host, port, user, password, name):
        self.path = path
        self._rec(
            "CONNECT",
            f"database={name};host={host};port={port}",
            user,
            password,
        )

    def _rec(self, *parts):
        with open(self.path, "a", encoding="utf-8") as handle:
            for part in parts:
                text = "" if part is None else str(part)
                text = text.replace("\n", "\\n").replace("\r", "\\r")
                handle.write(text + "\n")
            handle.write("END\n")

    def do(self, sql):
        self._rec("DO", sql)
        return True

    def execute(self, sql, args):
        self._rec("EXEC", sql, *args)

    def close(self):
        return None


class MysqlDB:
    def __init__(self, raw):
        self.raw = raw

    def do(self, sql):
        cur = self.raw.cursor()
        try:
            cur.execute(sql)
        finally:
            cur.close()
        return True

    def execute(self, sql, args):
        cur = self.raw.cursor()
        try:
            cur.execute(sql, args)
        finally:
            cur.close()

    def close(self):
        self.raw.close()


def connect_db(host, port, user, password, name):
    capture = os.environ.get("PDNS_TEST_CAPTURE")
    if capture:
        return CaptureDB(capture, host, port, user, password, name)
    try:
        import pymysql
    except ImportError:
        pymysql = None
    if pymysql is not None:
        raw = pymysql.connect(
            host=host,
            port=int(port),
            user=user,
            password=password,
            database=name,
            autocommit=True,
            charset="utf8mb4",
        )
        return MysqlDB(raw)
    die("Install python3-pymysql to load the database")


def settings_from_env(nodb):
    host = os.environ.get("PDNS_DB_HOST") or "127.0.0.1"
    port = os.environ.get("PDNS_DB_PORT") or "3306"
    name = os.environ.get("PDNS_DB_NAME") or "pdns"
    user = os.environ.get("PDNS_DB_USER") or "pdns"
    table = os.environ.get("PDNS_DB_TABLE") or "pdns"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        die("PDNS_DB_PORT must be 1..65535")
    if not IDENT.fullmatch(name):
        die("PDNS_DB_NAME must be an identifier")
    if not IDENT.fullmatch(table):
        die("PDNS_DB_TABLE must be an identifier")
    password = ""
    if not nodb:
        password = os.environ.get("PDNS_DB_PASSWORD") or ""
        if password == "":
            die("Set PDNS_DB_PASSWORD")
    return host, int(port), name, user, password, table


def load_static(path):
    found = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0]
            line = line.replace("\t", "").replace(" ", "").strip()
            if line:
                found.add(line)
    return found


def load_pcre(path):
    patterns = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0]
            line = line.replace("\t", "").replace(" ", "").strip()
            if not line:
                continue
            try:
                compiled = re.compile(line)
            except re.error as exc:
                die(f"Bad pattern in {path}: {exc}")
            patterns.append((line, compiled))
    patterns.sort(key=lambda item: len(item[0]), reverse=True)
    return [item[1] for item in patterns]


def load_list(static_path, pcre_path):
    if not static_path and not pcre_path:
        return None
    return {
        "static": load_static(static_path) if static_path else set(),
        "pcre": load_pcre(pcre_path) if pcre_path else [],
    }


def domain_match(query, answer, rules):
    if rules is None:
        return False
    static = rules["static"]
    if query in static or answer in static:
        return True
    for pattern in rules["pcre"]:
        if pattern.search(query) or pattern.search(answer):
            return True
    return False


def line_matches(rows, rules):
    return any(domain_match(row["query"], row["answer"], rules) for row in rows)


def rows_from_text(line):
    fields = line.split("||")
    if len(fields) != 9:
        return None
    tst, _cip, _sip, rr, query, rtype, answer, ttl, count = fields
    ts = unix_seconds(tst)
    ttl_n = whole_number(ttl)
    count_n = whole_number(count)
    if ts is None or ttl_n is None or count_n is None:
        return []
    return [{
        "query": strip_dot(query),
        "rr": rr,
        "type": rtype,
        "answer": strip_dot(answer),
        "ttl": ttl_n,
        "count": count_n,
        "ts": ts,
    }]


def rows_from_json(line):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    query = obj.get("query")
    answers = obj.get("answer")
    if not isinstance(query, str) or not isinstance(answers, list):
        return None
    ttl_n = whole_number(obj.get("ttl"))
    count_n = whole_number(obj.get("cnt"))
    ts = unix_seconds(obj.get("pts") if isinstance(obj.get("pts"), str) else "")
    if ttl_n is None or count_n is None or ts is None:
        return []
    qtype = obj.get("qtype") if isinstance(obj.get("qtype"), str) else ""
    atype = obj.get("atype") if isinstance(obj.get("atype"), str) else qtype
    rc = obj.get("rc") if isinstance(obj.get("rc"), str) else ""
    query = strip_dot(query)
    rows = []
    for item in answers:
        if not isinstance(item, str):
            continue
        rows.append({
            "query": query,
            "rr": "IN",
            "type": atype,
            "answer": strip_dot(item),
            "ttl": ttl_n,
            "count": count_n,
            "ts": ts,
        })
    if rows:
        return rows
    answer = rc if rc and rc != "NOERROR" else ""
    rtype = qtype or atype
    return [{
        "query": query,
        "rr": "IN",
        "type": rtype,
        "answer": answer,
        "ttl": ttl_n,
        "count": count_n,
        "ts": ts,
    }]


def parse_line(line):
    if line.startswith("{"):
        return rows_from_json(line)
    return rows_from_text(line)


def setup_db(db, table):
    try:
        db.do(f"select count(*) from {table} where 1=0")
        return
    except Exception:
        pass
    try:
        db.do(CREATE_SQL.format(table=table))
    except Exception:
        die(f"[E] Table {table} does not exist, and we could not create it! Sorry!")


def put_row(db, table, row):
    sql = INSERT_SQL.format(table=table)
    db.execute(sql, (
        db_text(row["query"]), row["rr"], row["type"], db_text(row["answer"]),
        row["ttl"], row["count"], row["ts"], row["ts"],
    ))


def append_alert(path, line):
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        logger(f"[W] Problems with open({path}): {exc}")


def parse_logfile(path, start, stop, db, table, lists, alertlog, nodb, verbose):
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        raise SystemExit(3)
    try:
        try:
            handle.seek(start)
        except OSError:
            raise SystemExit(2)
        while handle.tell() < stop:
            line = handle.readline()
            if line == "":
                break
            line = line.rstrip("\n").rstrip("\r")
            rows = parse_line(line)
            if rows is None:
                logger(f"[W] Not valid Nr. of args in format: '{path}'")
                continue
            if not rows:
                continue
            if line_matches(rows, lists["skip"]):
                if verbose:
                    logger("[*] Domain marked to skip DB insertion")
                continue
            if lists["white"] and lists["black"] and line_matches(rows, lists["white"]):
                if verbose:
                    logger("[*] Whitelisted domain")
            elif line_matches(rows, lists["black"]):
                if verbose:
                    logger("[*] Blacklisted domain")
                append_alert(alertlog, line)
            kept = rows
            if lists["only"] is not None:
                kept = [
                    row for row in rows
                    if domain_match(row["query"], row["answer"], lists["only"])
                ]
                if verbose and kept:
                    logger("[*] Onlylisted domain")
            if nodb:
                continue
            for row in kept:
                try:
                    put_row(db, table, row)
                except Exception:
                    continue
    finally:
        handle.close()


def file_watch(path, db, table, lists, alertlog, nodb, batch, verbose):
    pos = 0
    while True:
        try:
            startsize = os.path.getsize(path)
        except OSError:
            time.sleep(TIMEOUT)
            continue
        if startsize < pos:
            pos = 0
        parse_logfile(path, pos, startsize, db, table, lists, alertlog, nodb, verbose)
        pos = startsize
        if batch:
            logger(f"[*] Processing of {path} is done, exiting!")
            raise SystemExit(0)
        time.sleep(TIMEOUT)


def daemonize():
    try:
        os.chdir("/")
    except OSError as exc:
        die(f"chdir /: {exc}")
    devnull = os.open("/dev/null", os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    logfd = os.open(RUNLOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(logfd, 1)
    os.close(logfd)
    pid = os.fork()
    if pid > 0:
        try:
            with open(PIDFILE, "w", encoding="utf-8") as handle:
                handle.write(f"{pid}\n")
        except OSError as exc:
            die(f"open({PIDFILE}): {exc}")
        os._exit(0)
    os.setsid()
    os.dup2(1, 2)


def main(argv):
    parser = argparse.ArgumentParser(prog="pdns2db.py", description="Load passivedns logs into MySQL or MariaDB")
    parser.add_argument("--file", default="/var/log/passivedns.log")
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--skiplist")
    parser.add_argument("--onlylist")
    parser.add_argument("--whitelist")
    parser.add_argument("--blacklist")
    parser.add_argument("--skiplist-pcre")
    parser.add_argument("--onlylist-pcre")
    parser.add_argument("--whitelist-pcre")
    parser.add_argument("--blacklist-pcre")
    parser.add_argument("--alertlog", default="/var/log/passivedns-alert.log")
    parser.add_argument("--nodb", action="store_true")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", type=int, default=0)
    parser.add_argument("--version", action="version", version=f"pdns2db.py {VERSION}")
    args = parser.parse_args(argv)

    skip = load_list(args.skiplist, args.skiplist_pcre)
    white = load_list(args.whitelist, args.whitelist_pcre)
    black = load_list(args.blacklist, args.blacklist_pcre)
    only = load_list(args.onlylist, args.onlylist_pcre)
    if white and not black:
        logger("[W] Whitelist without Blacklist does not make sense!")
        white = None
    lists = {"skip": skip, "white": white, "black": black, "only": only}

    db = None

    def game_over(signum=None, frame=None):
        logger("[*] Terminating...")
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        if args.daemon:
            try:
                os.unlink(PIDFILE)
            except OSError:
                pass
        raise SystemExit(0)

    signal.signal(signal.SIGINT, game_over)
    signal.signal(signal.SIGTERM, game_over)
    signal.signal(signal.SIGQUIT, game_over)

    logger("[*] Starting pdns2db.py")
    if args.daemon:
        logger("[*] Daemonizing...")
        daemonize()

    host, port, name, user, password, table = settings_from_env(args.nodb)
    if not args.nodb:
        logger("[*] Connecting to database...")
        try:
            db = connect_db(host, port, user, password, name)
        except SystemExit:
            raise
        except Exception as exc:
            die(f"database connect failed: {exc}")
        setup_db(db, table)
    else:
        logger("[*] Skipping database operations...")

    logger(f"[*] Looking for passive DNS data in file: {args.file}")
    file_watch(
        args.file, db, table, lists, args.alertlog,
        args.nodb, args.batch, args.verbose,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
