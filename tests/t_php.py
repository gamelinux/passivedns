#!/usr/bin/env python3
"""Checks for the local PHP demo.

The page is not a running app here. Source checks always run. When php is
installed, a few requests are executed in the CLI SAPI.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "www", "index.php")
failed = 0


def report(ok, label, detail=""):
    global failed
    print("%s %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        failed += 1
        if detail:
            print(detail)


def php_bin():
    for name in ("php", "php8.3", "php8.2", "php8.1"):
        path = shutil.which(name)
        if path:
            return path
    return None


def source_checks(text):
    report("mysql_query" not in text and "mysql_error" not in text
           and "addslashes" not in text, "php-no-old-mysql")
    report("mysqli_prepare" in text and "htmlspecialchars" in text
           and "hash_equals" in text, "php-uses-prepare-and-escape")
    report("ANSWER = ?" in text and "QUERY LIKE ?" in text
           and "ANSWER LIKE ?" in text, "php-placeholders")
    report("PDNS_DB_PASSWORD" in text and "PDNS_WEB_TOKEN" in text, "php-env")
    report("ENT_QUOTES" in text and "utf8mb4" in text, "php-charset")


def run_php(php, env, prelude):
    code = prelude + "\ninclude %s;\n" % repr(PAGE)
    full = os.environ.copy()
    full.update(env)
    for key in list(full):
        if key.startswith("PDNS_") and key not in env:
            del full[key]
    return subprocess.run([php, "-r", code], capture_output=True, text=True,
                          env=full, timeout=15)


def runtime(php):
    proc = run_php(php, {}, "")
    report("PDNS_DB_PASSWORD is not set" in proc.stdout, "php-password",
           proc.stdout + proc.stderr)

    proc = run_php(php, {"PDNS_DB_PASSWORD": "secret", "PDNS_WEB_TOKEN": "tok"},
                   '$_GET["token"] = "nope";')
    report("Forbidden" in proc.stdout and "secret" not in proc.stdout, "php-token",
           proc.stdout + proc.stderr)

    token = "a<b\"'"
    proc = run_php(php, {"PDNS_DB_PASSWORD": "secret", "PDNS_WEB_TOKEN": token},
                   '$_GET["token"] = %s;' % repr(token))
    report("a&lt;b&quot;&#039;" in proc.stdout and token not in proc.stdout,
           "php-token-escaped", proc.stdout + proc.stderr)

    proc = run_php(php, {"PDNS_DB_PASSWORD": "secret"},
                   '$_GET["query"] = "<script>alert(1)</script>";')
    report("Database unavailable." in proc.stdout
           and "<script>" not in proc.stdout, "php-query-not-raw",
           proc.stdout + proc.stderr)


def main():
    with open(PAGE, encoding="utf-8") as fh:
        source_checks(fh.read())
    php = php_bin()
    if not php:
        print("SKIP php runtime (php is not installed)")
        return 1 if failed else 0
    runtime(php)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
