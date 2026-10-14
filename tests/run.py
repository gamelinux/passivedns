#!/usr/bin/env python3
"""Run the passivedns regression scripts.

    python3 tests/run.py

Each script exits non-zero on failure. Set PASSIVEDNS to the binary.
Otherwise the scripts look for src/passivedns, then /tmp/pdns-build/passivedns.
"""

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = ["regress.py", "t_cli.py", "t_tools.py", "t_php.py"]


def main():
    env = os.environ.copy()
    if not env.get("PASSIVEDNS"):
        for cand in (HERE.parent / "src" / "passivedns", Path("/tmp/pdns-build/passivedns")):
            if cand.is_file() and os.access(cand, os.X_OK):
                env["PASSIVEDNS"] = str(cand)
                break
    binary = env.get("PASSIVEDNS")
    if binary and not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        print("PASSIVEDNS is not an executable file: %s" % binary)
        return 1
    if not binary:
        print("no passivedns binary. Run make, or set PASSIVEDNS.")
        return 1
    print("binary %s" % binary)
    failed = 0
    for name in ORDER:
        print("== %s" % name)
        proc = subprocess.run([sys.executable, str(HERE / name)], env=env)
        if proc.returncode != 0:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
