#!/usr/bin/env python3
"""Self-test of the negative checks of scripts/mcp-receipt-e2e.py.

A negative check passes only when praetore-verify exits 1 (it refused the
input). A crash (101), a kill by a signal or exit 0 must fail it. Runs stub
verifiers through the script's own verify_cli and refused; builds nothing.
"""
import importlib.util
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
_spec = importlib.util.spec_from_file_location("mcp_receipt_e2e", os.path.join(HERE, "mcp-receipt-e2e.py"))
e2e = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e2e)

CASES = [
    ("exit 1 (refused)", "exit 1", True),
    ("exit 0 (accepted)", "exit 0", False),
    ("exit 2", "exit 2", False),
    ("exit 101 (panic)", "exit 101", False),
    ("killed by SIGKILL", "kill -9 $$", False),
]


def main():
    failures = 0
    with tempfile.TemporaryDirectory() as work:
        for index, (label, body, want) in enumerate(CASES):
            stub = os.path.join(work, f"verifier-{index}")
            with open(stub, "w", encoding="utf-8") as handle:
                handle.write(f"#!/bin/sh\n{body}\n")
            os.chmod(stub, stat.S_IRWXU)
            got = e2e.refused(e2e.verify_cli(stub, "journal"))
            ok = got == want
            print(f"{'PASS' if ok else 'FAIL'}: {label}: refused={got}, expected {want}")
            failures += not ok
    print(f"{failures} check(s) failed" if failures else "all checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
