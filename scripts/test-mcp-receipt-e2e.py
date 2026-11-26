#!/usr/bin/env python3
"""Self-test of the negative checks of scripts/mcp-receipt-e2e.py.

A negative check passes only when praetore-verify exits 1 and its JSON
summary names a refusal (`ok` false, a code other than USAGE or INTERNAL). A
crash (101), a kill by a signal, exit 0, a usage error (also exit 1) or a
summary that is not JSON must fail it. Runs stub
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

REFUSAL = """echo '{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}'"""
CASES = [
    ("exit 1 (refused)", f"{REFUSAL}; exit 1", True),
    ("exit 1, usage error", """echo '{"ok":false,"command":"journal","code":"USAGE"}'; exit 1""", False),
    ("exit 1, internal error", """echo '{"ok":false,"command":"unknown","code":"INTERNAL"}'; exit 1""", False),
    ("exit 1, ok true", """echo '{"ok":true,"command":"journal","code":"OK"}'; exit 1""", False),
    ("exit 1, no JSON", "echo refused; exit 1", False),
    ("exit 0 (accepted)", f"{REFUSAL}; exit 0", False),
    ("exit 2", f"{REFUSAL}; exit 2", False),
    ("exit 101 (panic)", f"{REFUSAL}; exit 101", False),
    ("killed by SIGKILL", f"{REFUSAL}; kill -9 $$", False),
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
