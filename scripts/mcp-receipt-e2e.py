#!/usr/bin/env python3
"""Receipts of the packaged praetore-mcp, verified by praetore-verify.

Runs the praetore-mcp binary in front of the real
@modelcontextprotocol/server-filesystem (the server of
scripts/mcp-smoke.py, installed from scripts/mcp-smoke/package-lock.json)
with a fresh home, an allow rule for read_text_file and a deny rule for
write_file, and sends one allowed and one denied tools/call. No rule needs
a person's decision: the flow has no approval.

Then praetore-verify, a separate binary built from this checkout, checks
what praetore-mcp wrote:

* each receipt with `evidence --strict` (signature, issuer pins, policy
  digest, intent and decision time), from the journal bytes as written;
* the receipts journal with `journal --expected-head HEAD
  --require-anchored`, where HEAD is the head praetore-mcp `verify`
  printed: the two implementations must agree on it;
* praetore-mcp `verify` with that head and `--expected-approval-head none`
  is OK (exit 0).

And it refuses what was changed after the fact:

* the journal without its last line, against the same head;
* a receipt with one byte of its signed evidence changed.

    npm ci --ignore-scripts --prefix scripts/mcp-smoke
    python3 -I scripts/mcp-receipt-e2e.py path/to/praetore-mcp path/to/praetore-verify

Exit code 0 when every check passes; every check is printed.
"""

import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
_spec = importlib.util.spec_from_file_location("mcp_smoke", os.path.join(HERE, "mcp-smoke.py"))
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def verify_cli(verifier, *args):
    result = subprocess.run(
        [verifier, *args], capture_output=True, text=True, timeout=60, check=False
    )
    print(f"$ praetore-verify {' '.join(args)}  -> exit {result.returncode}")
    for line in (result.stdout + result.stderr).splitlines():
        print(f"    {line}")
    return result


def evidence_bytes(line):
    """The `evidence` member of a journal line, byte for byte as signed."""
    key = '"evidence":'
    start = line.index(key) + len(key)
    if not line.endswith("}"):
        raise ValueError("journal line does not end with }")
    return line[start:-1]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    binary = os.path.realpath(sys.argv[1])
    verifier = os.path.realpath(sys.argv[2])
    server = smoke.server_command()
    failures = []

    def check(name, condition, detail=""):
        print(f"{'PASS' if condition else 'FAIL'}: {name}{f' ({detail})' if detail and not condition else ''}")
        if not condition:
            failures.append(name)

    work = os.path.realpath(tempfile.mkdtemp(prefix="praetore-mcp-receipt-e2e-"))
    home = os.path.join(work, "home")
    root = os.path.join(work, "fsroot")
    os.mkdir(root)
    with open(os.path.join(root, "a.txt"), "w", encoding="utf-8") as handle:
        handle.write("hola\n")

    run = smoke.run
    check("init", run(binary, "init", "--dir", home).returncode == 0)
    check("policy allow read_text_file",
          run(binary, "policy", "allow", "--id", "allow-read", "--server", "filesystem",
              "--tool", "read_text_file", "--dir", home).returncode == 0)
    check("policy deny write_file",
          run(binary, "policy", "deny", "--id", "deny-write", "--server", "filesystem",
              "--tool", "write_file", "--dir", home).returncode == 0)

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "praetore-mcp-receipt-e2e", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "read_text_file", "arguments": {"path": os.path.join(root, "a.txt")}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "write_file",
            "arguments": {"path": os.path.join(root, "b.txt"), "content": "x"}}},
    ]
    responses = smoke.wrap_session(binary, home, root, server, requests, {1, 2, 3})
    allowed = responses.get(2, {}).get("result", {})
    check("read_text_file is forwarded",
          allowed.get("isError") is not True and "hola" in json.dumps(allowed.get("content", [])),
          json.dumps(responses.get(2)))
    check("write_file is refused", responses.get(3, {}).get("result", {}).get("isError") is True,
          json.dumps(responses.get(3)))
    check("no approval journal", not os.path.exists(os.path.join(home, "approvals", "journal.jsonl")))

    journals = sorted(glob.glob(os.path.join(home, "receipts", "*.jsonl")))
    check("one receipts journal file", len(journals) == 1, str(journals))
    if len(journals) != 1:
        sys.exit(1)
    journal = journals[0]
    with open(journal, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    check("two receipts", len(lines) == 2, str(len(lines)))

    # The head praetore-mcp reports, read from its own verify output.
    own = run(binary, "verify", "--dir", home)
    match = re.search(r"^journal head: .*, head ([0-9a-f]{64}) \(", own.stdout, re.MULTILINE)
    check("praetore-mcp verify prints the journal head", match is not None, own.stdout)
    if match is None:
        sys.exit(1)
    head = match.group(1)

    pins = ["--attester-pin", os.path.join(home, "attester-public-key.hex"),
            "--policy", os.path.join(home, "policy.json")]
    for index, line in enumerate(lines):
        evidence = os.path.join(work, f"evidence-{index}.json")
        with open(evidence, "w", encoding="utf-8") as handle:
            handle.write(evidence_bytes(line))
        out = verify_cli(verifier, "evidence", "--evidence", evidence,
                         "--issuer-pins", os.path.join(home, "issuer-pins.jsonl"),
                         "--strict", *pins)
        check(f"praetore-verify evidence --strict, receipt {index}",
              out.returncode == 0 and out.stdout.startswith("OK evidence OK"), out.stdout + out.stderr)

    out = verify_cli(verifier, "journal", "--journal", journal, "--expected-head", head,
                     "--require-anchored", "--format", "json", *pins)
    check("praetore-verify journal at praetore-mcp's head", out.returncode == 0,
          out.stdout + out.stderr)
    try:
        reported = json.loads(out.stdout)
    except ValueError:
        reported = {}
    details = reported.get("details", reported)
    check("both verifiers report the same head",
          details.get("head") == head and HEX64.match(head) is not None,
          f"praetore-verify {details.get('head')} vs praetore-mcp {head}")
    check("praetore-verify counts two entries", details.get("entries") == 2, json.dumps(details)[:300])

    anchored = run(binary, "verify", "--dir", home, "--expected-head", head,
                   "--expected-approval-head", "none")
    check("praetore-mcp verify with both heads is OK (exit 0)",
          anchored.returncode == 0 and anchored.stdout.startswith("OK "), anchored.stdout)

    # Changed after the fact: both must fail.
    cut = os.path.join(work, "cut.jsonl")
    with open(cut, "w", encoding="utf-8") as handle:
        handle.write(lines[0] + "\n")
    out = verify_cli(verifier, "journal", "--journal", cut, "--expected-head", head,
                     "--require-anchored", *pins)
    check("praetore-verify refuses the journal without its last line", out.returncode != 0,
          out.stdout + out.stderr)

    text = evidence_bytes(lines[0])
    changed = text.replace("read_text_file", "read_text_filf", 1)
    check("the tamper changes the evidence", changed != text)
    tampered = os.path.join(work, "tampered.json")
    with open(tampered, "w", encoding="utf-8") as handle:
        handle.write(changed)
    out = verify_cli(verifier, "evidence", "--evidence", tampered,
                     "--issuer-pins", os.path.join(home, "issuer-pins.jsonl"), "--strict", *pins)
    check("praetore-verify refuses a changed receipt", out.returncode != 0, out.stdout + out.stderr)

    print(f"\n{len(failures)} check(s) failed" if failures else "\nall checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
