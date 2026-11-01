#!/usr/bin/env python3
"""End-to-end smoke test of a built praetore-mcp binary.

Runs the binary in front of the real @modelcontextprotocol/server-filesystem
(through npx) with a fresh LOCAL/DEV home and a deny rule for write_file,
sends one allowed tools/call (read_text_file) and one denied one
(write_file), and checks the replies, the file system, the receipts and
`verify`. Needs Python 3 (standard library only) and Node with npx.

Usage: python3 -I scripts/mcp-smoke.py path/to/praetore-mcp
Exit code 0 when every check passes; every check is printed.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading

SERVER = "@modelcontextprotocol/server-filesystem@2.1.0"
TIMEOUT_SECONDS = 180  # first run downloads the server through npx


def run(binary, *args):
    result = subprocess.run(
        [binary, *args], capture_output=True, text=True, timeout=60, check=False
    )
    print(f"$ praetore-mcp {' '.join(args)}  -> exit {result.returncode}")
    for line in (result.stdout + result.stderr).splitlines():
        print(f"    {line}")
    return result


def wrap_session(binary, home, root, requests, wanted_ids):
    """Sends `requests`, returns {id: response} once every wanted id answered."""
    process = subprocess.Popen(
        [binary, "wrap", "--dir", home, "--name", "filesystem", "--mode", "enforce",
         "--", "npx", "-y", SERVER, root],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    stderr_lines = []
    threading.Thread(
        target=lambda: stderr_lines.extend(process.stderr), daemon=True
    ).start()
    for request in requests:
        process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()

    responses = {}
    timer = threading.Timer(TIMEOUT_SECONDS, process.kill)
    timer.start()
    try:
        for line in process.stdout:
            message = json.loads(line)
            if message.get("id") in wanted_ids:
                responses[message["id"]] = message
            if wanted_ids <= responses.keys():
                break
    finally:
        timer.cancel()
        process.stdin.close()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
    for line in stderr_lines:
        print(f"    [stderr] {line.rstrip()}")
    return responses


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = os.path.realpath(sys.argv[1])
    failures = []

    def check(name, condition, detail=""):
        print(f"{'PASS' if condition else 'FAIL'}: {name}{f' ({detail})' if detail and not condition else ''}")
        if not condition:
            failures.append(name)

    # realpath: on macOS the temp dir is under /var, a symlink to /private/var.
    work = os.path.realpath(tempfile.mkdtemp(prefix="praetore-mcp-smoke-"))
    home = os.path.join(work, "home")
    root = os.path.join(work, "fsroot")
    os.mkdir(root)
    with open(os.path.join(root, "a.txt"), "w", encoding="utf-8") as handle:
        handle.write("hola\n")

    check("--version", run(binary, "--version").returncode == 0)
    check("init", run(binary, "init", "--dir", home).returncode == 0)
    check(
        "policy deny write_file",
        run(binary, "policy", "deny", "--id", "deny-write", "--server", "filesystem",
            "--tool", "write_file", "--dir", home).returncode == 0,
    )
    check("policy check", run(binary, "policy", "check", "--dir", home).returncode == 0)

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "praetore-mcp-smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "read_text_file", "arguments": {"path": os.path.join(root, "a.txt")}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "write_file",
            "arguments": {"path": os.path.join(root, "b.txt"), "content": "x"}}},
    ]
    print(f"$ praetore-mcp wrap --dir <home> --name filesystem --mode enforce -- npx -y {SERVER} <fsroot>")
    responses = wrap_session(binary, home, root, requests, {1, 2, 3})
    for key in sorted(responses):
        print(f"    reply {key}: {json.dumps(responses[key])[:300]}")

    allowed = responses.get(2, {}).get("result", {})
    allowed_text = json.dumps(allowed.get("content", []))
    check("read_text_file is forwarded", allowed.get("isError") is not True and "hola" in allowed_text,
          json.dumps(responses.get(2)))
    denied = responses.get(3, {}).get("result", {})
    denied_text = json.dumps(denied.get("content", []), ensure_ascii=False)
    check("write_file is refused with the rule",
          denied.get("isError") is True and "Denied by PRÆTORE policy" in denied_text
          and "deny-write" in denied_text, json.dumps(responses.get(3)))
    check("b.txt was not created", not os.path.exists(os.path.join(root, "b.txt")))

    receipts = run(binary, "receipts", "--dir", home)
    lines = receipts.stdout.splitlines()
    check("receipts: one ALLOW read_text_file",
          any("read_text_file" in l and "ALLOW" in l for l in lines))
    check("receipts: one DENY write_file deny-write",
          any("write_file" in l and "DENY" in l and "deny-write" in l for l in lines))
    verify = run(binary, "verify", "--dir", home)
    check("verify exit 0", verify.returncode == 0)
    check("verify: 2 verified, 0 failed", "2 receipts: 2 verified, 0 failed" in verify.stdout)

    print(f"{len(failures)} check(s) failed" if failures else "all checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
