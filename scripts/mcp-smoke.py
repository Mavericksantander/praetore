#!/usr/bin/env python3
"""End-to-end smoke test of a built praetore-mcp binary.

Runs the binary in front of the real @modelcontextprotocol/server-filesystem
with a fresh LOCAL/DEV home and a deny rule for write_file, sends one
allowed tools/call (read_text_file) and one denied one (write_file), and
checks the replies, the file system, the receipts and `verify`. Needs
Python 3 (standard library only) and Node.

The server comes from scripts/mcp-smoke/, installed from its committed
lockfile; the script does not download anything:

    npm ci --ignore-scripts --prefix scripts/mcp-smoke
    python3 -I scripts/mcp-smoke.py path/to/praetore-mcp

Exit code 0 when every check passes; every check is printed.
"""

import json
import os
import pty
import select
import subprocess
import sys
import tempfile
import threading
import time

SERVER_PACKAGE = "@modelcontextprotocol/server-filesystem"
SERVER_VERSION = "2.3.0"
SERVER_BIN = "mcp-server-filesystem"
NODE_PROJECT = os.path.join(os.path.dirname(os.path.realpath(__file__)), "mcp-smoke")
TIMEOUT_SECONDS = 180


def server_command():
    """`node <entry point>` of the server installed by `npm ci` in NODE_PROJECT.

    Exits when it is missing or is not the pinned version, so a run never
    falls back to a download.
    """
    package_dir = os.path.join(NODE_PROJECT, "node_modules", *SERVER_PACKAGE.split("/"))
    try:
        with open(os.path.join(package_dir, "package.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
    except FileNotFoundError:
        sys.exit(f"error: {SERVER_PACKAGE} is not installed; run "
                 f"`npm ci --ignore-scripts --prefix {NODE_PROJECT}` first")
    if manifest.get("version") != SERVER_VERSION:
        sys.exit(f"error: {SERVER_PACKAGE} {manifest.get('version')} is installed, "
                 f"expected {SERVER_VERSION} (scripts/mcp-smoke/package-lock.json)")
    entry = manifest.get("bin")
    if isinstance(entry, dict):
        entry = entry.get(SERVER_BIN)
    if not isinstance(entry, str):
        sys.exit(f"error: {SERVER_PACKAGE} has no `{SERVER_BIN}` bin entry")
    return ["node", os.path.join(package_dir, entry)]


def run(binary, *args):
    result = subprocess.run(
        [binary, *args], capture_output=True, text=True, timeout=60, check=False
    )
    print(f"$ praetore-mcp {' '.join(args)}  -> exit {result.returncode}")
    for line in (result.stdout + result.stderr).splitlines():
        print(f"    {line}")
    return result


def wrap_session(binary, home, root, server, requests, wanted_ids):
    """Sends `requests`, returns {id: response} once every wanted id answered."""
    process = subprocess.Popen(
        [binary, "wrap", "--dir", home, "--name", "filesystem", "--mode", "enforce",
         "--", *server, root],
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


def approve_on_pty(binary, home, approval_id):
    """Runs `approve` on a pseudo-terminal and types the code it prints."""
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [binary, "approve", approval_id, "--dir", home],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)
    buf = b""
    deadline = time.time() + 30

    def read_ready():
        ready, _, _ = select.select([master], [], [], 0.2)
        if not ready:
            return b""
        try:
            return os.read(master, 4096)
        except OSError:
            return b""

    typed = False
    while time.time() < deadline:
        chunk = read_ready()
        if chunk:
            buf += chunk
            if not typed and b"confirmation:" in buf and b"Type " in buf:
                code = buf.split(b"Type ", 1)[1].split()[0]
                os.write(master, code + b"\n")
                typed = True
        if process.poll() is not None and not select.select([master], [], [], 0)[0]:
            break
    try:
        returncode = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        returncode = process.wait()
    os.close(master)
    text = buf.decode("utf-8", "replace")
    print(f"$ praetore-mcp approve {approval_id}  -> exit {returncode}")
    for line in text.splitlines():
        print(f"    {line}")
    return returncode, text


def approval_id_from(message):
    content = message.get("result", {}).get("content") or []
    text = content[0].get("text", "") if content else ""
    marker = "Approval id: "
    if marker not in text:
        return ""
    return text.split(marker, 1)[1].split()[0]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = os.path.realpath(sys.argv[1])
    server = server_command()
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
    print(f"$ praetore-mcp wrap --dir <home> --name filesystem --mode enforce -- "
          f"node <{SERVER_PACKAGE}@{SERVER_VERSION}> <fsroot>")
    responses = wrap_session(binary, home, root, server, requests, {1, 2, 3})
    for key in sorted(responses):
        print(f"    reply {key}: {json.dumps(responses[key])[:300]}")

    allowed = responses.get(2, {}).get("result", {})
    allowed_text = json.dumps(allowed.get("content", []))
    check("read_text_file is forwarded", allowed.get("isError") is not True and "hola" in allowed_text,
          json.dumps(responses.get(2)))
    denied = responses.get(3, {}).get("result", {})
    denied_text = json.dumps(denied.get("content", []), ensure_ascii=False)
    # The client text is the same for every DENY; the rule is in the receipt.
    check("write_file is refused",
          denied.get("isError") is True and "Denied by PRÆTORE" in denied_text
          and "deny-write" not in denied_text, json.dumps(responses.get(3)))
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

    # Local approval, still on the same home: list_directory needs a person
    # to approve that exact call. The confirmation runs on a pseudo-terminal.
    check(
        "policy require-approval list_directory",
        run(binary, "policy", "require-approval", "--id", "approve-list",
            "--server", "filesystem", "--tool", "list_directory", "--dir", home).returncode == 0,
    )
    hold_requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "praetore-mcp-smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "list_directory", "arguments": {"path": root}}},
    ]
    print("$ praetore-mcp wrap ... list_directory (expect hold)")
    held = wrap_session(binary, home, root, server, hold_requests, {4})
    held_msg = held.get(4, {})
    approval_id = approval_id_from(held_msg)
    held_text = json.dumps(held_msg.get("result", {}).get("content", []))
    check(
        "list_directory is held for approval",
        held_msg.get("result", {}).get("isError") is True
        and "waiting for local human approval" in held_text
        and f"praetore-mcp approve {approval_id} --dir {home}" in held_text
        and len(approval_id) == 64,
        held_text[:400],
    )
    pending = run(binary, "approvals", "--dir", home)
    check("approvals lists the pending id", approval_id in pending.stdout, pending.stdout)
    code, approve_text = approve_on_pty(binary, home, approval_id)
    check("approve on a pty exits 0", code == 0, approve_text)

    retry_requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "praetore-mcp-smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "list_directory", "arguments": {"path": root}}},
    ]
    print("$ praetore-mcp wrap ... list_directory (expect one forward)")
    forwarded = wrap_session(binary, home, root, server, retry_requests, {5})
    forwarded_text = json.dumps(forwarded.get(5, {}).get("result", {}).get("content", []))
    check(
        "approved list_directory is forwarded once",
        forwarded.get(5, {}).get("result", {}).get("isError") is not True and "a.txt" in forwarded_text,
        forwarded_text[:400],
    )
    again_requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "praetore-mcp-smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
            "name": "list_directory", "arguments": {"path": root}}},
    ]
    print("$ praetore-mcp wrap ... list_directory (expect a new hold)")
    again = wrap_session(binary, home, root, server, again_requests, {6})
    again_id = approval_id_from(again.get(6, {}))
    again_text = json.dumps(again.get(6, {}).get("result", {}).get("content", []))
    check(
        "a second retry asks for approval again",
        again.get(6, {}).get("result", {}).get("isError") is True
        and again_id
        and again_id != approval_id
        and "waiting for local human approval" in again_text,
        again_text[:400],
    )
    receipts = run(binary, "receipts", "--dir", home)
    check(
        "receipts show the approval and the one execution",
        "approve by " in receipts.stdout and "executed once" in receipts.stdout,
        receipts.stdout,
    )
    verify = run(binary, "verify", "--dir", home)
    check("verify after approval exits 0", verify.returncode == 0, verify.stdout)
    check(
        "verify reports one approval execution",
        "0 failed" in verify.stdout and "1 decision(s), 1 execution(s)" in verify.stdout,
        verify.stdout,
    )

    print(f"{len(failures)} check(s) failed" if failures else "all checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
