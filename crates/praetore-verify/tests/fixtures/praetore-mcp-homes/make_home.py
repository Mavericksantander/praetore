"""Builds a praetore-mcp home with the praetore-mcp in BIN_DIR: one ALLOW,
one DENY, one held REQUIRE_APPROVAL call, approved on a pty, then forwarded
once. BIN_DIR also holds examples/fake_server.

Usage: python3 -I make_home.py BIN_DIR HOME

The fixtures next to this file keep only what verify reads: the policy,
the public key files, the receipts journal and the approval journal. The
private keys under HOME/keys are not copied."""
import json, os, pty, re, select, subprocess, sys, time
bin_dir, home = sys.argv[1], sys.argv[2]
mcp = os.path.join(bin_dir, 'praetore-mcp')
server = os.path.join(bin_dir, 'examples', 'fake_server')
def run(*args, stdin=''):
    r = subprocess.run([mcp, *args], input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f'{args}: {r.returncode}\n{r.stdout}\n{r.stderr}')
    return r
run('init', '--dir', home)
run('policy', 'allow', '--id', 'allow-echo', '--server', 'fake', '--tool', 'echo', '--dir', home)
run('policy', 'deny', '--id', 'deny-delete', '--server', 'fake', '--tool', 'delete', '--dir', home)
run('policy', 'require-approval', '--id', 'approve-append', '--server', 'fake', '--tool', 'append', '--dir', home)
def session(calls):
    lines = [
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}},
        {"jsonrpc":"2.0","method":"notifications/initialized"},
    ] + calls
    return ''.join(json.dumps(l) + '\n' for l in lines)
def call(i, tool, args):
    return {"jsonrpc":"2.0","id":i,"method":"tools/call","params":{"name":tool,"arguments":args}}
def wrap(calls):
    return run('wrap', '--dir', home, '--name', 'fake', '--mode', 'enforce', '--no-report', '--', server, stdin=session(calls))
append = {"path": "/nonexistent-praetore-fixture/out.txt", "text": "a"}
wrap([call(2, 'echo', {"text": "hi"}), call(3, 'delete', {"path": "x"}), call(4, 'append', append)])
ids = [f[:-5] for f in os.listdir(os.path.join(home, 'approvals', 'pending')) if f.endswith('.json')]
assert len(ids) == 1, ids
pid, fd = pty.fork()
if pid == 0:
    os.execv(mcp, [mcp, 'approve', ids[0], '--dir', home])
buf = b''
start = time.time()
while True:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            buf += os.read(fd, 4096)
        except OSError:
            break
    m = re.search(rb'Type (\w{6})', buf)
    if b'confirmation:' in buf and m:
        os.write(fd, m.group(1) + b'\n')
        break
    if time.time() - start > 10:
        sys.exit(buf.decode(errors='replace'))
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0, buf.decode(errors='replace')
wrap([call(5, 'append', append)])
print(run('verify', '--dir', home).stdout)
