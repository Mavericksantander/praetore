#!/bin/sh
# Rebuilds the /api/state fixtures used by the dashboard page tests from
# real homes: `init`, a policy, calls through `wrap` to the test MCP
# server, then the state the dashboard serves. The temporary home path is
# replaced by /home/user/.praetore/mcp, and the binary's path (in the
# approve and reject commands) by /home/user/.local/bin/praetore-mcp.
# Each wrap session also writes its report in reports/, which /api/state
# lists under "reports".
#
# From the repository root:
#   cargo build -p praetore-mcp --examples
#   sh crates/praetore-mcp/tests-js/fixtures/make.sh
set -eu
BIN=${BIN:-target/debug/praetore-mcp}
FAKE=${FAKE:-target/debug/examples/fake_server}
OUT=crates/praetore-mcp/tests-js/fixtures
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
REAL=$(cd "$WORK" && pwd -P)
EXE=$(cd "$(dirname "$BIN")" && pwd -P)/$(basename "$BIN")

init_line='{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"0"}}}'
call() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$1" "$2" "$3"; }

# A home with an allowed call, a call denied by a rule, a call denied by
# default deny and another allowed call.
make_home() {
  dir=$WORK/$1
  "$BIN" init --dir "$dir" >/dev/null
  "$BIN" policy allow --dir "$dir" --id allow-echo --server fake --tool echo >/dev/null
  "$BIN" policy deny --dir "$dir" --id deny-delete --tool delete_file >/dev/null
  "$BIN" policy require-approval --dir "$dir" --id ask-move --tool move_file >/dev/null
  {
    echo "$init_line"
    call 1 echo '{"msg":"one"}'
    call 2 delete_file '{"path":"/srv/data/report.txt"}'
    call 3 write_file '{"path":"/srv/data/new.txt","content":"<b>x</b>"}'
    call 4 echo '{"msg":"two"}'
  } | "$BIN" wrap --dir "$dir" --name fake --mode enforce -- "$FAKE" >/dev/null 2>&1
}

# dump DIR-NAME [FIXTURE-NAME [QUERY]]
dump() {
  dir=$WORK/$1
  name=${2:-$1}
  query=${3:-}
  "$BIN" dashboard --dir "$dir" --port 0 >"$WORK/$1.log" 2>&1 &
  pid=$!
  port=
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    port=$(grep -oE '127\.0\.0\.1:[0-9]+' "$WORK/$1.log" | head -1 | cut -d: -f2) || true
    [ -n "$port" ] && break
    sleep 0.3
  done
  curl -fsS "http://127.0.0.1:$port/api/state$query" |
    sed -e "s|$REAL/$1|/home/user/.praetore/mcp|g" -e "s|$WORK/$1|/home/user/.praetore/mcp|g" \
      -e "s|$EXE|/home/user/.local/bin/praetore-mcp|g" >"$OUT/$name.json"
  kill "$pid"
  wait "$pid" 2>/dev/null || true
}

# A home whose only rule denies delete_file, after one observe session: a
# DENY by rule and a DENY by default deny, both forwarded (the wrapped
# server ran them), and the DENY of a call the policy does not classify,
# which observe refuses too.
make_observe_home() {
  dir=$WORK/observe
  "$BIN" init --dir "$dir" >/dev/null
  "$BIN" policy deny --dir "$dir" --id deny-delete --tool delete_file >/dev/null
  {
    echo "$init_line"
    call 1 delete_file '{"path":"/srv/data/report.txt"}'
    call 2 echo '{"msg":"one"}'
    call 3 safety_stop '{}'
  } | "$BIN" wrap --dir "$dir" --name fake --mode observe -- "$FAKE" >/dev/null 2>&1
}

make_home healthy
make_home cut
make_home unreadable
make_observe_home
dump observe

# Cut: the third receipt removed, so the fourth (an ALLOW) no longer
# follows it.
journal=$(ls "$WORK/cut/receipts/"*.jsonl | head -1)
sed '3d' "$journal" >"$journal.new" && mv "$journal.new" "$journal"
# Unreadable: bytes that are not UTF-8 at the end of the journal.
journal=$(ls "$WORK/unreadable/receipts/"*.jsonl | head -1)
printf '\377\376garbage\n' >>"$journal"

for name in healthy cut unreadable; do dump "$name"; done
# The healthy home filtered to ALLOW: seq 3 and seq 0, two left out between.
dump healthy healthy-allow '?decision=ALLOW'
# Pending: the same healthy home after one more call, which waits for
# approval; its notice is in approvals/pending, not signed.
{
  echo "$init_line"
  call 5 move_file '{"from":"/srv/a","to":"/srv/b"}'
} | "$BIN" wrap --dir "$WORK/healthy" --name fake --mode enforce -- "$FAKE" >/dev/null 2>&1
dump healthy pending
# Sessions: the same home after `report --last`, which writes a new pair
# next to the report of the last session (two close reports, one with a
# regeneration grouped under it).
# No head is given, so the report says UNANCHORED and `report` exits 3.
status=0
"$BIN" report --dir "$WORK/healthy" --last >/dev/null || status=$?
[ "$status" -eq 3 ] || { echo "report --last: exit $status, expected 3" >&2; exit 1; }
dump healthy sessions
echo "wrote $OUT/{healthy,healthy-allow,pending,sessions,cut,unreadable,observe}.json"
