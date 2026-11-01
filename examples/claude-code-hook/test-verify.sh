#!/usr/bin/env bash
# Test de verify.sh con un bundle grande. Firma con el hook, en un estado
# temporal, 1000 recibos distintos, los exporta y comprueba:
#   1. verify.sh sale con 0. Antes, `ls | head` recibía SIGPIPE y salía con 141.
#   2. con UN recibo alterado entre los 1000, sale distinto de 0 y nombra ese
#      recibo.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/test-verify.sh [verify.sh]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SH="${1:-$HERE/verify.sh}"
COUNT=1000
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; failures=$((failures + 1)); }

# $COUNT recibos distintos, firmados por el hook en un estado temporal. No
# sirven copias de bundle/: verify.sh rechaza un recibo repetido (mismo
# evidence_id o mismo agent id y request_id), porque contaría una decisión
# varias veces.
cargo build --quiet --release --locked --manifest-path "$HERE/Cargo.toml"
BIN="$HERE/target/release/praetore-claude-hook"
mkdir -p "$WORK/proyecto" "$WORK/home"
PROJECT="$(cd "$WORK/proyecto" && pwd -P)"
STATE="$WORK/state"
HOME="$WORK/home" "$BIN" init "$STATE" --root "$PROJECT" --valid-days 30 >/dev/null
i=0
while [ "$i" -lt "$COUNT" ]; do
  printf '{"hook_event_name":"PreToolUse","tool_name":"Read","agent_type":"explorer","tool_use_id":"t%04d","cwd":"%s","tool_input":{"file_path":"%s/f%04d.txt"}}' \
    "$i" "$PROJECT" "$PROJECT" "$i" | "$BIN" hook "$STATE" >/dev/null
  i=$((i + 1))
done
# Un directorio de nombre largo: el listado de nombres debe pasar de 64 KiB,
# el buffer de un pipe, para que `ls | head` hubiera recibido SIGPIPE.
SIGNED="$WORK/bundle-firmado-con-mil-recibos-distintos-y-nombres-largos"
"$BIN" export "$STATE" "$SIGNED" >/dev/null

make_bundle() {
  cp -R "$SIGNED" "$1"
}

run_verify() {
  local bundle="$1" log="$2"
  set +e
  "$VERIFY_SH" "$bundle" >"$log" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

GOOD="$WORK/good-bundle-de-mil-recibos-distintos-con-nombres-largos"
make_bundle "$GOOD"
listing=$(printf '%s\n' "$GOOD"/evidence/*.json | wc -c | tr -d ' ')
echo "bundle con $COUNT recibos ($listing bytes de nombres; el buffer de un pipe es 64 KiB)"
[ "$listing" -gt 65536 ] || fail "el listado tiene $listing bytes: no pasa de 64 KiB"

rc=$(run_verify "$GOOD" "$WORK/good.log")
if [ "$rc" -eq 0 ] && grep -q "OK: $COUNT recibos verificados" "$WORK/good.log"; then
  pass "$COUNT recibos válidos: exit 0"
else
  fail "$COUNT recibos válidos: exit $rc (esperado 0)"
  tail -20 "$WORK/good.log"
fi

make_bundle "$WORK/tampered"
victim="$(printf '%s/evidence/%04d-' "$WORK/tampered" 737)"
victim=$(echo "$victim"*)
python3 - "$victim" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
offset = data.index(b'"outcome":"') + len('"outcome":"')
data[offset] ^= 0x20
open(path, "wb").write(data)
PY
rc=$(run_verify "$WORK/tampered" "$WORK/tampered.log")
if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ] && grep -q "FALLO: $(basename "$victim") no verificó" "$WORK/tampered.log"; then
  pass "1 recibo alterado entre $COUNT: exit $rc, nombra $(basename "$victim")"
else
  fail "1 recibo alterado entre $COUNT: exit $rc (esperado distinto de 0, y no 141)"
  tail -20 "$WORK/tampered.log"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures test(s) fallaron"
  exit 1
fi
echo "todos los tests pasaron"
