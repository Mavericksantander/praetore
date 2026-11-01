#!/usr/bin/env bash
# Test de verify.sh con un bundle grande. Arma, a partir de bundle/, uno con
# 1000 recibos (copias de los recibos firmados con otros nombres) y comprueba:
#   1. verify.sh sale con 0. Antes, `ls | head` recibía SIGPIPE y salía con 141.
#   2. con UN recibo alterado entre los 1000, sale distinto de 0 y nombra ese
#      recibo.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/test-verify.sh [verify.sh]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SH="${1:-$HERE/verify.sh}"
SOURCE="$HERE/bundle"
COUNT=1000
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; failures=$((failures + 1)); }

# Copia los metadatos del bundle y $COUNT recibos, recorriendo los firmados.
make_bundle() {
  local out="$1" i=0 n
  mkdir -p "$out/evidence"
  cp "$SOURCE/attester-public-key.hex" "$SOURCE/issuer-pins.jsonl" \
    "$SOURCE/policy.json" "$out/"
  shopt -s nullglob
  local signed=("$SOURCE"/evidence/*.json)
  shopt -u nullglob
  n=${#signed[@]}
  [ "$n" -gt 0 ] || { echo "no hay recibos en $SOURCE/evidence" >&2; exit 2; }
  while [ "$i" -lt "$COUNT" ]; do
    cp "${signed[$((i % n))]}" "$(printf '%s/evidence/r%04d-%s' "$out" "$i" "$(basename "${signed[$((i % n))]}")")"
    i=$((i + 1))
  done
  # index.json con una entrada por copia, la del recibo original: verify.sh
  # exige que index.json cubra cada recibo y lo atribuya a quien lo firmó.
  python3 -I - "$SOURCE/index.json" "$out" <<'PY'
import json, os, sys
source, out = sys.argv[1], sys.argv[2]
by_file = {os.path.basename(e["file"]): e for e in json.load(open(source))}
index = []
for name in sorted(os.listdir(os.path.join(out, "evidence"))):
    entry = dict(by_file[name.split("-", 1)[1]])
    entry["file"] = "evidence/" + name
    index.append(entry)
json.dump(index, open(os.path.join(out, "index.json"), "w"), indent=2)
PY
}

run_verify() {
  local bundle="$1" log="$2"
  set +e
  "$VERIFY_SH" "$bundle" >"$log" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

make_bundle "$WORK/good"
listing=$(printf '%s\n' "$WORK/good"/evidence/*.json | wc -c | tr -d ' ')
echo "bundle con $COUNT recibos ($listing bytes de nombres; el buffer de un pipe es 64 KiB)"

rc=$(run_verify "$WORK/good" "$WORK/good.log")
if [ "$rc" -eq 0 ] && grep -q "OK: $COUNT recibos verificados" "$WORK/good.log"; then
  pass "$COUNT recibos válidos: exit 0"
else
  fail "$COUNT recibos válidos: exit $rc (esperado 0)"
  tail -20 "$WORK/good.log"
fi

make_bundle "$WORK/tampered"
victim="$(printf '%s/evidence/r%04d-' "$WORK/tampered" 737)"
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
