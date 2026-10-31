#!/usr/bin/env bash
# Verificación por terceros de los recibos del hook de Claude Code con
# praetore-verify. No usa el binario del hook ni ninguna clave privada.
# Requisitos: cargo (Rust stable) y python3.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/verify.sh [bundle]
# Por defecto verifica examples/claude-code-hook/bundle.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUNDLE="$(cd "${1:-$HERE/bundle}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FALLO: %s\n' "$*" >&2; exit 1; }

step "1. Compilar praetore-verify (cargo build --release --locked)"
cargo build --quiet --release --locked --manifest-path "$ROOT/Cargo.toml" --package praetore-verify
VERIFY="$ROOT/target/release/praetore-verify"

step "2. Digest de la policy publicada"
POLICY_DIGEST="$("$VERIFY" policy-digest --policy "$BUNDLE/policy.json" --format json |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["details"]["digest"])')"
echo "policy.json -> $POLICY_DIGEST"

step "3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada e intención"
count=0
for evidence in "$BUNDLE"/evidence/*.json; do
  "$VERIFY" evidence \
    --evidence "$evidence" \
    --attester-pin "$BUNDLE/attester-public-key.hex" \
    --issuer-pins "$BUNDLE/issuer-pins.jsonl" \
    --require-intent \
    --format json >/dev/null || fail "$(basename "$evidence") no verificó"
  BOUND="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["policy_digest"])' "$evidence")"
  [ "$BOUND" = "$POLICY_DIGEST" ] || fail "$(basename "$evidence"): policy_digest distinto"
  count=$((count + 1))
done
[ "$count" -gt 0 ] || fail "el bundle no tiene recibos"
echo "OK: $count recibos verificados, todos ligados a la policy publicada"

step "4. Alterar UN byte de una copia de un recibo y comprobar que falla"
SAMPLE="$(ls "$BUNDLE"/evidence/*.json | head -1)"
python3 - "$SAMPLE" "$WORK/tampered.json" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
# Primera letra de decision.outcome (Allow, Deny o RequireApproval), en
# mayúscula pasa a minúscula: se rompe el contenido firmado.
offset = data.index(b'"outcome":"') + len('"outcome":"')
data[offset] = data[offset] ^ 0x20
open(sys.argv[2], "wb").write(data)
print(f"{sys.argv[1].rsplit('/', 1)[-1]}: decision.outcome alterado en el byte {offset}")
PY
set +e
"$VERIFY" evidence \
  --evidence "$WORK/tampered.json" \
  --attester-pin "$BUNDLE/attester-public-key.hex" \
  --issuer-pins "$BUNDLE/issuer-pins.jsonl" \
  --require-intent \
  --format json
TAMPER_RC=$?
set -e
[ "$TAMPER_RC" -ne 0 ] || fail "la copia alterada verificó (no debería)"
echo "OK: la copia alterada fue rechazada (exit $TAMPER_RC)"

step "5. Resumen por agente y decisión (de index.json)"
python3 - "$BUNDLE/index.json" <<'PY'
import collections, json, sys
index = json.load(open(sys.argv[1]))
tally = collections.Counter((e["agent"], e["outcome"]) for e in index)
for (agent, outcome), n in sorted(tally.items()):
    print(f"{agent:<9} {outcome:<16} {n}")
totals = collections.Counter(e["outcome"] for e in index)
print("total:", ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
PY

step "RESULTADO: todas las verificaciones dieron lo esperado"
