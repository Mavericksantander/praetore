#!/usr/bin/env bash
# Verificación por terceros de los recibos del hook de Claude Code con
# praetore-verify. No usa el binario del hook ni ninguna clave privada.
# Requisitos: cargo (Rust stable) y python3.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/verify.sh [bundle]
# Por defecto verifica examples/claude-code-hook/bundle.
# Sale con 0 solo si praetore-verify acepta todos los recibos (con la policy
# publicada) y rechaza la copia alterada; con 1 en cualquier otro caso.
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

step "3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada, intención y policy"
# Glob a un array, sin `ls | head`: con cientos de recibos, `head` cerraba el
# pipe, `ls` recibía SIGPIPE y pipefail hacía salir el script con 141 aunque
# todo hubiera verificado.
shopt -s nullglob
receipts=("$BUNDLE"/evidence/*.json)
shopt -u nullglob
[ "${#receipts[@]}" -gt 0 ] || fail "el bundle no tiene recibos"
for evidence in "${receipts[@]}"; do
  # --policy: praetore-verify exige que el recibo registre el digest de la
  # policy publicada.
  "$VERIFY" evidence \
    --evidence "$evidence" \
    --attester-pin "$BUNDLE/attester-public-key.hex" \
    --issuer-pins "$BUNDLE/issuer-pins.jsonl" \
    --require-intent \
    --policy "$BUNDLE/policy.json" \
    --format json >/dev/null || fail "$(basename "$evidence") no verificó"
done
echo "OK: ${#receipts[@]} recibos verificados, todos ligados a la policy publicada"

step "4. Alterar UN byte de una copia de un recibo y comprobar que falla"
SAMPLE="${receipts[0]}"
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

step "5. Resumen por agente y decisión (de index.json, solo informativo)"
# No cambia el código de salida: index.json no está firmado y el resultado ya
# lo dieron los pasos 3 y 4.
python3 - "$BUNDLE/index.json" <<'PY' || echo "aviso: no se pudo resumir index.json"
import collections, json, sys
index = json.load(open(sys.argv[1]))
tally = collections.Counter((e["agent"], e["outcome"]) for e in index)
for (agent, outcome), n in sorted(tally.items()):
    print(f"{agent:<9} {outcome:<16} {n}")
totals = collections.Counter(e["outcome"] for e in index)
print("total:", ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
PY

step "RESULTADO: todas las verificaciones dieron lo esperado"
