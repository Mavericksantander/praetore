#!/usr/bin/env bash
# Verificación por terceros de los recibos del hook de Claude Code con
# praetore-verify. No usa el binario del hook ni ninguna clave privada.
# Requisitos: cargo (Rust stable) y python3.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/verify.sh [bundle]
# Por defecto verifica examples/claude-code-hook/bundle.
# Sale con 0 solo si praetore-verify acepta todos los recibos (con la policy
# publicada) y rechaza la copia alterada, e index.json atribuye cada recibo al
# agente que lo firmó y una copia re-atribuida se rechaza; con 1 en cualquier
# otro caso.
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
# Con dotglob el glob incluye los archivos ocultos. Cualquier entrada que no
# sea un archivo regular *.json no oculto hace fallar: así este paso y
# check-attribution.py (paso 5, misma regla) leen exactamente los mismos
# archivos y ninguno queda sin verificar.
shopt -s nullglob dotglob
receipts=("$BUNDLE"/evidence/*)
shopt -u nullglob dotglob
for entry in "${receipts[@]}"; do
  name="$(basename "$entry")"
  if [[ "$name" == .* || "$name" != *.json || -L "$entry" || ! -f "$entry" ]]; then
    fail "evidence/$name: entrada no permitida (solo archivos regulares *.json no ocultos)"
  fi
done
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

step "5. Atribución: index.json debe decir lo mismo que los recibos firmados"
# index.json y los nombres de archivo no están firmados. check-attribution.py
# lee los recibos que el paso 3 verificó y exige que index.json nombre el
# mismo agente, perfil y agent id; una identidad por perfil.
python3 -I "$HERE/check-attribution.py" "$BUNDLE" ||
  fail "index.json no coincide con los recibos firmados"
echo "OK: cada recibo queda atribuido a la identidad que lo firmó"

step "6. Re-atribuir UN recibo en una copia de index.json y comprobar que falla"
python3 -I - "$BUNDLE/index.json" "$WORK/index-reattributed.json" <<'PY'
import json, sys
index = json.load(open(sys.argv[1]))
first = index[0]["agent"]
other = next((e["agent"] for e in index if e["agent"] != first), first + "-otro")
index[0]["agent"] = other
if index[0].get("profile") is not None:
    index[0]["profile"] = other
json.dump(index, open(sys.argv[2], "w"))
print(f"{index[0]['file']}: agent {first} -> {other}")
PY
if python3 -I "$HERE/check-attribution.py" "$BUNDLE" "$WORK/index-reattributed.json"; then
  fail "la copia re-atribuida de index.json fue aceptada (no debería)"
fi
echo "OK: la re-atribución fue rechazada"

step "RESULTADO: todas las verificaciones dieron lo esperado"
