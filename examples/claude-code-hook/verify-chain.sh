#!/usr/bin/env bash
# Verifica la cadena JSONL (journal-chain.jsonl) de un set de evidencia del
# hook y comprueba que copias manipuladas se rechazan. Solo usa llaves
# públicas. Formato: docs/proposals/journal-chain-jsonl.md.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/verify-chain.sh <set> <head esperado>
# El head esperado debe venir de una fuente que no sea el propio set (por
# ejemplo VERIFY.md o, mejor, una copia publicada fuera del repo).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SET="$(cd "${1:?falta el set}" && pwd)"
HEAD="${2:?falta el head esperado}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FALLO: %s\n' "$*" >&2; exit 1; }

step "1. Compilar praetore y praetore-verify (cargo build --release --locked)"
cargo build --quiet --release --locked --manifest-path "$ROOT/Cargo.toml" \
  --package praetore-verify --package praetore-cli
VERIFY="$ROOT/target/release/praetore-verify"
EXPORT="$ROOT/target/release/praetore"
CHAIN="$SET/journal-chain.jsonl"
PIN="$SET/attester-public-key.hex"

verify() { "$VERIFY" journal --journal "$1" --attester-pin "$PIN" --policy "$SET/policy.json" \
  --expected-head "$HEAD" --format json; }

# expect_reject <archivo> <código esperado> <descripción>
expect_reject() {
  set +e
  OUT="$(verify "$1" 2>"$WORK/stderr")"
  STATUS=$?
  set -e
  echo "$OUT"
  [ "$STATUS" -ne 0 ] || fail "$3: la copia fue aceptada"
  echo "$OUT" | grep -q "\"code\":\"$2\"" || fail "$3: código distinto de $2"
  [ -s "$WORK/stderr" ] || fail "$3: sin mensaje de error en stderr"
  echo "stderr: $(cat "$WORK/stderr")"
  echo "OK: $3 rechazada (exit $STATUS)"
}

step "2. Verificar la cadena publicada contra el head esperado"
verify "$CHAIN" || fail "la cadena publicada no verificó"

step "3. Reproducir: exportar de nuevo desde evidence/ y comparar byte a byte"
"$EXPORT" journal-export --receipts-dir "$SET/evidence" --attester-pin "$PIN" --output "$WORK/again.jsonl"
cmp "$CHAIN" "$WORK/again.jsonl" || fail "la exportación no es reproducible"
echo "OK: idéntica a journal-chain.jsonl"

step "4. Copia con un recibo borrado (línea 2 eliminada, sin recalcular)"
sed '2d' "$CHAIN" >"$WORK/deleted.jsonl"
expect_reject "$WORK/deleted.jsonl" JOURNAL_CHAIN_FAIL "copia con un recibo borrado"

step "5. Copia con un recibo borrado y la cadena recalculada (sin llave privada)"
mkdir "$WORK/subset"
cp "$SET"/evidence/*.json "$WORK/subset/"
rm "$(ls "$WORK"/subset/*.json | sed -n 2p)"
"$EXPORT" journal-export --receipts-dir "$WORK/subset" --attester-pin "$PIN" --output "$WORK/relinked.jsonl" >/dev/null
expect_reject "$WORK/relinked.jsonl" JOURNAL_HEAD_MISMATCH "copia recalculada sin un recibo"

step "6. Copia truncada (sin la última línea)"
sed '$d' "$CHAIN" >"$WORK/truncated.jsonl"
expect_reject "$WORK/truncated.jsonl" JOURNAL_HEAD_MISMATCH "copia truncada"

step "7. Copia con dos líneas intercambiadas"
python3 - "$CHAIN" "$WORK/reordered.jsonl" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines(keepends=True)
lines[1], lines[2] = lines[2], lines[1]
open(sys.argv[2], "w").write("".join(lines))
PY
expect_reject "$WORK/reordered.jsonl" JOURNAL_CHAIN_FAIL "copia reordenada"

step "8. Copia con un byte alterado en un recibo"
python3 - "$CHAIN" "$WORK/altered.jsonl" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
# Primera letra de decision.reason, cambiada de mayúscula a minúscula: el
# JSON sigue siendo válido, pero el contenido firmado cambia.
offset = data.index(b'"reason":"') + len('"reason":"')
data[offset] ^= 0x20
print(f"entrada seq=0: decision.reason alterado en el byte {offset}")
open(sys.argv[2], "wb").write(data)
PY
expect_reject "$WORK/altered.jsonl" EVIDENCE_FAIL "copia con un recibo alterado"

printf '\n== RESULTADO: cadena verificada (%s entradas) y 5 copias manipuladas rechazadas\n' "$(wc -l <"$CHAIN" | tr -d ' ')"
