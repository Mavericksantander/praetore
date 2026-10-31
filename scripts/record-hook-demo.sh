#!/usr/bin/env bash
# Graba el demo de examples/claude-code-hook como GIF (docs/img/hook-demo.gif):
# una llamada allow, una deny y una approval; luego praetore-verify da OK y
# después rechaza una copia de un recibo con un byte alterado.
# Requisitos: cargo, python3, asciinema (2.x) y agg.
# Uso, desde la raíz de un clon:  ./scripts/record-hook-demo.sh
#
# CLAVES DE PRUEBA: todas las claves se generan en un directorio temporal
# llamado DEMO-TEST-KEYS-*, solo para este demo, y se borran al salir.
# No son claves de ningún despliegue.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_DIR="$ROOT/examples/claude-code-hook"

if [ "${1:-}" = "--scene" ]; then
  # Escena que se graba. Recibe los binarios ya compilados por entorno.
  WORK="$2"
  say() { printf '\n\033[1;36m$ %s\033[0m\n' "$*"; sleep 0.6; }
  PROJECT="$WORK/proyecto"; STATE="$PROJECT/.claude/praetore"
  echo "# Demo PRÆTORE + hook de Claude Code (claves de PRUEBA en DEMO-TEST-KEYS-*)"
  HOME="$WORK/home" "$HOOK_BIN" init "$STATE" --root "$PROJECT" --valid-days 30 >/dev/null
  export CLAUDE_PROJECT_DIR="$PROJECT" PRAETORE_HOOK_BIN="$HOOK_BIN"
  call() {
    say "$1 → $2 $4"
    python3 -c '
import json, sys
agent, tool, ti, cwd = sys.argv[1:]
print(json.dumps({"hook_event_name":"PreToolUse","tool_name":tool,"tool_input":json.loads(ti),"cwd":cwd,"tool_use_id":"demo","agent_type":agent}))' \
      "$1" "$2" "$3" "$PROJECT" | "$HOOK_DIR/hook/praetore-hook.sh" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("  decisión: ALLOW (el hook no bloquea)")
else:
    o = json.loads(raw)["hookSpecificOutput"]
    label = {"deny": "DENY", "ask": "REQUIRE_APPROVAL"}[o["permissionDecision"]]
    print("  decisión:", label, "-", o["permissionDecisionReason"][:80])'
    sleep 1
  }
  P="$PROJECT"
  call explorer Read  "{\"file_path\":\"$P/README.md\"}" "README.md"
  call coder    Write "{\"file_path\":\"$P/.git/config\"}" ".git/config"
  call coder    Bash  '{"command":"git push origin main"}' "git push origin main"
  HOME="$WORK/home" "$HOOK_BIN" export "$STATE" "$WORK/bundle" >/dev/null
  B="$WORK/bundle"
  say "praetore-verify evidence (offline, solo claves públicas)"
  n=0
  for e in "$B"/evidence/*.json; do
    "$VERIFY_BIN" evidence --evidence "$e" --attester-pin "$B/attester-public-key.hex" \
      --issuer-pins "$B/issuer-pins.jsonl" --require-intent --format json >/dev/null
    n=$((n + 1))
  done
  echo "  OK: $n recibos verificados"
  sleep 1
  say "alterar 1 byte de una copia de un recibo y volver a verificar"
  python3 - "$(ls "$B"/evidence/*.json | head -1)" "$WORK/tampered.json" <<'PY'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
i = d.index(b'"outcome":"') + len('"outcome":"')
d[i] ^= 0x20
open(sys.argv[2], "wb").write(d)
print(f"  byte {i} alterado (decision.outcome)")
PY
  set +e
  "$VERIFY_BIN" evidence --evidence "$WORK/tampered.json" --attester-pin "$B/attester-public-key.hex" \
    --issuer-pins "$B/issuer-pins.jsonl" --require-intent --format json >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || { echo "  ERROR: la copia alterada verificó"; exit 1; }
  echo "  RECHAZADO: praetore-verify devolvió exit $rc"
  sleep 2
  exit 0
fi

OUT="${1:-$ROOT/docs/img/hook-demo.gif}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/DEMO-TEST-KEYS-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/proyecto/.claude" "$WORK/home"
WORK="$(cd "$WORK" && pwd -P)"

cargo build --quiet --release --locked --manifest-path "$HOOK_DIR/Cargo.toml"
cargo build --quiet --release --locked --manifest-path "$ROOT/Cargo.toml" --package praetore-verify
export HOOK_BIN="$HOOK_DIR/target/release/praetore-claude-hook"
export VERIFY_BIN="$ROOT/target/release/praetore-verify"

asciinema rec --overwrite --quiet --cols 110 --rows 24 \
  --command "bash '$ROOT/scripts/record-hook-demo.sh' --scene '$WORK'" "$WORK/demo.cast"
agg --font-size 14 --idle-time-limit 2 "$WORK/demo.cast" "$OUT"
echo "GIF en $OUT"
