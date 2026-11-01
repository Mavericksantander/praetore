#!/usr/bin/env bash
# Regenera bundle/: pasa un conjunto fijo de tool calls de Claude Code por el
# hook de PRÆTORE y exporta los recibos firmados.
# Requisitos: cargo (Rust stable) y python3.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/demo.sh [directorio-de-salida]
# Por defecto escribe examples/claude-code-hook/bundle (lo reemplaza).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/bundle}"
WORK="$(mktemp -d)"
# Las claves privadas del demo viven solo en $WORK y se borran al salir.
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n== %s\n' "$*"; }

step "1. Compilar el hook (cargo build --release --locked)"
cargo build --quiet --release --locked --manifest-path "$HERE/Cargo.toml"
BIN="$HERE/target/release/praetore-claude-hook"

step "2. Crear un proyecto vacío y emitir claves, autoridades y policy"
mkdir -p "$WORK/proyecto/.claude" "$WORK/home"
PROJECT="$(cd "$WORK/proyecto" && pwd -P)"
STATE="$PROJECT/.claude/praetore"
# HOME temporal: la policy incluye $HOME/.claude/projects y no debe llevar
# rutas de quien regenera el bundle.
HOME="$WORK/home" "$BIN" init "$STATE" --root "$PROJECT" --valid-days 3650

# Un symlink dentro del proyecto que apunta afuera: el hook resuelve la ruta
# antes de evaluar, así que no deja leer por ahí.
ln -s /etc "$PROJECT/enlace-afuera"

step "3. Pasar tool calls por el hook (mismo wrapper que usa Claude Code)"
export CLAUDE_PROJECT_DIR="$PROJECT" PRAETORE_HOOK_BIN="$BIN"
call() {
  local agent="$1" tool="$2" input="$3"
  python3 -c '
import json, sys
agent, tool, tool_input, cwd = sys.argv[1:]
event = {"hook_event_name": "PreToolUse", "tool_name": tool,
         "tool_input": json.loads(tool_input), "cwd": cwd,
         "tool_use_id": "demo"}
if agent != "main":
    event["agent_type"] = agent
print(json.dumps(event))' "$agent" "$tool" "$input" "$PROJECT" |
    "$HERE/hook/praetore-hook.sh" |
    python3 -c '
import json, sys
agent, tool, summary = sys.argv[1:]
raw = sys.stdin.read().strip()
if raw:
    out = json.loads(raw)["hookSpecificOutput"]
    decision, reason = out["permissionDecision"], out["permissionDecisionReason"]
else:
    decision, reason = "allow", "(sin decisión: siguen los permisos de Claude Code)"
print(f"{agent:<16} {tool:<9} {summary:<34} {decision:<6} {reason[:90]}")' "$agent" "$tool" "$4"
}
P="$PROJECT"
call explorer Read  "{\"file_path\":\"$P/README.md\"}"            "lee README.md"
call planner  Read  "{\"file_path\":\"$P/src/main.rs\"}"          "lee src/main.rs"
call explorer Bash  '{"command":"ls"}'                            "ejecuta ls"
call planner  Write "{\"file_path\":\"$P/docs/plan.md\"}"         "escribe docs/plan.md"
call coder    Write "{\"file_path\":\"$P/src/main.rs\"}"          "escribe src/main.rs"
call coder    Edit  "{\"file_path\":\"$P/.claude/agents/coder.md\"}" "edita su propia definición"
call main     Edit  "{\"file_path\":\"$P/.claude/settings.json\"}"   "edita la configuración"
call coder    Write "{\"file_path\":\"$P/.git/config\"}"          "escribe .git/config"
call coder    Bash  '{"command":"cargo test"}'                    "ejecuta cargo test"
call coder    Bash  '{"command":"git push origin main"}'          "git push"
call coder    Bash  '{"command":"cd app && git push"}'            "cd app && git push"
call coder    Bash  '{"command":"git -C ../otro push --force"}'   "git -C ../otro push"
call coder    Bash  '{"command":"$(echo git) push"}'              "\$(echo git) push"
call coder    Bash  "{\"command\":\"bash -c 'git push'\"}"        "bash -c 'git push'"
call coder    WebFetch '{"url":"https://example.com"}'            "usa la red"
call coder    Agent '{"subagent_type":"coder"}'                   "delega a otro agente"
call explorer Read  '{"file_path":"/etc/passwd"}'                 "lee fuera del proyecto"
call explorer Read  '{"file_path":"../fuera.txt"}'                "lee con ruta relativa .."
call explorer Read  "{\"file_path\":\"$P/enlace-afuera/passwd\"}" "lee por un symlink que sale"
call general-purpose Read "{\"file_path\":\"$P/README.md\"}"      "agente sin autoridad"
call web-fetch WebFetch '{"url":"https://example.com"}'          "lector web: usa la red"
call web-fetch Read "{\"file_path\":\"$P/README.md\"}"         "lector web: lee un archivo"

step "4. Verificar los recibos con el propio hook y exportar el bundle"
"$BIN" verify "$STATE"
rm -rf "$OUT"
"$BIN" export "$STATE" "$OUT"

step "5. Comprobar que cada recibo es HighAssurance (hora de decisión firmada)"
python3 -I - "$OUT" <<'PY'
import json, pathlib, sys
receipts = sorted(pathlib.Path(sys.argv[1], "evidence").glob("*.json"))
missing = [r.name for r in receipts
           if json.loads(r.read_text()).get("evaluation_mode") != "high_assurance"
           or not json.loads(r.read_text()).get("decided_at")]
if not receipts or missing:
    sys.exit(f"recibos sin decided_at: {missing or 'ninguno exportado'}")
print(f"OK: {len(receipts)} recibos HighAssurance, todos con decided_at")
PY
echo "Bundle en $OUT. Verifícalo con: ./examples/claude-code-hook/verify.sh $OUT --require-decision-time"
