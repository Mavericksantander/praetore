#!/usr/bin/env bash
# Test end to end de la atribución por agente (SAF-14). Regenera un bundle con
# demo.sh y comprueba con verify.sh (solo llaves públicas):
#   1. el bundle verifica;
#   2. coder y explorer firman con identidades distintas, cada una con una
#      autoridad que el emisor emitió para ese perfil;
#   3. ninguna de estas copias re-atribuye un recibo del explorer al coder:
#      a. editar agent/profile en index.json;
#      b. editar context.agent/context.profile dentro del recibo;
#      c. poner en el recibo la identidad y la autoridad del coder.
# Uso, desde la raíz de un clon:
#   ./examples/claude-code-hook/test-attribution.sh [verify.sh]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SH="${1:-$HERE/verify.sh}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; failures=$((failures + 1)); }

"$HERE/demo.sh" "$WORK/bundle" >"$WORK/demo.log" 2>&1 || {
  tail -20 "$WORK/demo.log"
  echo "demo.sh falló" >&2
  exit 2
}

verify() {
  set +e
  "$VERIFY_SH" "$1" >"$2" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

rc=$(verify "$WORK/bundle" "$WORK/good.log")
if [ "$rc" -eq 0 ]; then
  pass "el bundle regenerado verifica (exit 0)"
else
  fail "el bundle regenerado no verifica (exit $rc)"
  tail -20 "$WORK/good.log"
fi

# 2. Identidades por agente, leídas de los recibos firmados.
if python3 -I - "$WORK/bundle" <<'PY'; then
import json, sys
bundle = sys.argv[1]
index = json.load(open(f"{bundle}/index.json"))
def first(agent):
    entry = next(e for e in index if e["agent"] == agent)
    return json.load(open(f"{bundle}/{entry['file']}"))
coder, explorer = first("coder"), first("explorer")
for name, ev in (("coder", coder), ("explorer", explorer)):
    constraints = {c["key"]: c["value"] for c in ev["authority"]["constraints"]}
    print(f"{name:<9} agent id {ev['agent']['id']}  autoridad emitida para "
          f"{constraints.get('praetore.agent_profile')!r}  capacidades {ev['authority']['capabilities']}")
    assert ev["authority"]["subject"] == ev["agent"]["id"], name
    assert constraints.get("praetore.agent_profile") == name, f"{name}: sin perfil firmado por el emisor"
assert coder["agent"]["id"] != explorer["agent"]["id"], "mismo agent id"
assert coder["agent"]["public_key"] != explorer["agent"]["public_key"], "misma llave"
PY
  pass "coder y explorer firman con identidades y autoridades distintas"
else
  fail "coder y explorer no tienen identidades propias emitidas para su perfil"
fi

# 3. Copias que intentan atribuir al coder un recibo del explorer.
tamper() {
  local name="$1" script="$2" copy="$WORK/$1"
  cp -R "$WORK/bundle" "$copy"
  python3 -I - "$copy" <<PY
import json, sys
bundle = sys.argv[1]
index = json.load(open(f"{bundle}/index.json"))
victim = next(e for e in index if e["agent"] == "explorer")
donor = next(e for e in index if e["agent"] == "coder")
path = f"{bundle}/{victim['file']}"
ev = json.load(open(path))
donor_ev = json.load(open(f"{bundle}/{donor['file']}"))
$script
json.dump(index, open(f"{bundle}/index.json", "w"), indent=2)
open(path, "w").write(json.dumps(ev, separators=(",", ":"), sort_keys=True))
print(victim["file"])
PY
  rc=$(verify "$copy" "$WORK/$name.log")
  if [ "$rc" -ne 0 ]; then
    pass "$name: rechazado (exit $rc): $(grep -m1 'FALLO' "$WORK/$name.log" || true)"
  else
    fail "$name: la copia re-atribuida fue aceptada"
  fi
}

tamper index-json 'victim["agent"] = "coder"; victim["profile"] = "coder"; victim.pop("agent_id", None)'
tamper signed-context 'ev["context"]["agent"] = "coder"; ev["context"]["profile"] = "coder"; victim["agent"] = "coder"; victim["profile"] = "coder"'
tamper swapped-identity 'ev["agent"] = donor_ev["agent"]; ev["authority"] = donor_ev["authority"]; victim["agent"] = "coder"; victim["profile"] = "coder"; victim.pop("agent_id", None)'

if [ "$failures" -ne 0 ]; then
  echo "$failures test(s) fallaron"
  exit 1
fi
echo "todos los tests pasaron"
