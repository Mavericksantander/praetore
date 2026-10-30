#!/usr/bin/env bash
# Verificación por terceros del bundle DEMO de PRÆTORE con praetore-verify.
# Requisitos: git, cargo (Rust stable) y python3. Todo gratuito.
# Uso, desde la raíz de un clon limpio:
#   ./examples/third-party-verification/verify.sh
# Variables opcionales:
#   PRAETORE_SKIP_PYTHON=1  omite el verificador Python (no instala nada).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$ROOT/examples/third-party-verification/bundle"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$ROOT"

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FALLO: %s\n' "$*" >&2; exit 1; }

step "1. Compilar praetore-verify (cargo build --release --locked)"
cargo build --quiet --release --locked --package praetore-verify
VERIFY="$ROOT/target/release/praetore-verify"

step "2. Verificar el bundle: integridad, firma del atestador, autoridad pineada e intención del agente"
"$VERIFY" evidence \
  --evidence "$BUNDLE/evidence.json" \
  --attester-pin "$BUNDLE/attester-public-key.hex" \
  --issuer-pins "$BUNDLE/issuer-pins.jsonl" \
  --require-intent \
  --format json || fail "el bundle válido no verificó"

step "3. Comparar el digest de la política publicada con el digest ligado en la evidencia"
POLICY_DIGEST="$("$VERIFY" policy-digest --policy "$BUNDLE/policy.json" --format json |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["details"]["digest"])')"
BOUND_DIGEST="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["policy_digest"])' \
  "$BUNDLE/evidence.json")"
echo "policy.json         -> $POLICY_DIGEST"
echo "evidence.policy_digest -> $BOUND_DIGEST"
[ "$POLICY_DIGEST" = "$BOUND_DIGEST" ] || fail "el digest de la política no coincide"
echo "OK: coinciden"
# Lo mismo, hecho por el verificador: la firma del atestador cubre el digest.
"$VERIFY" evidence \
  --evidence "$BUNDLE/evidence.json" \
  --attester-pin "$BUNDLE/attester-public-key.hex" \
  --policy "$BUNDLE/policy.json" \
  --format json || fail "evidence --policy no verificó"

step "4. Verificar la autoridad sola, ligada a la identidad del agente (fecha fija 2026-10-24T00:00:00Z)"
"$VERIFY" authority \
  --authority "$BUNDLE/authority.json" \
  --issuer-pins "$BUNDLE/issuer-pins.jsonl" \
  --agent "$BUNDLE/agent.json" \
  --now 2026-10-24T00:00:00Z \
  --format json || fail "la autoridad no verificó"

step "5. Alterar UN byte de una copia y comprobar que la verificación falla"
python3 - "$BUNDLE/evidence.json" "$WORK/evidence-tampered.json" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
offset = data.index(b"DEMO allow") + len("DEMO ")
old = data[offset]
data[offset] = ord("A")  # "allow" -> "Allow" en decision.reason
open(sys.argv[2], "wb").write(data)
print(f"byte {offset}: {chr(old)!r} -> 'A' (decision.reason)")
PY
# cmp devuelve 1 cuando los archivos difieren; aquí eso es lo esperado.
DIFF_BYTES="$( (cmp -l "$BUNDLE/evidence.json" "$WORK/evidence-tampered.json" || true) | wc -l)"
echo "bytes distintos: $DIFF_BYTES"
[ "$DIFF_BYTES" -eq 1 ] || fail "se esperaba exactamente 1 byte distinto"
set +e
"$VERIFY" evidence \
  --evidence "$WORK/evidence-tampered.json" \
  --attester-pin "$BUNDLE/attester-public-key.hex" \
  --issuer-pins "$BUNDLE/issuer-pins.jsonl" \
  --require-intent \
  --format json
TAMPER_RC=$?
set -e
[ "$TAMPER_RC" -ne 0 ] || fail "la copia alterada verificó (no debería)"
echo "OK: la copia alterada fue rechazada (exit $TAMPER_RC), como se esperaba"

step "6. Verificador Python (paquete praetore de packages/praetore-python)"
if [ "${PRAETORE_SKIP_PYTHON:-0}" = "1" ]; then
  echo "OMITIDO: PRAETORE_SKIP_PYTHON=1"
else
  python3 -m venv "$WORK/venv"
  "$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check \
    "$ROOT/packages/praetore-python"
  "$WORK/venv/bin/python" - "$BUNDLE" "$WORK/evidence-tampered.json" <<'PY'
import sys
from pathlib import Path
import praetore

bundle, tampered_path = Path(sys.argv[1]), Path(sys.argv[2])
evidence = (bundle / "evidence.json").read_text(encoding="utf-8")
pin = (bundle / "attester-public-key.hex").read_text(encoding="ascii").strip()
tampered = tampered_path.read_text(encoding="utf-8")

results = {
    "integrity(valid)": praetore.verify_evidence_integrity(evidence),
    "attester_signature(valid)": praetore.verify_evidence_attester_signature(evidence, pin),
    "integrity(tampered)": praetore.verify_evidence_integrity(tampered),
    "attester_signature(tampered)": praetore.verify_evidence_attester_signature(tampered, pin),
}
for name, value in results.items():
    print(f"{name}: {value}")
expected = [True, True, False, False]
if list(results.values()) != expected:
    sys.exit("FALLO: el verificador Python no dio el resultado esperado")
print("OK: Python acepta el bundle y rechaza la copia alterada")
PY
fi

step "RESULTADO: todas las verificaciones dieron lo esperado"
