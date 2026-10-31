# Verifying the hook evidence

Run from the root of a clone. Requirements: Rust stable (cargo) and python3.
Only public keys are used. Outputs below were obtained by running these exact
commands on 2026-10-31 (Linux x86_64, `praetore-verify` 0.3.0 built from this
branch).

What a passing check proves: each receipt is intact, its attester signature
matches the pinned attester public key, its authority was signed by the pinned
issuer, its intent was signed by the agent profile key, and its
`policy_digest` equals the published `policy.json`. The keys ship with the
evidence, so this proves **integrity, not the identity of the signer**. It
says nothing about tool calls that did not go through the hook, nor about
whether the authority is valid today (`current_authorization=false`).

## 1. Build the verifier

```sh
cargo build --release --locked --package praetore-verify
V=target/release/praetore-verify
```

## 2. Whole set (script)

`verify.sh` checks every receipt of a set, its policy digest binding, a copy
with one altered byte, and prints a summary from `index.json`.

```sh
./examples/claude-code-hook/verify.sh examples/claude-code-hook/evidence/05-sesion-real-final
./examples/claude-code-hook/verify.sh examples/claude-code-hook/evidence/04-sesion-real-bloqueada-web-fetch
./examples/claude-code-hook/verify.sh examples/claude-code-hook/evidence/03-bundle-demo-reproducible
```

Real output, set 05:

```text
== 1. Compilar praetore-verify (cargo build --release --locked)

== 2. Digest de la policy publicada
policy.json -> 60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68

== 3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada e intención
OK: 118 recibos verificados, todos ligados a la policy publicada

== 4. Alterar UN byte de una copia de un recibo y comprobar que falla
0001-main-Glob-Allow.json: decision.outcome alterado en el byte 1655
{"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"}
OK: la copia alterada fue rechazada (exit 1)

== 5. Resumen por agente y decisión (de index.json)
coder     Allow            47
coder     RequireApproval  1
explorer  Allow            19
main      Allow            16
planner   Allow            5
web-fetch Allow            30
total: Allow 117, RequireApproval 1

== RESULTADO: todas las verificaciones dieron lo esperado
```

Real output, set 04:

```text
== 1. Compilar praetore-verify (cargo build --release --locked)

== 2. Digest de la policy publicada
policy.json -> 60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68

== 3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada e intención
OK: 8 recibos verificados, todos ligados a la policy publicada

== 4. Alterar UN byte de una copia de un recibo y comprobar que falla
0001-main-Glob-Allow.json: decision.outcome alterado en el byte 1647
{"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"}
OK: la copia alterada fue rechazada (exit 1)

== 5. Resumen por agente y decisión (de index.json)
main      Allow            8
total: Allow 8

== RESULTADO: todas las verificaciones dieron lo esperado
```

Real output, set 03:

```text
== 1. Compilar praetore-verify (cargo build --release --locked)

== 2. Digest de la policy publicada
policy.json -> 03f5e97499562eb2abc4ad1a4a2b1cc728a4907089d9d369a36d6a6b3ea102c3

== 3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada e intención
OK: 22 recibos verificados, todos ligados a la policy publicada

== 4. Alterar UN byte de una copia de un recibo y comprobar que falla
0001-explorer-Read-Allow.json: decision.outcome alterado en el byte 1886
{"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"}
OK: la copia alterada fue rechazada (exit 1)

== 5. Resumen por agente y decisión (de index.json)
coder     Allow            2
coder     Deny             4
coder     RequireApproval  5
explorer  Allow            1
explorer  Deny             4
general-purpose Deny             1
main      RequireApproval  1
planner   Allow            1
planner   Deny             1
web-fetch Allow            1
web-fetch Deny             1
total: Allow 5, Deny 11, RequireApproval 6

== RESULTADO: todas las verificaciones dieron lo esperado
```

## 3. One receipt by hand

```sh
E=examples/claude-code-hook/evidence/05-sesion-real-final
$V policy-digest --policy $E/policy.json
$V evidence --evidence $E/evidence/0093-coder-Bash-RequireApproval.json \
  --attester-pin $E/attester-public-key.hex \
  --issuer-pins $E/issuer-pins.jsonl --require-intent
echo "exit $?"
```

Real output:

```text
OK policy-digest OK digest="60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68" policy_id="claude-code-agents" policy_version=1
OK evidence OK authority_verified=true current_authorization=false evidence_id="2d619485-e1d3-48a5-88ff-97fae15cc038" intent_verified=true verification_scope="historical_receipt_integrity_and_attestation"
exit 0
```

Sets 03 and 04 use the same flags with their own folder. Policy digests:
03 `03f5e97499562eb2abc4ad1a4a2b1cc728a4907089d9d369a36d6a6b3ea102c3`,
04 and 05 `60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68`
(04 and 05 ran the same policy on the same project root).

## 4. Alter one byte

```sh
cp $E/evidence/0093-coder-Bash-RequireApproval.json /tmp/tampered.json
python3 - <<'PY'
d = bytearray(open("/tmp/tampered.json", "rb").read())
o = d.index(b'"outcome":"') + len('"outcome":"')
d[o] ^= 0x20   # "RequireApproval" -> "requireApproval"
open("/tmp/tampered.json", "wb").write(d)
PY
cmp -l $E/evidence/0093-coder-Bash-RequireApproval.json /tmp/tampered.json
$V evidence --evidence /tmp/tampered.json \
  --attester-pin $E/attester-public-key.hex \
  --issuer-pins $E/issuer-pins.jsonl --require-intent
echo "exit $?"
```

Real output (one byte differs, the copy is rejected):

```text
3582 122 162
ERROR evidence EVIDENCE_FAIL
exit 1
```

## 5. Sets 01 and 02: not verifiable

[`unverified-v0/`](unverified-v0/) holds sets 01 and 02, written by hook v0
without an attester signature or attester key. `praetore-verify evidence`
requires an attester pin, so these sets **cannot be verified** with it, and
nothing else in this repository verifies them. CI skips them. They are kept as
a historical record only.

## CI

The `hook-evidence` job in `.github/workflows/assurance.yml` runs
`verify.sh` on sets 03, 04 and 05 and fails if any of them does not verify.
