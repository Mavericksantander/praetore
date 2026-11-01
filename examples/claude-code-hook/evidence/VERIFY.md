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
== 0. Copiar el bundle a un directorio temporal
copia de <repo>/examples/claude-code-hook/evidence/05-sesion-real-final en <tmp>/bundle

== 1. Compilar praetore-verify (cargo build --release --locked)

== 2. Digest de la policy publicada
policy.json -> 60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68

== 3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada, intención y policy
OK: 118 recibos verificados, todos ligados a la policy publicada

== 4. Alterar UN byte de una copia de un recibo y comprobar que falla
0001-main-Glob-Allow.json: decision.outcome alterado en el byte 1655
{"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"}
OK: la copia alterada fue rechazada (exit 1)

== 5. Atribución: index.json debe decir lo mismo que los recibos firmados
coder            Allow            47
coder            RequireApproval  1
explorer         Allow            19
main             Allow            16
planner          Allow            5
web-fetch        Allow            30
perfil coder        agent id bad89773-9990-498e-9240-805809788f62  (nombre del perfil firmado por: agente y atestador)
perfil explorer     agent id 95dde15e-513a-493d-9af7-4913c50be95a  (nombre del perfil firmado por: agente y atestador)
perfil main         agent id b8e04f81-6414-41b5-8b52-b671b64122b2  (nombre del perfil firmado por: agente y atestador)
perfil planner      agent id a096438a-de9d-4fdb-95f2-e088090071cf  (nombre del perfil firmado por: agente y atestador)
perfil web-fetch    agent id 6d0813bc-d924-4e09-a083-10fabf5b4c33  (nombre del perfil firmado por: agente y atestador)
OK: cada recibo queda atribuido a la identidad que lo firmó

== 6. Re-atribuir UN recibo en una copia de index.json y comprobar que falla
evidence/0001-main-Glob-Allow.json: agent main -> web-fetch
FALLO: evidence/0001-main-Glob-Allow.json: index.json dice agent='web-fetch', el recibo firmado dice 'main'
FALLO: evidence/0001-main-Glob-Allow.json: index.json dice profile='web-fetch', el recibo firmado dice 'main'
OK: la re-atribución fue rechazada

== RESULTADO: todas las verificaciones dieron lo esperado
```

Real output, set 04:

```text
== 0. Copiar el bundle a un directorio temporal
copia de <repo>/examples/claude-code-hook/evidence/04-sesion-real-bloqueada-web-fetch en <tmp>/bundle

== 1. Compilar praetore-verify (cargo build --release --locked)

== 2. Digest de la policy publicada
policy.json -> 60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68

== 3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada, intención y policy
OK: 8 recibos verificados, todos ligados a la policy publicada

== 4. Alterar UN byte de una copia de un recibo y comprobar que falla
0001-main-Glob-Allow.json: decision.outcome alterado en el byte 1647
{"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"}
OK: la copia alterada fue rechazada (exit 1)

== 5. Atribución: index.json debe decir lo mismo que los recibos firmados
main             Allow            8
perfil main         agent id beca5532-3f85-4f4d-972f-0ff6ddcef040  (nombre del perfil firmado por: agente y atestador)
OK: cada recibo queda atribuido a la identidad que lo firmó

== 6. Re-atribuir UN recibo en una copia de index.json y comprobar que falla
evidence/0001-main-Glob-Allow.json: agent main -> main-otro
FALLO: evidence/0001-main-Glob-Allow.json: index.json dice agent='main-otro', el recibo firmado dice 'main'
OK: la re-atribución fue rechazada

== RESULTADO: todas las verificaciones dieron lo esperado
```

Real output, set 03:

```text
== 0. Copiar el bundle a un directorio temporal
copia de <repo>/examples/claude-code-hook/evidence/03-bundle-demo-reproducible en <tmp>/bundle

== 1. Compilar praetore-verify (cargo build --release --locked)

== 2. Digest de la policy publicada
policy.json -> 03f5e97499562eb2abc4ad1a4a2b1cc728a4907089d9d369a36d6a6b3ea102c3

== 3. Verificar cada recibo: integridad, firma del atestador, autoridad pineada, intención y policy
OK: 22 recibos verificados, todos ligados a la policy publicada

== 4. Alterar UN byte de una copia de un recibo y comprobar que falla
0001-explorer-Read-Allow.json: decision.outcome alterado en el byte 1886
{"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"}
OK: la copia alterada fue rechazada (exit 1)

== 5. Atribución: index.json debe decir lo mismo que los recibos firmados
coder            Allow            2
coder            Deny             4
coder            RequireApproval  5
explorer         Allow            1
explorer         Deny             4
main             RequireApproval  1
planner          Allow            1
planner          Deny             1
unregistered(agent_type="general-purpose") Deny             1
web-fetch        Allow            1
web-fetch        Deny             1
perfil coder        agent id 35a39cca-4f4b-4f77-8a18-9b320a293aef  (nombre del perfil firmado por: agente y atestador)
perfil explorer     agent id bddf4630-df55-41b7-9d37-509107daebd1  (nombre del perfil firmado por: agente y atestador)
perfil main         agent id ddde02df-82ff-49e7-b9d9-1f8034994d60  (nombre del perfil firmado por: agente y atestador)
perfil planner      agent id a9009a37-adec-4191-8cdc-45ecca82c1b0  (nombre del perfil firmado por: agente y atestador)
perfil unregistered agent id c6cc3acc-a18b-4e9e-9dba-242f5f1e5940  (nombre del perfil firmado por: agente y atestador)
perfil web-fetch    agent id 3e9ef239-ac40-4a11-9a6a-50103a12da99  (nombre del perfil firmado por: agente y atestador)
OK: cada recibo queda atribuido a la identidad que lo firmó

== 6. Re-atribuir UN recibo en una copia de index.json y comprobar que falla
evidence/0001-explorer-Read-Allow.json: agent explorer -> planner
FALLO: evidence/0001-explorer-Read-Allow.json: index.json dice agent='planner', el recibo firmado dice 'explorer'
FALLO: evidence/0001-explorer-Read-Allow.json: index.json dice profile='planner', el recibo firmado dice 'explorer'
OK: la re-atribución fue rechazada

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
OK policy-digest OK digest="60388a9ccfa887b9e712dd4f029f0a2aaa0e0f4df62d648c64629b3dae6f0f68" policy_format_version=1 policy_id="claude-code-agents" policy_version=1
OK evidence OK authority_checked_at_source="verifier_clock" authority_checked_at="2026-11-01T21:41:27.005347Z" authority_verified=true current_authorization=false evidence_id="2d619485-e1d3-48a5-88ff-97fae15cc038" intent_verified=true receipt_action_type="claude:exec" receipt_decision="RequireApproval" verification_scope="historical_receipt_integrity_and_attestation"
exit 0
```

`praetore-verify evidence` checks the authority and issuer pin at the
receipt's signed decision time (`decided_at`) when the receipt records one.
The receipts in sets 03, 04 and 05 are v1/v4 receipts without HighAssurance
metadata: they record no signed decision time, so the check uses the
verifier's current time (`authority_checked_at_source="verifier_clock"`). The
authorities and issuer pins of sets 04 and 05 expire on 2027-01-29; from that
day these commands and `verify.sh` (also in CI) fail for 04 and 05 with
`TRUST_STORE_FAIL` until the sets are re-recorded. Set 03 is valid until
2036-10-28. With `--require-decision-time` every receipt in sets 03, 04 and
05 fails with `DECISION_TIME_MISSING`.

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

## 6. Journal chains (sets 03, 04, 05)

Each verifiable set also ships `journal-chain.jsonl`: its receipts, in file
name order, as one hash-linked JSONL chain in the format of
[`docs/proposals/journal-chain-jsonl.md`](../../../docs/proposals/journal-chain-jsonl.md).
The receipts in `evidence/` are unchanged; the chain is generated from them
with `praetore journal-export`. `unverified-v0/` has no chain (its receipts
have no attester signature, so the exporter refuses them).

Published heads (outputs obtained on 2026-10-31, Linux x86_64, 0.3.0 built
from this branch):

| Set | Entries | Head |
|-----|---------|------|
| 03-bundle-demo-reproducible | 22 | `4cea4fe91378a8471368b755e9bbdd23092e76a9d39517cc8e2cb393f83da90a` |
| 04-sesion-real-bloqueada-web-fetch | 8 | `f1666f5447351b18896792e64c7994d27561896beca37ec695571b73882d5af0` |
| 05-sesion-real-final | 118 | `79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9` |

**What a head proves, and what it does not.** The link is an unkeyed
SHA-256. Anyone who has the signed receipts (no private key needed) can
delete, reorder or drop receipts and rebuild a chain that verifies on its
own; whoever holds the attester key can also sign new receipts and build any
chain. A head only detects deletion, reordering or truncation when the
verifier compares against a head it obtained **from somewhere the producer
does not control**. The table above lives in the same repository as the
chains, so whoever can change the chain files can change this table too: it
is not an external anchor. For it to mean something, copy the heads somewhere
else (another repository, a public post, a signed message) and compare
against that copy. The chain also says nothing about tool calls that never
reached the hook, nor about whether the export is complete with respect to
what happened.

### Produce

```sh
cargo build --release --locked --package praetore-cli --package praetore-verify
E=examples/claude-code-hook/evidence/05-sesion-real-final
target/release/praetore journal-export --receipts-dir $E/evidence \
  --attester-pin $E/attester-public-key.hex --output /tmp/chain.jsonl
cmp /tmp/chain.jsonl $E/journal-chain.jsonl && echo identical
```

`journal-export` never overwrites `--output`. It checks every receipt against
the pinned attester key before linking it and fails on an unsigned receipt,
a bad signature, a repeated `evidence_id`, or anything in the directory that
is not a regular `*.json` file. With `--tenant <uuid>` instead of
`--receipts-dir` it reads the `praetore.execution_journal` rows of that
tenant from `PRAETORE_GATEWAY_DATABASE_URL`, ordered by
`(created_at, request_id, agent_id)`.

### Verify by hand

```sh
V=target/release/praetore-verify
$V journal --journal $E/journal-chain.jsonl --attester-pin $E/attester-public-key.hex \
  --policy $E/policy.json \
  --expected-head 79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9
echo "exit $?"
sed '$d' $E/journal-chain.jsonl > /tmp/truncated.jsonl
$V journal --journal /tmp/truncated.jsonl --attester-pin $E/attester-public-key.hex --policy $E/policy.json
echo "exit $?"
$V journal --journal /tmp/truncated.jsonl --attester-pin $E/attester-public-key.hex --policy $E/policy.json \
  --expected-head 79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9
echo "exit $?"
```

Real output. The truncated copy **passes** without `--expected-head` (a
prefix of a valid chain is a valid chain) and fails with it:

```text
OK journal OK database_head=null database_head_verified=false entries=118 expected_head_verified=true head="79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9" kind="tenant" policy_verified=true verification_scope="historical_journal_integrity_and_attestation"
exit 0
OK journal OK database_head=null database_head_verified=false entries=117 expected_head_verified=false head="4e517e29b4e016aa985695fb26a8eabd7d775915b648da3eaf206541cb1c198e" kind="tenant" policy_verified=true verification_scope="historical_journal_integrity_and_attestation"
exit 0
journal: head 4e517e29b4e016aa985695fb26a8eabd7d775915b648da3eaf206541cb1c198e does not match the expected head
ERROR journal JOURNAL_HEAD_MISMATCH
exit 1
```

### Chain plus tampered copies (script)

`verify-chain.sh <set> <expected head>` verifies the chain against the head,
re-exports it from `evidence/` and compares byte for byte, then checks that
five tampered copies are rejected: one receipt deleted, one receipt deleted
and the chain rebuilt with the public tools, last line truncated, two lines
swapped, one byte altered.

```sh
./examples/claude-code-hook/verify-chain.sh examples/claude-code-hook/evidence/05-sesion-real-final 79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9
./examples/claude-code-hook/verify-chain.sh examples/claude-code-hook/evidence/04-sesion-real-bloqueada-web-fetch f1666f5447351b18896792e64c7994d27561896beca37ec695571b73882d5af0
./examples/claude-code-hook/verify-chain.sh examples/claude-code-hook/evidence/03-bundle-demo-reproducible 4cea4fe91378a8471368b755e9bbdd23092e76a9d39517cc8e2cb393f83da90a
```

Real output, set 05:

```text
== 1. Compilar praetore y praetore-verify (cargo build --release --locked)

== 2. Verificar la cadena publicada contra el head esperado
{"ok":true,"command":"journal","code":"OK","details":{"database_head":null,"database_head_verified":false,"entries":118,"expected_head_verified":true,"head":"79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9","kind":"tenant","policy_verified":true,"verification_scope":"historical_journal_integrity_and_attestation"}}

== 3. Reproducir: exportar de nuevo desde evidence/ y comparar byte a byte
{"command":"journal-export","database_head":null,"entries":118,"head":"79a5374eaa24f8bc79d3c3818fbb2624154d93607e3ed3ee6434bef43ae146c9","kind":"tenant","ok":true}
OK: idéntica a journal-chain.jsonl

== 4. Copia con un recibo borrado (línea 2 eliminada, sin recalcular)
{"ok":false,"command":"journal","code":"JOURNAL_CHAIN_FAIL"}
stderr: journal: entry 1: seq or prev does not match
OK: copia con un recibo borrado rechazada (exit 1)

== 5. Copia con un recibo borrado y la cadena recalculada (sin llave privada)
{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}
stderr: journal: head 23b30a9f558567127f1c6786b7f9c0e66ec31ad7c6e110140e945fc7c267c765 does not match the expected head
OK: copia recalculada sin un recibo rechazada (exit 1)

== 6. Copia truncada (sin la última línea)
{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}
stderr: journal: head 4e517e29b4e016aa985695fb26a8eabd7d775915b648da3eaf206541cb1c198e does not match the expected head
OK: copia truncada rechazada (exit 1)

== 7. Copia con dos líneas intercambiadas
{"ok":false,"command":"journal","code":"JOURNAL_CHAIN_FAIL"}
stderr: journal: entry 1: seq or prev does not match
OK: copia reordenada rechazada (exit 1)

== 8. Copia con un byte alterado en un recibo
entrada seq=0: decision.reason alterado en el byte 1766
{"ok":false,"command":"journal","code":"EVIDENCE_FAIL"}
stderr: journal: entry 0: evidence error: evidence integrity verification failed
OK: copia con un recibo alterado rechazada (exit 1)

== RESULTADO: cadena verificada (118 entradas) y 5 copias manipuladas rechazadas
```

Real output, set 04:

```text
== 1. Compilar praetore y praetore-verify (cargo build --release --locked)

== 2. Verificar la cadena publicada contra el head esperado
{"ok":true,"command":"journal","code":"OK","details":{"database_head":null,"database_head_verified":false,"entries":8,"expected_head_verified":true,"head":"f1666f5447351b18896792e64c7994d27561896beca37ec695571b73882d5af0","kind":"tenant","policy_verified":true,"verification_scope":"historical_journal_integrity_and_attestation"}}

== 3. Reproducir: exportar de nuevo desde evidence/ y comparar byte a byte
{"command":"journal-export","database_head":null,"entries":8,"head":"f1666f5447351b18896792e64c7994d27561896beca37ec695571b73882d5af0","kind":"tenant","ok":true}
OK: idéntica a journal-chain.jsonl

== 4. Copia con un recibo borrado (línea 2 eliminada, sin recalcular)
{"ok":false,"command":"journal","code":"JOURNAL_CHAIN_FAIL"}
stderr: journal: entry 1: seq or prev does not match
OK: copia con un recibo borrado rechazada (exit 1)

== 5. Copia con un recibo borrado y la cadena recalculada (sin llave privada)
{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}
stderr: journal: head faed92c984f5c40524dabf87625195c49312a75941ea01465f75d42cb74d72da does not match the expected head
OK: copia recalculada sin un recibo rechazada (exit 1)

== 6. Copia truncada (sin la última línea)
{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}
stderr: journal: head 938adc88fe20e2fa9e8171acdb6aa927e1ddd7bf1a030c52644e65512aeff3eb does not match the expected head
OK: copia truncada rechazada (exit 1)

== 7. Copia con dos líneas intercambiadas
{"ok":false,"command":"journal","code":"JOURNAL_CHAIN_FAIL"}
stderr: journal: entry 1: seq or prev does not match
OK: copia reordenada rechazada (exit 1)

== 8. Copia con un byte alterado en un recibo
entrada seq=0: decision.reason alterado en el byte 1758
{"ok":false,"command":"journal","code":"EVIDENCE_FAIL"}
stderr: journal: entry 0: evidence error: evidence integrity verification failed
OK: copia con un recibo alterado rechazada (exit 1)

== RESULTADO: cadena verificada (8 entradas) y 5 copias manipuladas rechazadas
```

Real output, set 03:

```text
== 1. Compilar praetore y praetore-verify (cargo build --release --locked)

== 2. Verificar la cadena publicada contra el head esperado
{"ok":true,"command":"journal","code":"OK","details":{"database_head":null,"database_head_verified":false,"entries":22,"expected_head_verified":true,"head":"4cea4fe91378a8471368b755e9bbdd23092e76a9d39517cc8e2cb393f83da90a","kind":"tenant","policy_verified":true,"verification_scope":"historical_journal_integrity_and_attestation"}}

== 3. Reproducir: exportar de nuevo desde evidence/ y comparar byte a byte
{"command":"journal-export","database_head":null,"entries":22,"head":"4cea4fe91378a8471368b755e9bbdd23092e76a9d39517cc8e2cb393f83da90a","kind":"tenant","ok":true}
OK: idéntica a journal-chain.jsonl

== 4. Copia con un recibo borrado (línea 2 eliminada, sin recalcular)
{"ok":false,"command":"journal","code":"JOURNAL_CHAIN_FAIL"}
stderr: journal: entry 1: seq or prev does not match
OK: copia con un recibo borrado rechazada (exit 1)

== 5. Copia con un recibo borrado y la cadena recalculada (sin llave privada)
{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}
stderr: journal: head 52f374c0f1de0a296c01e6ba52887f7c19e7418cc028cbf89fe29ff4e508bb1e does not match the expected head
OK: copia recalculada sin un recibo rechazada (exit 1)

== 6. Copia truncada (sin la última línea)
{"ok":false,"command":"journal","code":"JOURNAL_HEAD_MISMATCH"}
stderr: journal: head aa88be5bcf7d00076fe684c6fb3d53e54b3ccd5c437ed5502149ebbfcd082c84 does not match the expected head
OK: copia truncada rechazada (exit 1)

== 7. Copia con dos líneas intercambiadas
{"ok":false,"command":"journal","code":"JOURNAL_CHAIN_FAIL"}
stderr: journal: entry 1: seq or prev does not match
OK: copia reordenada rechazada (exit 1)

== 8. Copia con un byte alterado en un recibo
entrada seq=0: decision.reason alterado en el byte 1997
{"ok":false,"command":"journal","code":"EVIDENCE_FAIL"}
stderr: journal: entry 0: evidence error: evidence integrity verification failed
OK: copia con un recibo alterado rechazada (exit 1)

== RESULTADO: cadena verificada (22 entradas) y 5 copias manipuladas rechazadas
```

## CI

The `hook-evidence` job in `.github/workflows/assurance.yml` runs
`verify.sh` on sets 03, 04 and 05 and fails if any of them does not verify.
The `journal-chain` job runs `verify-chain.sh` on the three chains with the
heads above (pinned in the workflow, so a change to a chain file alone fails
the job) and also checks that set 04 is rejected against the head of set 05.
