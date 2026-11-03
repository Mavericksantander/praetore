# Walkthrough demo

One command shows the kernel end to end, in about 10 minutes of conversation:

1. A simulated AI agent attempts three actions: one allowed, one denied by a
   policy rule, and one outside the authority it was granted.
2. The kernel's decision for each one (`ALLOW`/`DENY`) and what caused it
   (`decided_by`: the policy rule, or the engine's authority check).
3. The signed receipts exported as a hash-linked chain, the chain verified,
   and three altered copies: two rejected by the chain itself, one only by
   comparing against the expected head. The chain is also re-checked with the
   separate `praetore-verify` binary.

The demo is `crates/praetore-core/examples/demo.rs`. It uses only the public
`praetore-core` API (`AuthorizationEngine` in HighAssurance mode,
`journal_chain::ChainExporter` and `journal_chain::verify_chain`). Terminal
output is in Spanish. The program exits non-zero if any decision or
verification differs from the expected one; CI runs it on every pull request
(`assurance.yml`, step "Walkthrough demo").

## Not a production configuration

The demo prints this warning first, and it applies to everything below:

- **Replay guard in memory.** A reused request id is rejected within the
  process, but nothing survives a restart. Production uses
  `praetore-replay-postgres`.
- **Fixed one-minute freshness lease, no revocation source.** A revoked agent
  key or authority would still be accepted. This is the same behavior as the
  local mode of `praetore-mcp`.
- **Keys generated at start-up**, held in memory and discarded. Ids, digests
  and hashes change on every run; the decisions and verification results do
  not.
- **The expected head comes from the same process that produced the chain.**
  The links are an unkeyed SHA-256: anyone holding the receipts can remove or
  reorder them and recompute every link, and the result verifies (alteration
  C shows this). Only a comparison against an expected head catches it, and a
  head only proves something when it is anchored somewhere the producer does
  not control (see `docs/proposals/journal-chain-jsonl.md`). This demo does
  not anchor it.

## Requirements

- git
- A C linker: Xcode Command Line Tools on macOS (`xcode-select --install`),
  `build-essential` or equivalent on Linux. Rust needs it to link.
- Rust 1.88 or newer (`rustup`, <https://rustup.rs>). Installing it takes
  1–2 minutes.
- `make` (optional; preinstalled on macOS with the Command Line Tools and on
  most Linux distributions). Without it, use the `cargo` commands below.
- No database, network service or Docker.

## Run it (under 5 minutes from scratch)

```sh
git clone https://github.com/Mavericksantander/praetore.git
cd praetore
make demo          # the demo itself
make demo-verify   # runs the demo, then re-checks its files with the separate praetore-verify binary
```

The first build compiles only `praetore-core`, `praetore-verify` and their
dependencies: about 20 seconds on an Apple M1, longer on slower machines.
Compiler progress is hidden (`cargo -q`), so `make demo` first prints a
"Compilando…" line and then nothing until the build ends. Later runs start
in under a second.

Without `make`:

```sh
cargo run --locked -q -p praetore-core --example demo -- target/praetore-demo
cargo run --locked -q -p praetore-verify -- journal \
  --journal target/praetore-demo/journal.jsonl \
  --attester-pin target/praetore-demo/attester-public-key.hex \
  --policy target/praetore-demo/policy.json \
  --expected-head "$(cat target/praetore-demo/expected-head.txt)"
```

The same `praetore-verify journal` command must fail (exit code 1) with
`EVIDENCE_FAIL` for `--journal target/praetore-demo/journal-tampered.jsonl`
and with `JOURNAL_HEAD_MISMATCH` for
`--journal target/praetore-demo/journal-relinked.jsonl`. `make demo-verify`
checks those exact codes, so any other failure (a missing file, for
example) fails the target.

## What each step shows

| Step | What happens | Where the decision comes from |
|---|---|---|
| 1 | `read_account` with capability `accounts:read` | Policy rule `allow-read-accounts` |
| 2 | `create_refund` of 2,500,000 CLP | Policy rule `deny-refund-over-limit` (`amount_clp > 500000`) |
| 3 | `export_customer_data` with capability `customers:export` | Engine guard `authority_capability`: the policy would allow it, but the agent's signed authority grants only `accounts:read` and `refunds:create` |
| Chain | The three receipts, attester-signed, linked by SHA-256 (`prev` of each line) | `journal_chain::ChainExporter` |
| Alteration A | The second receipt's outcome changed from `Deny` to `Allow` | Rejected: `EVIDENCE_FAIL` (integrity hash) |
| Alteration B | The second receipt removed, links left as they were | Rejected: `JOURNAL_CHAIN_FAIL` (`seq`/`prev` no longer match) |
| Alteration C | The second receipt removed and every link recomputed (with the kernel's own `ChainExporter`) | Verifies without an expected head; rejected only against it: `JOURNAL_HEAD_MISMATCH` |

Steps 2 and 3 are both `DENY` for different reasons: in step 2 the policy
forbids the action; in step 3 the agent never held the authority, so no
policy rule is reached.

The output directory (`target/praetore-demo` by default; `make demo
DEMO_DIR=...` or the first argument of the example to change it) holds
`journal.jsonl`, `journal-tampered.jsonl`, `journal-relinked.jsonl`,
`attester-public-key.hex`, `policy.json` and `expected-head.txt`. Each run
deletes the previous ones first. Only public keys are written.

## Expected output

Output of `make demo-verify`. Ids, digests and hashes differ on every run.

```text
Compilando y ejecutando la demo (la primera vez tarda entre 20 s y unos minutos)...
PRÆTORE: demo del kernel de autorización determinista

AVISO: configuración de demostración, NO apta para producción.
  - Replay guard en memoria: no sobrevive a un reinicio del proceso.
  - Frescura con lease fijo de 1 minuto y SIN fuente de revocación:
    una llave o autoridad revocada seguiría siendo aceptada.
  - Llaves generadas al vuelo; los hashes cambian en cada ejecución.
  - El head esperado lo produce este mismo proceso. Solo prueba algo si
    se ancla fuera del control del productor (ver alteración C).

== Configuración
Agente simulado: "agente-soporte" (id 4134d9ce-b623-4e79-a1c2-224577cf159e)
Autoridad firmada por el emisor `demo-issuer`: accounts:read, refunds:create
Política `demo-payments-policy` v1 (digest bfadf4de414424f2…):
  - allow-read-accounts     read_account          requiere accounts:read
  - deny-refund-over-limit  create_refund         si amount_clp > 500000
  - allow-refunds           create_refund         requiere refunds:create
  - allow-customer-export   export_customer_data  requiere customers:export

== El agente intenta tres acciones

[1] El agente pide: leer el saldo de la cuenta acct-1029
    Decisión:  ALLOW (permitida)
    Causa:     regla de política `allow-read-accounts`
    Motivo:    Policy rule 'allow-read-accounts' matched
    Recibo:    b2f144d0-8726-4bc9-afec-c851beec0fe6 (firmado por el atestador)

[2] El agente pide: reembolsar 2500000 CLP (límite de la política: 500000 CLP)
    Decisión:  DENY (denegada)
    Causa:     regla de política `deny-refund-over-limit`
    Motivo:    Policy rule 'deny-refund-over-limit' matched
    Recibo:    d7bb6116-be85-4023-8638-5bc13099592b (firmado por el atestador)

[3] El agente pide: exportar la base de clientes (capacidad customers:export)
    Decisión:  DENY (denegada)
    Causa:     control del motor `authority_capability`
    Motivo:    authority does not permit capability: customers:export
    Recibo:    7a32b513-f5e1-483d-9087-c39ffed13a0c (firmado por el atestador)
    Nota:      aquí no decide la política. La política permitiría la
               exportación a quien tenga customers:export, pero este
               agente nunca recibió esa autoridad: "la política lo
               prohíbe" (caso 2) no es lo mismo que "el agente nunca
               tuvo esa autoridad" (caso 3).

== Registro de evidencia encadenado por hash
  seq 0  prev 0000000000000000…  Allow  read_account
  seq 1  prev d12e2f47087f973d…  Deny   create_refund
  seq 2  prev 6b49dc95233f9011…  Deny   export_customer_data
  head (último eslabón): 6fb89ca934b4ff05c596440bd677c3fe07964637967139b94c8e68f249f4e0e3

== Verificación de la cadena
  Original: OK (3 recibos, firmas válidas, head coincide)
  Alteración A: en el recibo 2 se cambia "Deny" por "Allow".
    -> RECHAZADA [EVIDENCE_FAIL]: entry 1: evidence error: evidence integrity verification failed
  Alteración B: se borra el recibo 2 de la cadena.
    -> RECHAZADA [JOURNAL_CHAIN_FAIL]: entry 1: seq or prev does not match
  Alteración C: se borra el recibo 2 y se recalculan todos los enlaces.
    -> sin head esperado: la cadena VERIFICA (los enlaces no llevan llave).
    -> con head esperado: RECHAZADA [JOURNAL_HEAD_MISMATCH]: head 98926bf7398564f82bcb4c9ff91d62e5c2ec7c5b32fef3b4bd3da8083b46146a does not match the expected head
    Por eso el head debe anclarse fuera del control de quien produce la
    cadena. Esta demo no lo ancla.

== Archivos para verificar con un binario independiente
  target/praetore-demo/journal.jsonl
  target/praetore-demo/journal-tampered.jsonl
  target/praetore-demo/journal-relinked.jsonl
  target/praetore-demo/attester-public-key.hex
  target/praetore-demo/policy.json
  target/praetore-demo/expected-head.txt

  cargo run --locked -q -p praetore-verify -- journal \
    --journal target/praetore-demo/journal.jsonl \
    --attester-pin target/praetore-demo/attester-public-key.hex \
    --policy target/praetore-demo/policy.json \
    --expected-head "$(cat target/praetore-demo/expected-head.txt)"

Demo completa: 3 decisiones, cadena verificada, 3 alteraciones detectadas (C solo con head).

== praetore-verify: cadena original (debe verificar)
OK journal OK attester_key_ids={"a3d3f98394357b2c3cb775703ef21f1270a89d0368c21745fe6fb018500f50ab":3} database_attester_key_ids=null database_head=null database_head_verified=false entries=3 expected_head_verified=true head="6fb89ca934b4ff05c596440bd677c3fe07964637967139b94c8e68f249f4e0e3" kind="tenant" policy_verified=true verification_scope="historical_journal_integrity_and_attestation"
== praetore-verify: recibo alterado (debe fallar con EVIDENCE_FAIL)
journal: entry 1: evidence error: evidence integrity verification failed
ERROR journal EVIDENCE_FAIL
OK: rechazada
== praetore-verify: recibo borrado y enlaces recalculados (debe fallar con JOURNAL_HEAD_MISMATCH)
journal: head 98926bf7398564f82bcb4c9ff91d62e5c2ec7c5b32fef3b4bd3da8083b46146a does not match the expected head
ERROR journal JOURNAL_HEAD_MISMATCH
OK: rechazada (solo porque se compara contra el head esperado)
```

## What the demo does not show

- Executing the action. The kernel decides and signs; dispatching the action
  is the gateway's job (`praetore-gateway`), which this demo does not start.
- Human approval (`REQUIRE_APPROVAL` and `praetore approve`). That flow needs
  the gateway and PostgreSQL; see "Human approval with `praetore approve`" in
  the README.
- Durable storage, key custody, revocation or an anchored chain head.
