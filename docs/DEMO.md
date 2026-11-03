# Walkthrough demo

One command shows the kernel end to end, in about 10 minutes of conversation:

1. A simulated AI agent attempts three actions: one allowed, one denied by a
   policy rule, and one outside the authority it was granted.
2. The kernel's decision for each one (`ALLOW`/`DENY`) and what caused it
   (`decided_by`: the policy rule, or the engine's authority check).
3. The signed receipts exported as a hash-linked chain, the chain verified,
   and two altered copies rejected. The chain is also re-checked with the
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
  A head only proves something when it is anchored somewhere the producer
  does not control (see `docs/proposals/journal-chain-jsonl.md`). Without it,
  a truncated chain (for example, the last receipt removed) still verifies.

## Requirements

- git
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
make demo-verify   # re-check its output with the separate praetore-verify binary
```

The first build compiles only `praetore-core`, `praetore-verify` and their
dependencies: about 20 seconds on an Apple M1, longer on slower machines.
Later runs start in under a second.

Without `make`:

```sh
cargo run --locked -q -p praetore-core --example demo -- target/praetore-demo
cargo run --locked -q -p praetore-verify -- journal \
  --journal target/praetore-demo/journal.jsonl \
  --attester-pin target/praetore-demo/attester-public-key.hex \
  --policy target/praetore-demo/policy.json \
  --expected-head "$(cat target/praetore-demo/expected-head.txt)"
```

The same `praetore-verify journal` command with
`--journal target/praetore-demo/journal-tampered.jsonl` must fail with
`EVIDENCE_FAIL` (exit code 1).

## What each step shows

| Step | What happens | Where the decision comes from |
|---|---|---|
| 1 | `read_account` with capability `accounts:read` | Policy rule `allow-read-accounts` |
| 2 | `create_refund` of 2,500,000 CLP | Policy rule `deny-refund-over-limit` (`amount_clp > 500000`) |
| 3 | `export_customer_data` with capability `customers:export` | Engine guard `authority_capability`: the policy would allow it, but the agent's signed authority grants only `accounts:read` and `refunds:create` |
| Chain | The three receipts, attester-signed, linked by SHA-256 (`prev` of each line) | `journal_chain::ChainExporter` |
| Alteration A | The second receipt's outcome changed from `Deny` to `Allow` | Rejected: `EVIDENCE_FAIL` (integrity hash) |
| Alteration B | The second receipt removed | Rejected: `JOURNAL_CHAIN_FAIL` (`seq`/`prev` no longer match) |

Steps 2 and 3 are both `DENY` for different reasons: in step 2 the policy
forbids the action; in step 3 the agent never held the authority, so no
policy rule is reached.

The output directory (`target/praetore-demo` by default; `make demo
DEMO_DIR=...` or the first argument of the example to change it) holds
`journal.jsonl`, `journal-tampered.jsonl`, `attester-public-key.hex`,
`policy.json` and `expected-head.txt`. Only public keys are written.

## Expected output

Ids, digests and hashes differ on every run.

```text
PRÆTORE: demo del kernel de autorización determinista

AVISO: configuración de demostración, NO apta para producción.
  - Replay guard en memoria: no sobrevive a un reinicio del proceso.
  - Frescura con lease fijo de 1 minuto y SIN fuente de revocación:
    una llave o autoridad revocada seguiría siendo aceptada.
  - Llaves generadas al vuelo; los hashes cambian en cada ejecución.

== Configuración
Agente simulado: "agente-soporte" (id 2c9aa7e5-1871-478f-85cd-9507282cd931)
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
    Recibo:    76ccfcf9-f3a6-44b3-b207-911e47fa3cdc (firmado por el atestador)

[2] El agente pide: reembolsar 2.500.000 CLP (límite de la política: 500.000 CLP)
    Decisión:  DENY (denegada)
    Causa:     regla de política `deny-refund-over-limit`
    Motivo:    Policy rule 'deny-refund-over-limit' matched
    Recibo:    88841527-0de2-42af-ad73-5e1a372afdde (firmado por el atestador)

[3] El agente pide: exportar la base de clientes (capacidad customers:export)
    Decisión:  DENY (denegada)
    Causa:     control del motor `authority_capability`
    Motivo:    authority does not permit capability: customers:export
    Recibo:    02c33aef-18c0-4649-bb5b-1b345de2cef9 (firmado por el atestador)
    Nota:      aquí no decide la política. La política permitiría la
               exportación a quien tenga customers:export, pero este
               agente nunca recibió esa autoridad: "la política lo
               prohíbe" (caso 2) no es lo mismo que "el agente nunca
               tuvo esa autoridad" (caso 3).

== Registro de evidencia encadenado por hash
  seq 0  prev 0000000000000000…  Allow  read_account
  seq 1  prev acf124f5e3d0cccf…  Deny   create_refund
  seq 2  prev 4cbdf46d150e4a63…  Deny   export_customer_data
  head (último eslabón): 39c5216b8d7c715cb7e499f457e0361588b429477cdc5f4a7c89a0494fb4882b

== Verificación de la cadena
  Original: OK (3 recibos, firmas válidas, head coincide)
  Alteración A: en el recibo 2 se cambia "Deny" por "Allow".
    -> RECHAZADA [EVIDENCE_FAIL]: entry 1: evidence error: evidence integrity verification failed
  Alteración B: se borra el recibo 2 de la cadena.
    -> RECHAZADA [JOURNAL_CHAIN_FAIL]: entry 1: seq or prev does not match

== Archivos para verificar con un binario independiente
  target/praetore-demo/journal.jsonl
  target/praetore-demo/journal-tampered.jsonl
  target/praetore-demo/attester-public-key.hex
  target/praetore-demo/policy.json
  target/praetore-demo/expected-head.txt

  cargo run --locked -q -p praetore-verify -- journal \
    --journal target/praetore-demo/journal.jsonl \
    --attester-pin target/praetore-demo/attester-public-key.hex \
    --policy target/praetore-demo/policy.json \
    --expected-head "$(cat target/praetore-demo/expected-head.txt)"

Demo completa: 3 decisiones, cadena verificada, 2 alteraciones detectadas.
== praetore-verify: cadena original (debe verificar)
OK journal OK attester_key_ids={"5968acedc7fa280d0dea8fdb9b2d48a66af5ddaa0368f9819cfb70968df80b34":3} database_attester_key_ids=null database_head=null database_head_verified=false entries=3 expected_head_verified=true head="39c5216b8d7c715cb7e499f457e0361588b429477cdc5f4a7c89a0494fb4882b" kind="tenant" policy_verified=true verification_scope="historical_journal_integrity_and_attestation"
== praetore-verify: copia alterada (debe ser rechazada)
journal: entry 1: evidence error: evidence integrity verification failed
ERROR journal EVIDENCE_FAIL
OK: la copia alterada fue rechazada
```

## What the demo does not show

- Executing the action. The kernel decides and signs; dispatching the action
  is the gateway's job (`praetore-gateway`), which this demo does not start.
- Human approval (`REQUIRE_APPROVAL` and `praetore approve`). That flow needs
  the gateway and PostgreSQL; see "Human approval with `praetore approve`" in
  the README.
- Durable storage, key custody, revocation or an anchored chain head.
