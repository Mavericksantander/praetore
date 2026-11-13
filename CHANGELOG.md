# Changelog

## Unreleased

### Breaking

- **`praetore-gateway-demo` requires `PRAETORE_GATEWAY_ADAPTER` (T-016).**
  The service no longer falls back to `local-demo` when the variable is
  missing or empty: it exits before it connects to PostgreSQL and names the
  three values (`sandbox`, `http`, `local-demo`). Action: set the adapter
  explicitly, including `local-demo` for local runs (`docs/operations.md`).
- **Gateway attester keys are read from owner-only files (T-016).**
  `PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_FILE` and
  `PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_FILE` name two files with 64
  lowercase hexadecimal characters each, checked like the safety namespace
  key (regular file, not a symlink, owned by the service user, no group or
  other bits, at most 128 bytes). The two keys must differ. The
  `..._KEY_HEX` variables are no longer read; the service refuses to start
  while either is set. Execution receipts carry the key id
  `execution-attester-<public key hex>` instead of the earlier prefixed id.
  Legacy baseline adoption reads the evidence key from the same file
  variable. Action: move each key into its own file and remove the
  `..._KEY_HEX` variables.
- **`praetore-observe` requires its read-only role (T-016).** At startup it
  checks that `PRAETORE_OBSERVE_DATABASE_URL` logs in as `praetore_observe`
  or as a member of it, is not a member of `praetore_runtime`,
  `praetore_safety_ingest` or `praetore_safety_audit`, and holds no
  privilege beyond the documented column `SELECT` grant
  (`docs/observability-mvp.md`). New
  `praetore_replay_postgres::verify_observe_role_with`. No migration creates
  the role. Action: run observe with the documented role instead of the
  gateway runtime credential.
- **`praetore-verify journal` renames `database_head_verified` to
  `database_head_consistent` (T-016).** The field means that the tenant
  chain's reference matches the database head given by `--database-journal`
  or `--expected-database-head`. The new `database_head_anchored` is true
  only with `--expected-database-head`, a head the caller holds; the head
  of a `--database-journal` file is not anchored by that file. Action:
  scripts that read `database_head_verified` read `database_head_consistent`,
  and check `database_head_anchored` where an anchored database head is
  required.
- **A journal chain holds the receipts of one tenant (T-016).** `praetore-verify
  journal` and `praetore journal-export` refuse a chain whose receipts name
  different tenants in their signed authority, or a tenant and none
  (`JOURNAL_TENANT_MISMATCH`). The verifier reports the chain's tenant as
  `tenant_id` (`null` for a database chain, or when the receipts name
  none). Exports written by `journal-export --tenant` hold one tenant and
  are not affected.
- **Storage record signatures must be lowercase hex (T-016).** A storage
  record whose signature is written in uppercase or mixed-case hex is
  refused (`EVIDENCE_FAIL`), as receipts and safety records already were.
  `praetore` only ever wrote lowercase.

- **Cooperative execution is refused by default (T-013).** The local HTTP
  API (`praetore run`) and `praetore-gateway-demo`, with every adapter and
  with or without `sandbox_root`, require `praetore-exec-mode: gateway` on
  every execution-path request and never answer `approved` on `/status`
  for an approved action. Before, this applied only with `sandbox_root`, and
  `praetore-gateway-demo` never applied it. `http_api::HttpOptions` now has
  `exec_mode: ExecMode` instead of `gateway_executes_effects: bool`. Action:
  clients send the header (the `praetore` CLI already does). Development
  only, with no guarantee about who performs an effect:
  `praetore init --dev-cooperative-exec` or
  `PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC=1` (local-demo adapter).
- **`ExecutionJournal::record_human_approval` takes a `HumanDecisionRecord`
  (T-016).** A rejection now carries its signed `approval_rejected` close and
  the journal writes the decision and the close in one transaction; an
  approval carries no close. Action: custom journal implementations write
  both, or neither, as `PostgresExecutionJournal` does.
- **`ExecutionAttestation::create` takes `observed_at` (T-016, `signing`
  feature).** Callers pass the time from their trusted clock; the gateway
  passes the engine's clock.
- **praetore-mcp journal lines are hash-linked (T-016).** Each line of
  `receipts/<date>.jsonl` is now `{"seq","prev","evidence"}`, the line
  format of `praetore_core::journal_chain`, instead of a bare evidence
  document. `praetore-mcp verify` checks the order (an entry removed,
  duplicated or reordered is reported), prints the journal head and accepts
  `--expected-head HEX`. Entries removed at the end of the journal are only
  detected with `--expected-head` against a head kept elsewhere; the chain
  has no key. Lines written by earlier versions still verify as unchained
  entries before the chain. Action: tools that read journal lines
  directly take the `evidence` member (see the praetore-mcp README).
- **praetore-mcp no longer forwards unchecked client lines in observe
  (T-016).** A line it cannot parse that may name a `safety*` tool, and any
  line over 32 MiB, is refused in both modes. Other unparseable lines are
  still forwarded in observe, now with a warning that gives the SHA-256 and
  the length.
- **The receipt of a held approval is signed as `awaiting_approval`
  (T-016, schema v5).** The 202 response of a request that requires human
  approval now carries `execution: "awaiting_approval"` (before:
  `"not_dispatched"` with no reason), signed in execution attestation
  schema v5. Schema v5 has exactly one shape: `requires_approval`, no
  reason, no output, no failure. A saved 202 receipt keeps verifying as
  `awaiting_approval` with `final: false` after the request was approved
  and executed; it can no longer be read as a closed `not_dispatched`
  request. `awaiting_approval` is a signed receipt state only, never a
  journal state: `GatewayReceipt::execution` and
  `ExecutionAttestation::execution` are now `AttestedExecution`
  (`ExecutionStatus` remains the journal row state, and
  `AttestedExecution::journal_status()` maps between them).
  `NonFinalReason` gains `AwaitingApproval` and loses `Intermediate` (no
  signed receipt carries an intermediate state). Action: HTTP clients that
  match on the 202 `execution` field accept `awaiting_approval`; offline
  verifiers are upgraded together with the gateway (see the table below).
- **An approval claimed after its window closes as
  `approved_claim_expired` (T-016).** New signed `not_dispatched_reason`
  (schema v3) for an approved request whose single dispatch is claimed too
  late. `approval_expired` now means only that the window closed without a
  decision. Rows closed before this release keep `approval_expired`.
- **`ActionDispatcher::preflight` takes the verified authority (T-016).**
  The signature is now `preflight(&self, authority: &Authority, action:
  &Action)`; the gateway passes the same authority that `dispatch` receives,
  so an adapter that routes per tenant can check its route before an action
  is dispatched or held for approval. Action: adapters that override
  `preflight` add the parameter.
- **HTTP and sandbox-supervisor adapters report refusals made before sending
  as `no_effect` (T-016).** `HttpActionDispatcher` now implements
  `preflight`: an action with no configured route for the verified tenant,
  action type and target, with a capability other than the route's, or with
  parameters over 64 KiB is refused at submission (403
  `action_not_dispatchable`, signed `not_dispatched` with reason
  `dispatch_refused`), and an action that requires approval is not held.
  Before, it was dispatched and signed `outcome_unknown`, or held for
  approval first. In `dispatch`, every check before the request is sent
  (action digest, tenant, route, capability, size) now returns
  `DispatchError::NotApplied` (signed `failed` with the class `no_effect`)
  instead of `Ambiguous` (`outcome_unknown`). `SandboxActionDispatcher`
  (the mTLS supervisor client) does the same for its checks before sending
  (tenant, action digest, request size), and its `preflight` refuses a
  request without a verified tenant or over 64 KiB. Any error after the
  request may have been sent is still `outcome_unknown`. Action: clients
  that expected `outcome_unknown` for these cases handle 403
  `action_not_dispatchable` and `failed` / `no_effect`.
- **A sandbox delete whose `unlinkat` fails is signed `effect_failed`
  (T-016).** `fs:delete_file` is `failed` / `no_effect` (403
  `action_not_dispatchable`) only when the checks before `unlinkat` refuse
  it (path, parent directory, entry). An error from the `unlinkat` call
  itself, `ENOENT` included, is now `failed` / `effect_failed` (502
  `action_effect_failed`): that error does not show that nothing was
  removed. Before, it was signed `no_effect`. New:
  `praetore_sandbox_fs::Dir::unlink_file`; `Root::remove_file` is
  unchanged.
- **Migration 0022 (`0022_awaiting_approval_state`).** Admits
  `awaiting_approval` in `execution_attestations` (accepted only while the
  journal row is held: `requires_approval`, `not_dispatched`, no reason, no
  decision, no expiration receipt, schema v5; a held row is attested only as
  `awaiting_approval`, and schema v5 is accepted for no other state), adds
  `approved_claim_expired` to both reason vocabularies, and refuses a new
  `approval_expired` close of `approved_pending_dispatch` and an
  `approved_claim_expired` close without an approve decision. No row is
  rewritten. A held row written before 0022 keeps its existing attestation.
  `Gateway::reconcile` adds an `awaiting_approval` attestation (schema v5)
  next to it; starting the gateway, `praetore run`, and the published HTTP
  and CLI routes do not. Until that reconcile, the inherited v2 receipt
  still verifies as `final: false` (`awaiting_approval_or_legacy`). Manual
  rollback:
  `docs/rollback/0022-awaiting-approval-state.sql`, refused while any
  `awaiting_approval` or `approved_claim_expired` row exists (in practice,
  once a request was held under 0022). The gateway never signs a held
  request as `not_dispatched` with no reason: a held row with a decision or
  an expiration and no signed close is reported as `InvalidRecord`.

  | | praetore-verify / Python binding <= 0.3.3 | This release |
  |---|---|---|
  | Receipts v1 to v4 | verify | verify as before; pending v2 receipts and `outcome_unknown` report `final: false` |
  | Receipt v5 (`awaiting_approval`) | rejected (`RECEIPT_INVALID`, `False`) | verifies, `final: false`, `non_final_reason: awaiting_approval` |
  | Reason `approved_claim_expired` | rejected (`RECEIPT_INVALID`, `False`) | verifies, final |
  | Rollback of 0022 | n/a | only while no `awaiting_approval` or `approved_claim_expired` row exists |

  The <= 0.3.3 column is the receipts that release already knew. v0.3.3
  rejects the later v3 reason `approval_rejected` (`RECEIPT_INVALID`).

  A gateway or CLI built before this release refuses a database at 0022
  (unknown migration version). This release applies 0022 to a database at
  0021 with `praetore-gateway-demo migrate` (schema owner URL in
  `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`), and `praetore run` also
  applies pending migrations when it starts. A production gateway process
  applies them on start only when that migration URL is set. Release 0.3.3
  knows migrations up to 0019 and already refuses a database at 0020 or
  0021. The offline verifiers do not open the database.

  Older verifiers fail closed: they never accept a new receipt with another
  meaning.

### Added

- **`praetore init` writes `attester-public-key.hex`; `praetore
  attester-pin`.** `init` also writes the evidence attester's public key,
  64 lowercase hex characters (the `--attester-pin` format of `praetore
  journal-export`), next to `evidence-attester.key`. The console's
  `PRAETORE_CONSOLE_ATTESTER_PIN_FILES` and `praetore journal-export
  --attester-pin` take it. `praetore attester-pin <directory>` writes it
  for a directory initialized before: it reads `evidence-attester.key`
  itself, fails without it, and never overwrites. No secret file changes.

- **`praetore-verify journal` reports an unanchored head (T-016).** Without
  `--expected-head` it reports the `head_not_anchored` warning, on stderr
  and in `details.warnings`, as `safety-journal` does: a truncated or
  re-linked chain also verifies then. `--require-anchored` fails with
  `JOURNAL_NOT_ANCHORED` (exit 1) after the chain verifies when no
  `--expected-head` was given.
- **`praetore-verify evidence` always reports `authority_verified`, and
  takes `--strict` (T-016).** `authority_verified` is `false` when no
  `--issuer-pins` were given. `--strict` requires `--issuer-pins` and
  `--policy` (`USAGE` otherwise) and implies `--require-intent` and
  `--require-decision-time`. A receipt that is not HighAssurance does not
  record the engine mode that produced it; no flag can show it.
- **Receipt finality in the verifiers (T-016).** `praetore-verify receipt`
  reports `final` and `non_final_reason`: the receipt returned while a human
  approval is pending (`requires_approval`, `not_dispatched`, no signed
  reason; older receipts with that shape too) is reported as
  `awaiting_approval_or_legacy`, and `outcome_unknown` as `outcome_unknown`,
  because a later receipt for the same request can record another state.
  `--require-final` fails with `RECEIPT_NOT_FINAL` for them. Rust:
  `GatewayReceipt::is_final()` and `non_final_reason()`; Python:
  `verify_final_gateway_receipt` and `gateway_receipt_finality`. The signed
  format and the result of signature verification are unchanged.
- **Approvals inbox in `praetore-console` (P-002 D2).** With
  `PRAETORE_CONSOLE_GATEWAY_URL` (a loopback `http://IP:port`),
  `PRAETORE_CONSOLE_APPROVER_KEY_ID`, `PRAETORE_CONSOLE_APPROVER_KEY_FILE`
  and `PRAETORE_CONSOLE_APPROVER_TOKEN_FILE` (owner-only files, the
  `approver.key` / `approver-api.token` formats of `praetore init`) the
  console lists the requests held for approval and lets the operator
  approve, reject, or run the single dispatch of an approved request. It
  reads the journal through `PRAETORE_CONSOLE_DATABASE_URL`, which in the
  tested setup is the gateway's runtime role: the reads run in
  transactions the console opens read only (per session, not by
  privilege), under the tenant's row-level security. Each request shows
  who, what (quoted), on what (quoted), until when, and its parameters
  with keys sorted and quoted: texts quoted, numbers as written, each list
  element apart with its own mark, and characters escaped by Unicode
  category (Cc, Cf, Zl, Zp, Co, Cn, every Zs other than U+0020, plus
  variation selectors, U+034F, the Hangul fillers and U+2800). The inbox
  tells apart structure, types and invisible characters; it does not flag
  look-alike characters from different scripts (homoglyphs). A request whose parameters do not fit (more than 20 lines, 200
  characters per value or 2 levels) or could be read two ways (a key with
  a dot, keys that repeat once normalized, text not in Unicode NFC) can
  only be rejected in the console, also server side, and approved with
  `praetore approve`. Approve and reject take a confirmation in the same
  card that repeats the parameters and the deadline. The console signs on
  this computer, as `praetore approve` does, only after it checks that the
  gateway challenge is the one rebuilt from the journal evidence it read;
  it checks that evidence against the attester pins and the local policy
  (see Changed). The gateway verifies, records and dispatches. The browser
  gets opaque references, never keys, journal ids or raw evidence.
  Actions need the console's own `Origin` and an `x-praetore-consola`
  header besides the session cookie. A partial set of the four variables
  is a startup error;
  none of them leaves the console without the inbox (history only). The
  gateway API is unchanged. Limit: a process running as the same operating
  system user as the console can read `approver.key` (and the token file)
  directly and sign without the console; real separation requires running
  the agent as another user (`crates/praetore-console/README.md`).
- **`praetore-console` sessions are per run and open through a single-use
  link (P-002 D2).** The session secret is new on every start and is no
  longer read from or written to a file (`PRAETORE_CONSOLE_SESSION_FILE` is
  ignored, with a warning); a cookie from an earlier run stops working. At
  startup the console writes `http://<bind>/?abrir=<code>` to stderr; under
  systemd that is the journal, readable by whoever reads it. The link works
  once and for at most five minutes. A new link is issued only by the
  operator (Enter in the console's terminal, when stdin and stderr are a
  terminal and the console is in its foreground, or a restart); asking for
  the page never issues one. SIGTTIN is ignored, so a console sent to the
  background keeps serving instead of being stopped by the system. `/` alone
  no longer sets the cookie, and responses carry `Referrer-Policy:
  no-referrer`. Every request must carry the
  console's own `Host` (DNS rebinding). Agent-chosen text in the history
  is shown with the same characters escaped. Action: open the printed
  link after each start.
- **Compliance package in `praetore-console` (P-002 D3).** With
  `PRAETORE_CONSOLE_POLICY_FILE` and `PRAETORE_CONSOLE_ATTESTER_PIN_FILES`
  (one to 16 public-key files, separated like `PATH`) the page offers
  "Descargar paquete de compliance": a `praetore-compliance.tar.gz` built on
  this computer with `journal.jsonl` (the tenant's chain, produced by the
  same code as `praetore journal-export --tenant`), `policy.json` as read,
  `policy-digest.txt` (the digest `praetore-verify policy-digest`
  computes), `attester-pin-N.hex`, `export.json`, `SHA256SUMS` over every
  other file, and `LEEME.txt` with the `praetore-verify` commands and what
  the package does not show: a path around the gateway, anything before
  the first record or after the export, completeness without an anchored
  head (the chain carries the policy decision only; since D3.1 the
  approval and execution receipts travel in `approvals.jsonl`, see below).
  `LEEME.txt` asks for `praetore-verify` built from `main`: the v0.3.3
  verifier also accepts this `journal.jsonl`, but does not report
  `tenant_id` nor warn `head_not_anchored`, which the instructions use,
  and has no `outcomes` command; v0.3.3 also rejects with
  `RECEIPT_INVALID` schema v5 execution receipts (`awaiting_approval`) and
  the reasons `approved_claim_expired` and `approval_rejected`, which
  `approvals.jsonl` can carry. `LEEME.txt` counts the decision receipts apart from the
  `database_head` reference line, and has a section on completeness
  (`--expected-head`, and `--expected-database-head` when the chain
  references the database head). The download is a `GET` that needs the session cookie, the
  console's `Host`, the `x-praetore-consola` header and, when the browser
  sends it, `Sec-Fetch-Site: same-origin`; it writes nothing. Pins are
  parsed and written back as public keys only; a pin equal to the
  approver's public key or secret (with the inbox configured) is refused,
  and so is any pin that verified no entry of the export, so a secret key
  file listed by mistake is refused instead of copied; the page names the
  unused pin in words by its place in `PRAETORE_CONSOLE_ATTESTER_PIN_FILES`
  and the log records its position and path. Every piece is read again at
  each download; if one is missing or does not check out (policy, pins,
  or the export) no package is produced and the page says what failed
  (for a failed export, the possible causes; an export stops at 4096
  entries or 8 MiB of chain). One package is built at a time; a second
  request meanwhile is told to wait. The page asks
  `/api/paquete/estado` and, when the package is not configured, says so
  instead of offering the button. One variable without the other is a
  startup error. New dependencies of the console: `tar` and
  `flate2` (Rust backend).
- **Approval and execution receipts in the compliance package (P-002
  D3.1).** When at least one of the new settings below is configured, the
  package adds `approvals.jsonl`: the tenant's human
  decisions (approve, reject), approval-expiration receipts and execution
  receipts (schema v1 to v5, the `GatewayReceipt` the gateway returned,
  with the journal's evidence and, for `executed` and `confirmed`, the
  adapter output its signature covers), one signed record per line, read
  in the same read-only snapshot as `journal.jsonl`. New optional
  settings `PRAETORE_CONSOLE_EXECUTION_PIN_FILES` and
  `PRAETORE_CONSOLE_APPROVER_PIN_FILES` (0 to 16 each, only with the D3
  settings) name the pins that verify them; with neither, the package is
  the D3 one, and `LEEME.txt` and `export.json` (`"outcomes":
  {"included": false, ...}`) say the console is not configured to include
  those receipts. The pins use the JSON format of the
  `approver-pin.json` that `praetore init` writes
  (`{"schema_version":1,"key_id":...,"public_key_hex":...}`); they go in
  the package as `execution-pin-N.json` and `approver-pin-N.json`,
  re-encoded from the parsed key. Before anything is archived, every
  record is verified with the code `praetore-verify outcomes` runs; a
  record that does not verify, does not match its request of the journal
  or contradicts another record of that request, or a record signed by a
  key no pin names, means no package, and the page says so without ids or
  hex; so does an `approvals.jsonl` over 32 MiB or 20,480 lines. An
  execution pin equal to the approver's key, an approver pin equal to the
  approver's secret, a file that is not a JSON pin, and a repeated key or
  key id are refused. An execution or approver pin that verified no
  record is left out of the package and logged with its position and path
  (a tenant with no human decision gets no `approver-pin-1.json`).
  `export.json` counts the records of each kind, the held requests by
  outcome and the omitted pins (`omitted_execution_pins`,
  `omitted_approver_pins`). `LEEME.txt` has a new step 5
  (`praetore-verify outcomes`, how to find each held request of the
  journal in its `held` list; the order of the lines is not verified, and
  an unused pin is reported, not an error) and says what it does not
  show: that `approvals.jsonl` is complete (its records are not chained,
  so an approved or executed request can show as `pending`,
  `approved_pending_dispatch` or `not_dispatched`), and that a
  request shown as `pending` may also have expired without the gateway
  having recorded it yet. The step 2 note on v0.3.3 now says that
  `approvals.jsonl` can carry what v0.3.3 rejects. The page's notice on the
  package names `approvals.jsonl` and the execution and approver public
  keys, and asks to review the output of each executed action, which may
  hold sensitive data, before handing the package over.
- **`praetore init` writes `execution-pin.json`; `praetore execution-pin`
  (P-002 D3.1).** `init` also writes the execution key's public pin
  (`{"schema_version":1,"key_id":"local-demo-<public key hex>","public_key_hex":...}`),
  the format of `approver-pin.json`, for the console's
  `PRAETORE_CONSOLE_EXECUTION_PIN_FILES` and `praetore-verify outcomes
  --execution-pin`. `praetore execution-pin <directory>` writes it for a
  directory initialized before: it reads `execution-attester.key` itself
  and never overwrites. No secret file changes.
- **`praetore-verify outcomes` (P-002 D3.1).** Verifies a tenant's
  approval and execution records (a JSONL file such as `approvals.jsonl`)
  against its journal chain, which it verifies first: each human decision
  against the challenge derived from its journal receipt and an
  `--approver-pin`, each expiration and execution receipt against an
  `--execution-pin` (both repeatable, up to 16, JSON pins), the evidence
  embedded in each execution receipt against the journal's receipt for
  that request, and that the records of one request agree. It reports
  `counts`, `held` (every held request of the journal with its outcome:
  `pending`, `rejected`, `expired`, `approved_pending_dispatch`,
  `approved_executed`, `approved_failed`, `approved_outcome_unknown`,
  `approved_not_dispatched` or `not_dispatched`), `held_by_outcome`, the
  pins that verified nothing, and `head_not_anchored` without
  `--expected-head`. New error codes `OUTCOME_MALFORMED`,
  `OUTCOME_UNKNOWN_REQUEST`, `OUTCOME_EVIDENCE_MISMATCH`,
  `OUTCOME_KEY_UNKNOWN`, `OUTCOME_SIGNATURE_INVALID`,
  `OUTCOME_SELF_APPROVAL`, `OUTCOME_DUPLICATE`, `OUTCOME_INCONSISTENT`,
  `OUTCOME_PIN_DUPLICATE`, `OUTCOMES_TOO_LARGE`. Before, the verifier
  checked one execution receipt per run (`receipt`) and had no command for
  human decisions or expiration receipts. The code is
  `praetore_receipt::outcomes`; `praetore_core::journal_chain` adds
  `verify_journal_receipts`, which also returns the verified receipts, and
  `praetore_replay_postgres::journal_export` adds
  `export_tenant_with_outcomes`.
- **`praetore_replay_postgres::journal_export` (P-002 D3).** The tenant
  export of `praetore journal-export` (`export_tenant`: receipts and
  storage records in one read-only, repeatable-read snapshot, then the
  chain) moved from the CLI to this module, so the CLI and the console run
  the same code. The CLI's output and errors are unchanged. New in
  `praetore_core::journal_chain`: `ChainExporter::unused_attesters`, the
  pins that verified no entry.

### Changed

- **`praetore-console` checks journal evidence against the attester pins
  and the local policy before it offers a decision.** The approvals inbox
  now requires `PRAETORE_CONSOLE_POLICY_FILE` and
  `PRAETORE_CONSOLE_ATTESTER_PIN_FILES`; without them the console does not
  start, and the error names what is missing, so a console with the inbox
  also offers the compliance package. A held request is shown, and can be
  approved or rejected, only when its evidence is signed by one of the pins
  and records the local policy's digest; the console checks again just
  before signing, and still requires the gateway challenge to match the
  evidence. A request that does not verify is only counted. With pins, the
  history also checks each receipt's attester signature, not the current
  policy; a receipt that does not verify is shown as unreadable instead of
  failing the page. Without pins, the history checks the integrity hash
  only, as before. The inbox and the history read the pins and the policy
  once, at startup: a change takes effect on restart. After a policy
  change, requests held under the earlier policy are no longer offered in
  the inbox; `praetore approve` and `praetore reject` still decide them.
  With the policy and the pins but no inbox (package only), the console
  now reads those files at startup and does not start if one cannot be
  read, is a symlink or is not a regular file; before, they were first
  read at download, and the download still follows symlinks. The package
  download is otherwise unchanged.

- **`praetore-console` keeps its session per tab.** The opening link is now
  `http://<bind>/#abrir=<code>`; the page redeems the code once over
  `POST /api/sesion` and keeps the session token in `sessionStorage` for
  that tab, sent as `Authorization: Bearer`. No session cookie is set. A
  token expires after 12 hours and does not survive a restart; another tab
  needs a new link. `PRAETORE_CONSOLE_*` variables are unchanged.

- **Approval types moved to `praetore-receipt` (P-002 D3.1).**
  `ExecutionKey`, `ApprovalChallenge`, `HumanApprovalOutcome`,
  `HumanApprovalDecision`, `ExpiredOutcome`, `ApprovalExpiredReceipt` and
  `ApprovalError` moved from `praetore-gateway`, which re-exports them
  unchanged, so offline verifiers can check decisions and expiration
  receipts without server dependencies. What they sign and how they verify
  is unchanged. New: `HumanApprovalDecision::verify_signature` and
  `is_self_approval` (the checks the gateway already ran, now shared);
  `ApprovalExpiredReceipt::create` is public behind the `signing` feature,
  like `ExecutionAttestation::create`.

- **Migration `0021_journal_insert_rules` (T-016).** The execution journal
  accepts on INSERT only the initial states the gateway writes (`authorized`
  for `allowed`, `not_dispatched` otherwise, with no output, reason or
  failure class), and an execution attestation only for the journal row's
  current state, with the same reason, failure class and signed identity.
  Rows written before 0021 are not rewritten. Manual rollback:
  `docs/rollback/0021-journal-insert-rules.sql`; the 0020 rollback now
  refuses to run while 0021 is applied.
- **Execution attestations are timestamped with the engine's trusted clock
  (T-016).** `observed_at` comes from the same clock as approval
  expirations, not the host clock. When that clock is unavailable the gateway signs
  nothing and returns an error; an execution already dispatched stays
  `dispatched` until `reconcile` closes it.
- **A human rejection and its signed close commit together (T-016).** The
  decision and the `approval_rejected` close are written in one
  transaction: when the write fails, neither is recorded and the request
  can still be decided. Rows written by earlier releases with a decision
  and no close are still repaired on the next read.
- **Claude Code hook example fails closed when its binary fails (T-016).**
  `hook/praetore-hook.sh` no longer `exec`s the binary: a binary that cannot
  start, panics, is killed by a signal, exits with a status other than 0 or
  prints something other than a JSON object yields a `deny` decision. The
  binary turns a panic during authorization into a deny. The README
  registers the hook with `"onFailure": "block"` and a `timeout`.
- **Claude Code hook example: `-c` in a group of short options (T-016).**
  `bash -lc '...'`, `sh -ec '...'` and fish's `--command` are treated as
  `shell -c` (unanalyzable command).
- **praetore-mcp fsyncs directories (T-016)** after creating a daily journal
  file or a directory, and after writing a new file, a backup or a renamed
  config or policy.
- `praetore_core::journal_chain::receipt_link` is public, so other journals
  link receipts with the same function.
- **Documentation matches the current code (T-016).** `docs/operations.md`
  describes an execution attestation that cannot be signed after dispatch
  (the row stays `dispatched` until `reconcile`) and the scope of the 0012
  trigger next to 0021. The descriptions of `praetore-gateway-service` and
  `praetore-mcp`, `demo/README.md`, the release-signing notes in
  `docs/assurance-matrix.md` and `docs/pre-user-pilot-gates.md`, the policy
  golden-vector test names in `docs/assurance-matrix.md` and
  `docs/threat-model.md`, and the migration range in
  `docs/observability-mvp.md` are corrected. The praetore-mcp GUIDE lists a
  held journal lock as a troubleshooting case. The help of
  `praetore-mcp policy` describes how `--arg-path-prefix` values are
  resolved; the flags and their behavior are unchanged.
- **Kubernetes templates deny ingress and egress by default per namespace
  (T-016).** `praetore-agents`, `praetore-gateway`, `praetore-tools`,
  `praetore-egress` and `praetore-sandbox` each get a policy that selects
  every pod for ingress and egress; the existing allows add to it. The
  gateway proxy gets an explicit egress allow (protected tools, public 443,
  DNS) and the sandbox supervisor an egress allow for the Kubernetes API
  and DNS, to be narrowed to the cluster's API server addresses. The Cilium
  profile writes these policies with the empty-rule form (`- {}`).
  `praetore-data` is not covered. CI checks the floor with
  `scripts/check-k8s-default-deny.rb`. Action: add the egress your protected
  tools need as separate allow policies.
- **Claude Code hook example: `PRAETORE_HOOK_BIN` must be an absolute path
  to an executable regular file (T-016).** Otherwise the wrapper denies
  without running anything; an empty value still means the installed
  binary. The README states what is not checked: whoever controls the
  environment of the hook process chooses the binary.
- **Safety ingestion counts a resent `conflict` event as a duplicate
  (T-016).** An event identical to one already recorded as `conflict` for
  its `source_seq` creates no second record: it is counted as `duplicate`,
  like a resend of the first event. A different event with that
  `source_seq` is still recorded as `conflict`. The record format, the
  verifier and the signed counts are unchanged; chains written before may
  hold the same `conflict` more than once and still verify. Rust:
  `safety_ingest::EventLookup` has a new method, `conflict_recorded`
  (implemented by `MemoryLookup` and `PostgresSafetyStore`); custom
  lookups implement it.
- **Safety ingestion docs (T-016).** `docs/operations.md` and
  `SafetySourceKey` state that a source key is used by one source,
  ingester and tenant, and is not shared between ingesters or tenants.
  `EpochFile` and `docs/operations.md` state that a missing epoch file is
  read as the first start of the source, including after the file is
  deleted, and how to recover from that.
- **praetore-mcp release archives are packaged before the smoke test
  (T-016).** In `Assurance gates`, `mcp-binaries` builds, packages and
  checksums each binary without installing Node tooling, and a new
  `mcp-smoke` job tests the uploaded archive after checking its `.sha256`.
  `Release checksums` waits for both. The smoke test installs
  `@modelcontextprotocol/server-filesystem@2.1.0` with `npm ci` from the
  committed `scripts/mcp-smoke/package-lock.json` instead of `npx -y`, and
  `scripts/mcp-smoke.py` stops if that install is missing or another version.
  The binaries and the archive layout are unchanged.

### Fixed

- **CLI PostgreSQL tests locate `praetore-verify` on Cargo 1.100.**
  The test helper walked two parent directories from the test
  executable, which matched Cargo 1.99 (`target/debug/deps/`). Cargo
  1.100 places test executables under
  `target/debug/build/<package>/<hash>/out/`, so the helper looked in
  the hash directory and `postgres_t013b_refusal_before_effect_is_a_signed_failed_state`
  failed after stable moved to rustc 1.100.0. The helper now walks
  ancestors until it finds the binary in the artifact directory
  (`target/debug` or `target/release`), which is still where Cargo
  uplifts workspace binaries.

## 0.3.3 - 2026-11-03

Closes the two known limitations of v0.3.2 in the post-hoc safety ingestion
(G1) for AI-enabled systems: R7, the tenant lock of `praetore-safety-ingest`
can only be taken by the tenant's registered role (#97, migration 0019), and
L95-1, the socket is set up without following symbolic links (#98). Breaking:
the socket directory needs the sticky bit when it is writable by group or
others. GitHub release with checksums only; nothing is published to
crates.io.

### Breaking

- **`praetore-safety-ingest` refuses a socket directory writable by group or
  others without the sticky bit (L95-1, #98),** also with
  `PRAETORE_SAFETY_SOCKET_GROUP`. Before, a group-writable directory (for
  example `0770`) was accepted with a socket group; now the ingester does
  not start. Action: `chmod 1770 <dir>` (with a socket group) or
  `chmod 0700 <dir>`.

### Fixed

- **L95-1 (#98): socket mode and group without following symbolic links.**
  `praetore-safety-ingest` opens the socket directory with `O_DIRECTORY |
  O_NOFOLLOW`, checks owner and mode on that descriptor, creates and opens
  its private bind directory relative to it, sets the socket's group with
  `fchownat(AT_SYMLINK_NOFOLLOW)` and its mode relative to the private
  directory's descriptor after checking the entry is its own socket, and
  renames it into place without replacing an existing entry
  (`renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on
  macOS). On Linux the mode is set with `fchmodat` without
  `AT_SYMLINK_NOFOLLOW` (`fchmodat2`, Linux 6.6 and later, is not used); the
  entry is checked first, in a directory only the ingester's user can
  write.

- **R7 (#97, migration 0019): the tenant lock of `praetore-safety-ingest`
  can only be taken by the tenant's registered role.** It is now a row lock (`FOR UPDATE
  NOWAIT`) on the ingester's own row of `praetore.safety_ingest_tenants`,
  on a second connection, instead of a PostgreSQL advisory lock that any
  login could hold. Migration 0019 adds the `lock_anchor` column, the only
  one `praetore_safety_ingest` may UPDATE, and an UPDATE policy limited to
  the session's own registration with `WITH CHECK (false)`, so the row can
  be locked but not changed. Another tenant's role, an unregistered role or
  a role with no grant fails closed. The ingester checks the lock before
  each write and renews it every `PRAETORE_SAFETY_LOCK_RENEW_SECONDS`
  (default 300: `COMMIT; BEGIN; SELECT ... FOR UPDATE NOWAIT`), so its
  transaction id is never older than one interval. If the lock is lost or
  a renewal finds it taken, the ingester keeps running, writes nothing and
  retries until it takes the lock again. Reversible with
  `docs/rollback/0019-safety-ingest-row-lock.sql` (it sets `lock_timeout`). Stop v0.3.2 ingesters
  before migrating: the old and new locks do not exclude each other.

## 0.3.2 - 2026-11-03

Post-hoc ingestion of safety actions that executors of AI-enabled systems
already ran (G1, format 2: #92, #94, #95; migrations 0016 to 0018), the
safety namespace manifest (G2), mission safety classes in policies (G7,
policy format 2), HighAssurance receipts in the Claude Code hook example,
the walkthrough demo, and the v0.3.1 follow-ups. GitHub release with
checksums only; nothing is published to crates.io.

### Known limitations (planned for v0.3.3)

- **R7: any role of the database can take a tenant's ingestion lock.** The
  per-tenant PostgreSQL advisory lock needs no privilege, so a session of
  another tenant's ingester, of the gateway or of any other login can hold
  it and keep that tenant's `praetore-safety-ingest` from starting (denial
  of service; it cannot read or write the tenant's records). The refusal
  and `praetore-safety-ingest doctor` name the holding session
  (`docs/operations.md`, "Deployment").
- **L95-1: a group-writable socket directory.** With
  `PRAETORE_SAFETY_SOCKET_GROUP` the socket's parent directory may be
  writable by that group. A member of the group can then remove or replace
  the socket (executors would report to another process, and those events
  would be lost; it cannot sign records) or entries the ingester creates
  there at startup (which then fails). By replacing the temporary entry
  the ingester binds in (`.bind-<pid>`) with a symbolic link, a member can
  also make the `chmod`/`chown` of that startup apply to another file of the
  ingester's user, for example its signing key (which would then be
  readable by the group). Give the directory the sticky bit (`chmod 1770`)
  or keep it writable by the ingester's user only (`docs/operations.md`,
  "Deployment").

### Changes

- **Post-hoc safety ingestion: format 2 and hardening (G1 follow-ups, #94,
  #95).** Changes the G1 format of #92 before its first release; records
  written by an earlier build of `main` (format 1) cannot be read and must
  be exported and removed first (`docs/operations.md`, "Source epochs").
  - Format 2: every event signs `source_epoch`, the source's run (persisted
    by `praetore_safety_client::EpochFile`, which fails closed instead of
    starting again from 1); `source_seq` starts at 1 in each epoch and a
    chain is a sequence of segments, one per epoch. Every record of a source
    chain signs `high_water` and `source_epoch`; the ingester resumes from
    the last signed record only (`SafetyIngestor::resume_heads`, replacing
    `set_heads`; `IngestorConfig::heads` is removed), and `commit` now
    returns an error unless the records extend the current head.
  - New `rejected` reasons `seq_jump_too_large`, `stale_epoch` and
    `epoch_jump_too_large` (bounded by `PRAETORE_SAFETY_MAX_SEQ_JUMP` and
    `PRAETORE_SAFETY_MAX_EPOCH_JUMP`, which also bounds a chain's first
    epoch); an
    event far from the ingester's clock carries `clock_skew_seconds`
    (`PRAETORE_SAFETY_MAX_CLOCK_SKEW_SECONDS`). A chain head signed by an
    unregistered ingestion key fails closed; previous keys of a rotation are
    listed in `PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE`.
  - Rate limits per source (spent only by events that can advance the
    chain) and for every other input, replays included
    (`PRAETORE_SAFETY_SOURCE_RATE`/`_BURST`,
    `PRAETORE_SAFETY_REJECTED_RATE`/`_BURST`), and on Linux a sender user id
    check (`PRAETORE_SAFETY_ALLOWED_UIDS`, `SCM_CREDENTIALS`; refused at
    startup on other platforms). What is not recorded one by one is added to
    signed counts on `_unattributed` (`loss` reasons `rate_limited`,
    `rejected_suppressed`, `duplicate`, `peer_refused`). **Decision
    change:** an exact duplicate no longer creates a `duplicate` record; it
    is counted (a `conflict` is still recorded, and the verifier still
    accepts `duplicate` records).
  - Migration `0017_safety_records_followups`: the `source_epoch` column,
    `record_id` unique per tenant, the columns checked against the signed
    `high_water` and `source_epoch`, and the tenant registry
    `praetore.safety_ingest_tenants` (one login role and one ingestion key
    per tenant, registered by the schema owner). Row-level security on
    `safety_records` follows the registered role instead of the
    `praetore.tenant_id` setting, and the insert trigger accepts only
    records naming the tenant's registered key. The ingester and the
    exporter check the registration at startup. A documented manual
    rollback of 0016 to 0018 (`docs/rollback/g1-safety-records.sql`) is
    tested in CI.
  - Migration `0018_safety_audit_and_role_oids`: registrations name the
    login role by OID (`'<role>'::regrole`), so a role dropped and created
    again with the same name is not registered; the read-only group
    `praetore_safety_audit` and `praetore.safety_audit_tenants` let a login
    role export and audit the tenants it is registered for, without write
    access (`verify_safety_audit_role_with`).
  - `PRAETORE_SAFETY_MAX_EPOCH_JUMP` bounds the step of `source_epoch` and a
    chain's first epoch. The ingester binds its socket without changing the
    process umask.
  - `praetore journal-export --safety --from-seq N [--limit M]` exports a
    chain in ranges, each anchored on the record before it, and
    `praetore-verify safety-journal --range [--expected-anchor HEX]`
    verifies one. Without `--expected-head` the verifier now warns
    (`head_not_anchored`). It reports epochs and `dropped_by_reason`.
  - **Known limitation:** the per-tenant advisory lock needs no privilege,
    so any role of the database can hold a tenant's lock and keep its
    ingester from starting (denial of service only). The refusal and
    `praetore-safety-ingest doctor` name the holding session. A lock that
    only the tenant's registered role can take is planned for v0.3.3.
  - CI runs every ignored PostgreSQL test one by one
    (`scripts/postgres-ignored-tests.sh`) and every G1 end-to-end test.

- **Walkthrough demo.** `make demo` (or `cargo run --locked -p praetore-core
  --example demo`) runs three decisions of a simulated agent (allowed, denied
  by a policy rule, outside its authority), exports the signed receipts as a
  hash-linked chain, verifies it and rejects two altered copies; `make
  demo-verify` re-checks the chain with `praetore-verify`. Demonstration
  configuration only: in-memory replay guard and a fixed freshness lease with
  no revocation source. See `docs/DEMO.md`. Runs in CI (`assurance.yml`).

- **Post-hoc safety ingestion (G1, SAF-09.5, #92).** Safety actions that an
  executor of an AI-enabled system already ran can be recorded, isolated from
  the decision path. New module `praetore_core::safety_ingest`:
  `SafetyEvent` (signed by a `SafetySourceKey` under
  `PRAETORE_SAFETY_EVENT_V1\0`: `source_id`, monotonic `source_seq`, the raw
  action name, `occurred_at` by the source clock, optional bounded `params`,
  `post_hoc: true`), `SafetyRecord` (signed by a `SafetyIngestKey` under
  `PRAETORE_SAFETY_RECORD_V1\0`, chained per source inside the signed
  payload; statuses `accepted`, `undeclared`, `invalid_name`, `duplicate`,
  `conflict`, `late`, `rejected`, `loss`), the `SafetyIngestor` state machine
  and `verify_safety_chain`. Key ids use `PRAETORE_SAFETY_SOURCE_KEY_V1\0ed25519\0`
  and `PRAETORE_SAFETY_INGEST_KEY_V1\0ed25519\0`. New crate
  `praetore-safety-client`: one non-blocking Unix datagram per event, no
  retry; on failure the event is dropped and counted locally. New binary
  `praetore-safety-ingest` (in `praetore-cli`; `run`, `doctor`,
  `public-key`): its own process, database role and key; verifies the safety
  namespace manifest and refuses any two roles with the same key at
  startup, without a flag; a `0600` (or `0660` with a group) socket in a
  directory it owns; a bounded queue whose overflow, like a database outage,
  becomes a signed loss record; one ingester per tenant (advisory lock);
  graceful shutdown. Migration `0016_safety_records`: table
  `praetore.safety_records` (append-only by trigger, an insert trigger that
  refuses a row that does not extend its chain or whose columns are not its
  signed fields, forced row-level security per tenant) and the NOLOGIN group
  `praetore_safety_ingest` (`USAGE` on the schema, `SELECT` on
  `schema_migrations`, `SELECT`, `INSERT` on `safety_records`); creating it
  needs `CREATEROLE` in the migrating role, checked before any migration
  (`MigrationError::GroupRoleMissing`). `verify_safety_ingest_role_with`
  checks the ingester's role, and `verify_runtime_role` now refuses a
  gateway role that can insert safety records
  (`RuntimeRoleError::RoleSeparation`). New export `praetore journal-export
  --safety --tenant UUID --source ID --ingest-pin HEX_FILE` (verifies before
  writing, never overwrites; reads `PRAETORE_SAFETY_DATABASE_URL`) and new
  verifier command `praetore-verify safety-journal --journal JSONL
  --ingest-pin HEX_FILE [--source-pins JSONL] [--expected-head HEX]`, which
  checks record signatures, the chain, `source_seq` continuity (gaps covered
  by loss records), duplicates and conflicts, event signatures and the head,
  and reports the count of each status. Format:
  `docs/proposals/safety-ingestion-jsonl.md`. New fuzz target
  `safety_ingest`; new CI job `g1-mutation`. Transport v1 is local only;
  HTTP with mutual TLS is future work.
- **Safety namespace manifest (G2).** New module
  `praetore_core::safety_namespace`. `SafetyActionName::parse` is the one
  validator of `safety:*` names (exact ASCII prefix `safety:`, printable
  ASCII, a name that starts with an ASCII letter or digit, at most
  `MAX_SAFETY_ACTION_NAME_BYTES` = 128 bytes), with the typed
  `SafetyNameError`. `Policy::validate` uses it for every `Safety` entry, so
  a `Safety` entry longer than 128 bytes now fails to load with the new
  `ActionClassError::SafetyNameTooLong` (G7 accepted up to 1024 bytes).
  `SafetyNamespaceManifest` (schema version 1) is a signed, canonical JSON
  statement of the `Safety` names of one format 2 policy, bound to its
  digest, id and version, built deterministically by
  `SafetyNamespaceManifest::from_policy`. It is signed by a dedicated
  `SafetyNamespaceKey` (not the attester or issuer key) under the new domain
  `PRAETORE_SAFETY_NAMESPACE_V1\0`, with key ids under
  `PRAETORE_SAFETY_NAMESPACE_KEY_V1\0ed25519\0`. `verify` checks it against a
  pinned key, `verify_matches_policy` against a policy (digest and exact
  list), and `classify_name` answers `Declared` or `Undeclared` for the
  ingestion path; `ensure_distinct_keys` refuses the same key in the
  namespace and attester or issuer roles (`SameKeyForBothRoles`). Only the
  canonical encoding parses (`from_json`); a manifest file is that document
  and one newline (`to_file`, `from_file`). New commands: `praetore policy
  safety-manifest --policy P --key K --output NEW_FILE [--other-pin A]...`
  (never overwrites; writes a synced `O_TMPFILE` or temporary file, links
  it to the output name and checks the linked entry; needs a filesystem
  with hard links; reads the key with `O_NOFOLLOW`, checks the open
  descriptor and, on macOS, refuses extended ACLs) and `praetore-verify
  safety-manifest --manifest M --pin K [--policy P] [--other-pin A]...`,
  both with `--format json|text`; `--other-pin` (alias `--attester-pin`)
  refuses a namespace key equal to an attester or issuer key. The manifest authorizes nothing and is not read on
  the decision path. Golden vector
  `docs/golden/safety-namespace-manifest-v1.json`; new fuzz target
  `safety_namespace`.
- **Claude Code hook example: HighAssurance receipts.**
  `examples/claude-code-hook` now evaluates with
  `AuthorizationEngine::production` (HighAssurance) instead of `strict`.
  Every receipt it writes, the `unclassified` DENY included, records the
  engine's signed decision time (`decided_at`), so `praetore-verify evidence
  --issuer-pins` checks the authority and the issuer pin at that instant and
  `--require-decision-time` accepts it. Intents are signed v2 for the
  audience `praetore-claude-hook`, valid for 60 s. The replay guard is a
  durable local claim store in the hook state (`replay/`): one file per
  request, created with `create_new` (`O_CREAT|O_EXCL`) and `fsync`ed with
  its directories; on every claim the store must be a real directory owned
  by the current user with no group/other bits and (macOS) no extended ACL
  entries, and the state directory must be owned by the user and not
  group/other-writable; any store error denies without a receipt. The guard
  records each signed request's claim once; it does not deduplicate tool
  calls (each invocation builds a new request). `receipts.jsonl` is now
  `fsync`ed after each append (and its directory on creation); a claim can
  remain without a receipt when that write fails, and the call is denied.
  Each receipt signs Claude Code's `tool_use_id` (`claude.tool_use_id`, a
  string or number up to 128 bytes; a longer one or another JSON type is
  evaluated as `unregistered` and recorded only as `praetore.claim_rejected`;
  a missing one is not recorded). The `receipts.jsonl` line carries an
  unsigned copy only when the receipt signs one; `verify` and `export`
  refuse an unsigned copy on a HighAssurance receipt that signs none, and
  `export` takes it only from the signed context. Unparseable hook input is
  denied with a fixed message that does not quote input values. The guard does not forge receipts and does not
  deduplicate invocations: a re-delivered tool call is evaluated again, and
  the hook's `verify` warns (without failing) about `tool_use_id`s signed in
  more than one receipt. An unanalyzable shell command is now denied (rule
  `deny-unanalyzable-command`, signed receipt) instead of held for approval.
  A DENY with a receipt shows only its reason class (`capability`, `path`,
  `unregistered`, `unclassified`, `unanalyzable_command, use simple
  commands`) and the evidence id, never the rule id or text; a
  RequireApproval message also includes the evidence id.
  Freshness is
  local (60 s lease, no revocation source). `init` creates `replay/`; state
  created before this change has none and is refused with a message that
  points to `init` (same pattern as the SAF-14 check). Profiles and
  per-agent keys (SAF-14), G7 classification and declared Safety tools
  (no decision, no receipt) are unchanged, and so is the receipt format.
  The hook's `verify` checks the authority at `decided_at` when a receipt
  records it. `verify.sh` takes `--require-decision-time`; `demo.sh` checks
  that the bundle it regenerates is HighAssurance. The committed `bundle/`
  and sets 03, 04 and 05 are unchanged and verify as before (they fail
  `--require-decision-time`, as expected). `evidence/VERIFY.md` section 7
  describes how to record new sets 04 and 05 with this hook. The G7 hook
  mutant (`scripts/g7-mutants/hook.patch`) is rebased onto the new code.
- **Claude Code hook example: no subagent profile gets `process:execute` by
  default** (GHSA-wg33-3h8v-xvqw). The hook sees a command's text, not what
  it does when it runs, so `Bash` under `process:execute` is equivalent to
  every other capability; the README now says so, and that the `.claude/`
  write rule for subagents holds for Write/Edit only. `coder` loses
  `process:execute` in `PROFILES` (the main session keeps it) and
  `agents/coder.md` no longer lists `Bash`. State written by an earlier
  `init` keeps what it was issued; the README documents re-running `init`
  into a new directory. As defense in depth, not a boundary, the `Bash` scan
  now also flags an analyzable command whose words name `<root>/.claude` or
  `<root>/.git`, a path outside the project root, or a common network tool,
  and the default policy holds each for approval
  (`approval-command-touches-protected-path`, `approval-command-leaves-root`,
  `approval-command-uses-network`). `init` writes the root to
  `project-root` in the state directory. The README documents running
  `Bash` under Claude Code's sandbox. Receipt format unchanged; committed
  evidence not regenerated (`bundle/` predates the change).
- **Claude Code hook example: client configuration is protected from
  subagent writes** (GHSA-wg33-3h8v-xvqw). Writes to the project paths Claude
  Code lists as protected in its permission modes (`.mcp.json`, `.vscode/`,
  `.cargo/`, `.husky/`, `.envrc`, shell startup files, and the rest of that
  list) are denied to every profile except `main`
  (`deny-subagent-client-config-writes`), and `main` needs approval
  (`approval-main-client-config-writes`); the `Bash` scan flags the same
  paths. The hook also denies commands (`claude:exec`) to every profile
  except `main` whatever its authority grants, warns on stderr about state
  without `project-root` or with a subagent holding `process:execute`, fails
  closed on an invalid `project-root`, and maps `Monitor` and `PowerShell` to
  `claude:exec` (`PowerShell` is never analyzed, so `main` needs approval).
  The format-1 policy error now recommends a fresh `init`.
- **Claude Code hook example: protected names compared after Unicode
  folding; writes to them reserved to `main` in the binary**
  (GHSA-wg33-3h8v-xvqw). Path components are compared after dropping
  default-ignorable code points, NFKC and full case folding (`caseless`,
  `unicode-normalization`, the versions praetore-mcp uses), and for every
  profile except `main` a write to a non-ASCII component that starts with
  `.` or whose folded form differs from its ASCII lowercase form is denied
  (`main` needs approval). A write that would complete a bare git repository
  (`HEAD`, `config`, `objects`, `refs`) is held the same way. The hook now
  denies, whatever the policy says, a write by a profile other than `main`
  to client configuration, `.claude`, `.git` or a path that failed its
  check, evaluated as `unregistered` with a signed receipt; without
  `project-root` every such write is denied. An `agent_id` without an
  `agent_type` is evaluated as `unregistered`, the governance rules name
  every profile except `main`, and a write tool without its path parameter
  is denied.
- **Claude Code hook example: guard denials name the guard in the signed
  receipt.** A denial by the hook's exec or write guard records
  `praetore.hook_guard` (`exec_reserved_to_main`, `client_config_write`,
  `governance_write`, `path_check_failed`, `no_project_root`) and
  `praetore.requested_profile` in the signed context; `check-attribution.py`
  (run by `verify.sh`) requires them together on a Deny signed as
  `unregistered` and counts them apart, and `test-attribution.sh` checks
  them. A non-ASCII name now counts as a possible alias only if it starts
  with `.` or folds to ASCII, so ordinary non-ASCII file names are writable
  again; `commondir` and `gitdir` join the bare-repository names; a write
  without its path parameter says so instead of naming a path rule.

- **Claude Code hook example: guard denials and state warnings with
  HighAssurance receipts.** A denial by the hook's exec or write guard shows
  the reason class derived from the signed `praetore.hook_guard`
  (`exec_reserved_to_main` is `capability`; the write guards are `path`),
  and `verify` checks the guard claims like `check-attribution.py`. The
  state warnings also reach the user as `systemMessage`. `PowerShell` and a
  `Monitor` without a command are unanalyzable, so they are denied like any
  unanalyzable command.
- **Breaking (API, G7): `AuthorizationRequest.action` is a `MissionAction`.**
  `praetore-core` separates mission actions, which PRÆTORE decides, from
  safety actions, which the executor of an AI-enabled system runs without
  waiting for PRÆTORE (for example `safety:halt`, `safety:stop_all`). The new
  types `MissionAction` and `SafetyAction` are built only by
  `Policy::classify(action) -> Result<ClassifiedAction>`, and
  `AuthorizationRequest::new` takes a `MissionAction`, so a safety action
  cannot be put in a request (compile error E0308, checked by a
  `compile_fail` doc test). `AuthorizationEngine::evaluate` keeps its
  signature and re-checks the class against its own policy.
  `Policy::evaluate` / `evaluate_with_context` take a `&MissionAction`.
  `AuthorizationRequest` no longer implements `Deserialize`:
  `AuthorizationRequest::from_json(json, &policy)` classifies the action
  first and returns `SafetyActionNotGoverned` or `UnclassifiedAction`.
  New typed errors: `PraetoreError::SafetyActionNotGoverned`
  (`SAFETY_ACTION_NOT_GOVERNED`), `UnclassifiedAction`
  (`UNCLASSIFIED_ACTION`), `PolicyFormatUnsupported` and
  `PolicyActionClassInvalid(ActionClassError)`.
  `verify_journal` takes an `Option<&RecordedPolicy>`.
- **Breaking (policy format 2, G7).** A policy needs `"format_version": 2`
  and an `action_classes` table (`"Mission"` or `"Safety"` per exact
  `action_type`). `Policy::validate` rejects, with typed errors: a rule on an
  undeclared action type, a `safety:` type not declared `Safety` (and a
  `Safety` entry without the prefix), an unprefixed name that contains
  `safety` (ASCII, any case), and any rule that targets a `Safety` action
  (this replaces the external lint proposed in SAF-09). Mission action types
  need no prefix. A format 1 document (no `format_version`) is rejected for
  evaluation in every mode (`PolicyFormatUnsupported { found: 1 }`).
  Digests of migrated policies change; the receipt format does not.
- **Historical verification keeps working.** `RecordedPolicy::from_json`
  reads format 1 and 2 documents and computes the digest they had; it
  cannot be evaluated. `praetore-verify evidence|journal --policy` and
  `policy-digest` (which now also prints `policy_format_version`) use it,
  as does the hook's `verify`. The committed evidence sets (hook `bundle/`,
  sets 03, 04 and 05, `examples/verify/`,
  `examples/third-party-verification/bundle/`) are unchanged and verify
  against their recorded format 1 documents; `docs/golden/canonical-policy-v1.json`
  keeps its digest and `canonical-policy-v2.json` is added.
- **Entry points classify first (G7).** A declared `Safety` action gets no
  decision: the gateway HTTP API answers 422 `safety_action_not_governed`,
  the `praetore-mcp` gate forwards it to the wrapped server without a
  receipt (enforce and observe), and the Claude Code hook adds no decision;
  nothing is evaluated, signed, claimed or journaled. An action type the
  policy does not declare is refused at every entry point with a **signed
  DENY receipt**: the new `AuthorizationEngine::refuse_unclassified` (and
  `refuse_unclassified_with_atomic_commit`) takes an
  `AuthorizationRequest<UnclassifiedAction>` (built only from
  `Policy::unclassified`), verifies it exactly like a mission request
  (identity, authority, issuer pin, intent signature and, in HighAssurance,
  intent window, freshness and replay claim), never evaluates policy rules,
  and records `Deny` with reason `unclassified` and
  `decided_by: {"kind": "engine_guard", "guard": "unclassified_action"}` (an
  existing `decided_by` kind; verifiers that read engine guards accept it).
  It is journaled and claimed like a policy DENY. A forged or
  unauthenticated request gets no receipt. `praetore-mcp` refuses it in both
  modes; the hook appends it to `receipts.jsonl`. An unreadable `policy.json` still refuses every tool call,
  `safety:*` included (documented in `docs/threat-model.md`).
- **Breaking (gateway API behaviour change).** Every DENY from
  `POST /v1/execute` now returns 403 with one body,
  `{"code": "authorization_denied", "authorization": "denied", "execution":
  "not_dispatched", "evidence_id": ..., "request_id": ...}`, instead of the
  signed receipt, whatever decided it (a rule, an engine guard or an
  undeclared action type), so a DENY response does not reveal what the
  policy declares or which rule matched (REQUIRE_APPROVAL responses still
  carry the receipt and the rule). The receipt, with its reason, is in the
  execution journal (`praetore journal-export`). The 422
  `unclassified_action` response is removed. Likewise, `praetore-mcp`
  answers every DENY with `Denied by PRÆTORE. Evidence id: ...` (the rule
  and reason go to stderr) and the hook answers every DENY that has a
  receipt with `PRÆTORE denied this tool call (evidence ...)` (details on
  stderr). Response timing is not made uniform.
- **Gateway: the reserved `safety:` prefix decides before classification.**
  `POST /v1/execute` answers every action type that starts with `safety:`
  with the same 422 `safety_action_not_governed` (same body, headers and
  code path), declared Safety or not, before any verification, engine,
  journal or signing work. An undeclared `safety:*` gets no receipt at the
  gateway. Every request at this gate writes the same unsigned WARN line
  (claimed agent id and action type, bounded and escaped, and
  `declared=true|false`), so the answer cannot be used to enumerate the
  table; the remaining timing difference is a documented limit. `SAFETY:x`
  (not the exact prefix) goes through the unclassified path and gets a
  signed DENY when the request is authenticated. `praetore-mcp` and the hook keep the signed `unclassified`
  DENY for it.
- Human-facing text escapes characters that render invisibly or reorder text
  (zero-width, bidi, control) as `\u{XXXX}`: `praetore-verify --format text`
  (which now also reports `receipt_action_type`, `receipt_tool`,
  `receipt_decision` and `receipt_decided_by`), `praetore-mcp` tables and
  stderr, the hook's stderr, and the gateway's WARN line (`praetore_core::display`). JSON
  output and receipts stay exact. `UNCLASSIFIED_DENY_REASON` and
  `UNCLASSIFIED_ACTION_GUARD` are public constants in `praetore-core`.
- **Breaking (behaviour change, praetore-mcp observe mode).** A call whose
  action type the policy does not declare (`UNCLASSIFIED_ACTION`) is now
  refused in observe mode too, not forwarded: an undeclared `safety:*`, any
  tool name that starts with `safety` in any ASCII case and is not exactly a
  declared Safety action (including names with a trailing space or tab, and
  ambiguous lines), and also every mission call when the policy does not
  declare `mcp.tools/call`. `praetore-mcp init` declares `mcp.tools/call`,
  so new homes are not affected. A JSON-RPC batch stays all or nothing in
  enforce, so a declared Safety call in a batch with a blocked call is not
  forwarded; send safety calls on their own. Runtime tests per entry point
  check zero engine calls and zero journal writes, with the journal down,
  in under 100 ms (`crates/praetore-gateway/tests/safety_actions.rs`, the
  `g7_` tests in `crates/praetore-mcp/src/gate.rs`,
  `examples/claude-code-hook/src/tests_g7.rs`, and the PostgreSQL test
  `postgres_g7_safety_action_is_refused_before_the_engine_with_the_journal_down`).
  `scripts/g7-mutation-test.sh` shows they fail when `classify` is removed.
  Mission actions take the unchanged path: synchronous signing, fail closed.
  Recording safety actions (SAF-09.5, isolated ingestion) is not
  implemented.
- `praetore policy classify --policy <path>` proposes an `action_classes`
  table for a policy and lists what prevents loading it as format 2. It
  never writes files. `praetore-core` gains a `test-probe` feature (off by
  default, enabled only from dev-dependencies) that counts engine calls for
  tests.
- Shipped policies are format 2: `praetore-mcp init`, the hook's `init`,
  `praetore init` and `crates/praetore-cli/examples/policies/*.json`.

  Migration guide. **Migrate the policy to format 2 before upgrading the
  binary.** After the upgrade a format 1 policy no longer loads, so hook or
  `praetore-mcp` state written before G7 refuses every tool call (fail
  closed, `safety:*` included) until its policy is migrated; the gateway
  service does not start.

  ```text
  # before (format 1)
  {"id":"p","version":3,"canonical_version":1,"semantics_version":2,"rules":[
    {"id":"w","action_type":"fs:write_file","effect":"Allow", ...}]}

  # after (format 2)
  {"format_version":2,"id":"p","version":3,"canonical_version":1,"semantics_version":2,
   "action_classes":{"fs:write_file":"Mission","safety:halt":"Safety"},
   "rules":[{"id":"w","action_type":"fs:write_file","effect":"Allow", ...}]}
  ```

  1. Before upgrading, run `praetore policy classify --policy policy.json`
     (or add the fields by hand) and add the printed
     `format_version` and `action_classes` to the document.
  2. Rename any action the executor runs without waiting for PRÆTORE to
     `safety:<name>`, declare it `Safety` and remove every rule on it.
  3. Rust callers: `let action = policy.classify(action)?.into_mission()?;`
     before `AuthorizationRequest::new`, `AuthorizationRequest::from_json(json,
     &policy)`, `Policy::new(..).with_mission_actions([..])` /
     `.with_action_class(..)`.
  4. praetore-mcp homes: make sure `action_classes` declares
     `"mcp.tools/call": "Mission"`, otherwise every call is refused, in
     observe too.
  5. Pin the new digest (HighAssurance `policy_digest`). Keep the format 1
     document: receipts that recorded its digest verify only against it
     (`praetore-verify --policy old-policy.json`).
- **Journal export across an attester key rotation (v0.3.2 follow-up
  B5-5).** `praetore journal-export` and `praetore-verify journal` accept
  `--attester-pin` more than once (up to 16 keys); each receipt and storage
  record is checked against the pinned key its key id names, and nothing is
  re-signed. A database adopted with a retired key exports and verifies
  again with the retired and the current pin; with only the current pin the
  export fails and names the key that signed the adoption record. New
  library API: `ChainExporter::with_attesters` and
  `journal_chain::verify_journal_with_attesters`; `export`,
  `export_with_database_head` and `export_storage_records` of the CLI take
  a slice of keys.
- **`praetore-verify journal --policy` on a database chain fails (B5-4)**
  with `INVALID_REQUEST` (`ChainError::PolicyNotApplicable`) instead of
  reporting `policy_verified: true` with nothing compared. **Breaking
  (API):** new `ChainError` variant.
- **Extension objects in `praetore` are refused (B5-1).** The runtime check
  (`RuntimeRoleError::ExtensionObjects`) and the migration runner
  (`UnsafeDatabase`) refuse an extension installed in `praetore` and any
  `praetore` object that belongs to an extension, which a role with CREATE
  on the database can install since PostgreSQL 13. **Breaking (API):** new
  `RuntimeRoleError` variants.
- **`PRAETORE_SCHEMA_OWNER` (B5-2).** Optional exact role name of the
  `praetore` schema owner. When set, the runtime check
  (`RuntimeRoleError::UnexpectedSchemaOwner`) and migrating refuse another
  owner (and, before the schema exists, another migrating role). Read by the
  gateway, the CLI and `praetore-observe`; the gateway warns while it is
  unset. Set it in every deployment. New `RuntimeRoleOptions::with_schema_owner`
  and `MigrationOptions::schema_owner` (a new public field).
- **Docs (B5-3).** `docs/operations.md` now says that an allowlisted event
  trigger runs with the privileges of the role executing the migration DDL
  (unless its function is SECURITY DEFINER), as a test records, not with its
  function owner's.
- **`praetore run`, `praetore-gateway-demo` and `praetore-observe` report a
  port in use** with exit status 1 and the bind error, instead of aborting
  (SIGABRT or a panic) while they dropped their blocking PostgreSQL clients
  on the async runtime thread. The services bind before the state moves into
  the runtime, and the runtime is dropped before the last reference.
- **`DEPENDS ON EXTENSION` marks on `praetore` objects are refused** by the
  runtime check and the migration runner, like extension members: `DROP
  EXTENSION ... CASCADE` by the extension's owner would drop the marked
  object (for example an append-only trigger function).
- **`PRAETORE_SCHEMA_OWNER` with a NOLOGIN owner group.** With no schema yet,
  a migrating role that is a member of the named NOLOGIN group creates
  `praetore` owned by the group and runs the migrations as it; any other
  named role is refused before anything is created. The installation order
  is in `docs/operations.md`. The CLI and `praetore-observe` now warn, like
  the gateway, while the variable is unset. Before anything is created, a
  typed `MigrationError::SchemaOwner` (`SchemaOwnerProblem`) refuses a
  membership without SET or INHERIT (or a NOINHERIT migrating role), a
  predefined `pg_*` role, the bootstrap superuser for a new schema, and a
  missing CREATE privilege on the database; `MigrationError::
  RuntimeGroupMissing` refuses, before migration 0001, when
  `praetore_runtime` does not exist and the role running the migrations has
  no CREATEROLE. The owner is checked again inside the transaction that
  creates or adopts the schema. `verify_runtime_role` refuses a `pg_*`
  value as a configuration error. **Breaking (API):** new `MigrationError`
  variants.
- **`praetore-verify journal` reports `attester_key_ids`** (entries per
  signing key id), and a receipt signed by a key that is not pinned fails
  with `AUTH_FAIL` naming that key id (`ChainError::UnpinnedAttesterKey`).
  New `journal_chain::verify_journal_report` and `JournalReport`. With
  `--database-journal`, `database_attester_key_ids` reports that file's
  signers.
- **Tests (B5-6 and an intermittent CI failure).** The full ignored
  PostgreSQL suite runs in parallel: the fault-injection test runs in its own
  scratch database, and cluster-wide grants of `pg_read_all_data` /
  `pg_write_all_data` are serialized with every runtime-role check.
  `postgres_cli_journal_export_tenant_end_to_end` no longer picks two ports
  that can coincide, and waits for a gateway that accepts its own token
  rather than any answer to `/healthz` (two gateways on one port made
  `praetore demo` get 401 `authentication_required`).

## 0.3.1 - 2026-11-01

This release also includes every change listed under 0.3.1-rc.1 below.

- **Breaking (journal chain format):** the journal export gains signed
  storage records. Adopting a legacy baseline writes a record signed with
  the evidence attester key into `praetore.storage_records` (migration
  0015, append-only) in the adoption transaction; adoption without a signer
  is refused (`MigrationError::AdoptionRequiresSigner`). `praetore
  journal-export --database` exports them as a database-level chain
  (`record` lines), and a tenant export of a database with records starts
  with a `database_head` reference to that chain. `praetore-verify journal`
  verifies both, and `--database-journal`/`--expected-database-head` check
  the reference. Chains without records are unchanged; older verifiers
  refuse chains with the new lines. See
  `docs/proposals/journal-chain-jsonl.md`.
- Migration checks accept event triggers and global revoke-only default
  privileges only when listed explicitly (`PRAETORE_TRUSTED_EVENT_TRIGGERS`,
  `PRAETORE_TRUSTED_DEFAULT_PRIVILEGES`; off by default; listed event
  triggers are verified at startup and refused if they cannot be). Default
  privileges in schemas other than `praetore` are no longer considered.
  Relaxations are logged at startup and reported by `praetore doctor`.
  `docs/operations.md` documents them and recommends
  `PRAETORE_RUNTIME_LOGINS` in production.
- **Breaking:** an existing `praetore` schema without migration records is
  no longer adopted silently. `apply_migrations` refuses it
  (`MigrationError::LegacyBaselineNotAdopted`). Adoption is explicit:
  `PRAETORE_ADOPT_LEGACY_BASELINE=1` for the gateway service,
  `praetore run <directory> --adopt-legacy-baseline` (or the same variable)
  for the CLI, `apply_migrations_with` and `MigrationOptions` in the
  library. An adoption is recorded in `praetore.schema_migrations`
  (`adopted_legacy_baseline`, `adopted_by`, `baseline_structure_sha256`,
  with `applied_at`), returned by `legacy_baseline_adoption`, logged by the
  gateway service and printed by `praetore doctor`. The record is
  informative and not tamper-evident; `baseline_structure_sha256` identifies
  the compared 0001-0009 structure for the server version, not the
  database. `praetore doctor` flags the most direct inconsistency
  (`migration_record_inconsistency`). Fresh databases and databases with
  migration records are unaffected.
- `apply_migrations` compares the `praetore` structure with a scratch apply
  of the recorded migrations on every run (before migrating forward and
  after applying), checks owners on every run, and runs migrations as the
  schema owner when it is a NOLOGIN group of the migrating role
  (`MigrationError::SchemaDrift`, `MigrationError::InvalidConfiguration`).
- `verify_runtime_role` also checks ownership of every `praetore` object,
  members of the schema owner (allowed only through
  `PRAETORE_SCHEMA_OWNER_MEMBERS`), non-superuser members of
  `pg_read_all_data`/`pg_write_all_data`, objects elsewhere that depend on
  `praetore`, `WITH GRANT OPTION`, the exact documented `praetore_observe`
  columns, and SECURITY DEFINER functions with the owner's rights that any
  other role may execute. Other login members of `praetore_runtime` are
  reported at startup and by `praetore doctor`, and refused when
  `PRAETORE_RUNTIME_LOGINS` lists the allowed ones.
- `PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS` entries must be
  schema-qualified with their signature; they are resolved by OID, an
  entry that does not resolve is a configuration error, superuser-owned
  ones are logged with a warning, and `praetore run` reads the variable.
- `docs/threat-model.md` describes the trust perimeter of these checks.
- `apply_migrations` checks the database environment on every run, fresh,
  adopted or current (`MigrationError::UnsafeDatabase`).
  `verify_runtime_role` checks schema ACLs (`RuntimeRoleError::UnexpectedGrant`):
  only the grants the migrations make and the documented `praetore_observe`
  shape are accepted. SECURITY DEFINER functions with the owner's rights are
  refused unless listed in `PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS`
  (semicolon-separated; logged at startup).
- The 0009 baseline check in `praetore-replay-postgres` (a `praetore`
  schema without migration records, recorded as 0001-0009 without running
  them) now compares the live schema with 0001-0009 applied by the same
  server, not names. In a transaction that is always rolled back, 0001-0009
  run in a scratch schema (schema name rewritten; the `praetore.tenant_id`
  setting is kept), and a canonical dump of both schemas must be identical:
  relations (kind, RLS and FORCE RLS, owner, ACL, index and view
  definitions), columns (type, NOT NULL, default, identity, collation,
  column ACL), constraints (`pg_get_constraintdef`), functions (`prosrc`,
  result, language, SECURITY DEFINER, `SET search_path`, volatility,
  STRICT, LEAKPROOF, parallel, owner, ACL; overloads are separate),
  triggers (`pg_get_triggerdef`, enabled, internal triggers), RLS policies
  (command, roles, USING, WITH CHECK), rewrite rules, inheritance and
  partitions, types, other objects in the schema, and objects in other
  schemas that depend on it. The schema owner must be the migrating role
  or one it is a member of; event triggers, default privileges for the
  schema or owner, and per-database or per-role `search_path`,
  `row_security` or `session_replication_role` settings are refused. Any
  difference refuses the migration and names the objects
  (`MigrationError::UnrecognizedSchema` now carries a `String`).
- The migration runner sends every statement with
  `search_path = pg_catalog, pg_temp` (the caller's value is restored) and
  catalog names qualified. It refuses a session with
  `session_replication_role` other than `origin`
  (`MigrationError::UnsafeSession`), fresh database or not.
- `crates/praetore-replay-postgres/migrations/.gitattributes` keeps the
  migrations LF (`*.sql text eol=lf`): their bytes are checksummed and
  compared.
- `verify_runtime_role` also refuses
  (`RuntimeRoleError::OwnerFunctionExecutable`) a SECURITY DEFINER function
  outside `pg_catalog`/`information_schema` that runs with the praetore
  owner's rights and that the runtime role may execute.
- The baseline check also refuses SECURITY DEFINER functions outside
  `praetore` that run with the owner's rights; any role that can act as the
  owner other than the migrating role and NOLOGIN groups it belongs to (the
  owner must be the migrating role or such a group); `FOR ALL TABLES` and
  `TABLES IN SCHEMA praetore` publications. The dump adds sequence
  parameters, index flags (`indisvalid`, `indisready`, `indislive`,
  `indimmediate`), `relhastriggers`, `relhasrules`, replica identity, access
  method and the column collation with its schema. The comparison and the
  recording of 0001-0009 now run in one transaction with the praetore
  tables locked, and a failing comparison names the server's error.
- Limits of the baseline check: it inspects an untrusted database from
  inside it and is best effort. It is structural only (stored rows are not
  validated; a legitimate `VALIDATE CONSTRAINT` on the `NOT VALID` foreign
  keys is refused), and it cannot defend against a superuser who edits the
  system catalogs directly.
- New ignored PostgreSQL tests, run in CI with `--exact`, one per case
  above.
- **BREAKING (engine, Development mode): no `action_type` fallback for rule
  capabilities.** In Development, a matching `Allow` or `RequireApproval`
  rule without `required_capability` was still applied when the authority
  also granted the action's `action_type`. It is now denied in every mode,
  as Strict and HighAssurance already did: the decision is `Deny` with
  reason `policy rule '<id>' must declare required_capability` and
  `decided_by` engine guard `unbound_rule_capability`. Actions without a
  capability stay denied in Development (engine guard `missing_capability`)
  and rejected with `INVALID_REQUEST` in Strict and HighAssurance. Deny
  rules without `required_capability` are unaffected. The receipt format is
  unchanged; no golden file or signed fixture changed.

  Migration (Development only; Strict and HighAssurance behave as before):

  ```rust
  // Before: allowed in Development when the authority granted "read_data".
  PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
  // After: the rule names the capability it requires.
  PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
      .with_capability("read_data")
  ```

  In policy JSON, set `"required_capability"` on every `Allow` and
  `RequireApproval` rule. Every action still needs
  `Action::with_capability(...)`.
- Engine construction has no default mode. This was already the case since
  0.2.0 (`new` and `with_clock` were removed in #6) and is now pinned by
  `compile_fail` doc tests: `AuthorizationEngine::new(..)` and
  `AuthorizationEngine::default()` do not compile. Choose the profile by
  name: `AuthorizationEngine::development(policy)` /
  `development_with_clock(policy, clock)` (explicit, unsigned, local only),
  `strict(policy, pins)`, or `production(policy, HighAssuranceConfig)`.
- Docs: README, `docs/crypto-and-policy.md`, `docs/policy-language.md`,
  ADR-002, ADR-005 and the threat model no longer describe deprecated
  `new` / `with_clock` compatibility constructors (they no longer exist) and
  document that the rule-capability requirement applies in every mode.
- Runtime connections now pin search_path. Every runtime transaction
  (`praetore_replay_postgres::set_tenant_context`, now public; also used by
  `praetore journal-export`, `praetore approve` and `praetore dispatch`)
  sets `search_path = pg_catalog, pg_temp` for the transaction and calls
  `pg_catalog.set_config`; `DatabaseConnector` starts sessions with the same
  search_path. `verify_runtime_role` runs its checks under that search_path
  and also refuses a per-database or per-role `search_path`, `row_security`
  or `session_replication_role` setting, a non-default session-start value
  of `row_security` or `session_replication_role`, parameter grants on
  them, a session search_path that does not start with `pg_catalog`, and a
  session with `session_replication_role` other than `origin`
  (`RuntimeRoleError::TriggersDisabled`, `RuntimeRoleError::UnsafeSetting`).
  It also refuses praetore objects that depend on functions, operators,
  types or collations outside `pg_catalog` and `praetore`
  (`RuntimeRoleError::ForeignDependency`).
  The checks run once at startup; `praetore-observe` now runs them too,
  and `praetore doctor` reports the effective relaxations.
  Only the `search_path` refusals can be relaxed, explicitly, with
  `PRAETORE_RUNTIME_ALLOW_SETTINGS=search_path` (exact names; anything else
  is a configuration error; the effective setting is logged at startup), or
  `verify_runtime_role_with` and `RuntimeRoleOptions` in the library.
  `DatabaseConnector` refuses URL `options` that end with an unescaped
  backslash. The documented `praetore_observe` grant now includes
  `tenant_id`, which the reader's queries need. `docs/operations.md`
  documents the runtime refusals.
- SAF-14 (proposal, `docs/proposals/SAF-14-identidad-por-agente.md`):
  per-agent identity. It records what the agent signature identifies today
  (one key per home in `praetore-mcp`, one key per profile in the Claude
  Code hook, no agent keys in the gateway) and proposes per-profile keys,
  per-client agents for `praetore-mcp`, and instance/session ids as signed
  claims. It gives attribution between cooperative agents, not isolation:
  every key is readable by the same OS user.
- `examples/claude-code-hook`: a receipt can no longer be re-attributed to
  another agent by editing an unsigned field. `verify` counted receipts by
  the unsigned `agent` field of `receipts.jsonl` and `export` copied it into
  `index.json`, which `verify.sh` only summarized; editing either changed who
  a receipt was attributed to with exit 0. Now `verify` and `export` read
  the agent and profile from the signed receipt and fail when the unsigned
  copy disagrees, `verify` checks the signing identity against
  `agents/<profile>.json`, and `verify.sh` runs `check-attribution.py`
  (fails on a mismatch, a missing index entry, or more than one identity per
  profile) and rejects a re-attributed copy of `index.json`. `init` adds an
  issuer-signed `praetore.agent_profile` constraint to each authority and
  the hook sends the same action parameter, so the engine refuses an
  authority issued for another profile (a profile file copied over another
  now fails closed instead of signing as the other agent). Claude Code's
  `agent_id` and `session_id`, when present, are recorded in the signed
  context (over 128 bytes: deny). `index.json` gains `agent_id`. The receipt
  format does not change; the committed evidence sets still verify. New
  `test-attribution.sh` (in CI).
- `examples/claude-code-hook`, fixes from the independent review of #79:
  `verify.sh` and `check-attribution.py` accept in `evidence/` only regular,
  non-hidden `*.json` files and fail on anything else. Before, a hidden
  `evidence/.X.json` with broken signatures skipped `praetore-verify` (the
  bash glob ignores dotfiles) but was counted in the attribution (exit 0).
  An explicit `agent_type: "main"` (a subagent named `main`) no longer gets
  the main session's profile; explicit `main` and `unregistered` are
  evaluated as `unregistered` (Deny, signed receipt), and the default
  policy's context conditions match the signing `profile` instead of the raw
  `agent`. State created before the `praetore.agent_profile` constraint now
  fails closed with a message to re-run `init`. A numeric `agent_id` or
  `session_id` is recorded as its canonical text; one that is not a string
  or number, or over 128 bytes, is denied under `unregistered` with a signed
  receipt that records the reason in `praetore.claim_rejected`, not the
  value. Summaries show unregistered `agent_type` values escaped to ASCII.
- `examples/claude-code-hook`, second review of #79: `verify.sh` copies the
  bundle to a temporary directory first and runs every step on that copy,
  so it verifies and attributes the same bytes (a receipt replaced in the
  original between steps 3 and 5 used to be counted unverified, exit 0).
  `check-attribution.py` and the hook's `verify` fail on a repeated receipt
  (same `evidence_id`, or same agent id and `request_id`), which counted one
  decision several times. `test-verify.sh` now signs 1000 distinct receipts
  with the hook instead of copying `bundle/`, since copies of one receipt
  are now an invalid bundle.

- Policy loading reports size, depth, node, integer, duplicate-key,
  malformed-JSON and unknown-field rejections with typed errors
  ([#23](https://github.com/Mavericksantander/praetore/issues/23)); wrong
  types, missing fields and unknown enum variants are still
  `PolicyEvaluationFailed(String)`. The error
  code of all of them stays `POLICY_EVALUATION_FAIL`, so `praetore-verify`,
  the CLI, the gateway and `praetore-mcp` report the same codes as before.
  Receipts and policy digests are unchanged.
  - New `praetore_core::canonical::JsonError` and `parse_json_strict`: the
    strict parser, `validate_json_value` and the canonical encoder return
    a typed reason (input size, malformed with line and column, duplicate
    key, value size, depth, node count, unsafe integer, canonical size).
    `parse_json_rejecting_duplicates` keeps its `String` error and messages.
    `MAX_JSON_NODES` is now public.
  - `Policy::validate` maps canonical-size errors to
    `PolicyLimitExceeded { CanonicalBytes }` from the typed error, without
    matching the `"exceeds maximum size"` message.
  - Breaking: new `PolicyLimit` variants `InputBytes` (raw text passed to
    `Policy::from_json` over 64 KiB), `JsonDepth` and `JsonNodes`. A
    decoded value over 64 KiB is `CanonicalBytes`. These used to be
    `PolicyEvaluationFailed(String)`.
  - Breaking: new `PraetoreError::PolicyDocumentInvalid(PolicyDocumentError)`
    with `Malformed { line, column }`, `DuplicateKey`,
    `UnknownField { field }` and `UnsafeInteger`, for policy documents that
    used to fail with `PolicyEvaluationFailed(String)`. Wrong types, missing
    fields and unknown enum values are still `PolicyEvaluationFailed`.
  - Breaking: `MAX_CONDITION_SET_VALUES` (256) now caps the total number of
    array elements in a condition's expected value, across every array at
    every depth, not only the top-level `In` set. A flat `In` set of 256
    values is still accepted; a policy whose expected value holds more than
    256 array elements in total is now rejected with
    `PolicyLimitExceeded { limit: ConditionSetValues, max: 256 }`, shown as
    "policy limit exceeded: array elements in a condition's expected value
    (total across all nested arrays) (maximum 256)".
  - **Limit:** at most 256 array elements per condition, counted as one total
    over every array in its expected value (the `expected` array itself and
    arrays nested in arrays or objects, at any depth). Elements are counted,
    not leaves: `[[]]` counts 1, `[[0]]` counts 2; object keys do not count;
    the cap is per condition, so two conditions of 256 in one rule are
    accepted. Only `Exact` and `In` can hold such values. No policy in this
    repository is affected.
  - Messages for integral floats outside the safe range now say "JSON
    integer exceeds interoperable safe range".

- A combined decision's signed `reason` now names the same rule as its
  `decided_by`. When a DENY rule matched before a RECOVER rule
  (`[deny d, recover r]`), `decided_by` and the recovery obligation named `r`
  but `reason` named `d`; the reason now follows the rule with the higher
  effective severity (RECOVER > DENY > REQUIRE_APPROVAL > ALLOW, earlier rule
  on a tie), so it no longer depends on rule order. Only the `reason` text of
  that combination changes. The receipt format is unchanged and receipts
  signed with the old reason still verify (integrity, attester signature and
  policy digest; see
  `receipt_with_the_previous_deny_then_recover_reason_still_verifies` in
  `tests/core/decision.rs`). Dispatch revalidation (`RecordedDecision::records`)
  only handles ALLOW/REQUIRE_APPROVAL receipts, which never carry a recovery
  obligation, so it is not affected. New black-box decision tests live in
  `tests/core/decision.rs` (the `decision` test target of `praetore-core`);
  the empty `tests/{core,integration,python,security}` placeholders are gone.
- **Breaking (`praetore-verify evidence --issuer-pins`):** the embedded
  authority and its issuer pin are now checked at the receipt's signed
  decision time instead of the verifier's clock. For HighAssurance receipts
  that is `decided_at`, the engine clock at evaluation, covered by the context
  hash and the attester signature. A HighAssurance receipt whose authority has
  since expired now verifies; one whose `decided_at` falls before the
  authority's `not_before` or after its `not_after` now fails, whatever the
  current time. Receipts without HighAssurance metadata (v1, v3/v4 without
  it) record no signed time and are still checked at the current time; this
  includes the committed hook evidence sets 03, 04 and 05 and both bundles,
  so sets 04 and 05 still stop verifying on 2027-01-29. JSON and text output
  add `authority_checked_at` (RFC 3339) and `authority_checked_at_source`
  (`receipt_decided_at` or `verifier_clock`). A pass shows the authority was
  valid at that instant, not that it is valid now; anyone holding the
  attester key can sign a back-dated `decided_at`, and it passes even after
  the issuer pin expires, since the pin is also checked at `decided_at` and
  the attester pin has no validity window. Text output prints
  `authority_checked_at_source` right after the result code. New optional
  `--require-decision-time` (off by default): a receipt without a signed
  `decided_at` fails with `DECISION_TIME_MISSING` instead of falling back to
  the verifier clock (`journal` does not check authorities and rejects the
  flag). The `authority` subcommand and its `--now` are unchanged. Planned
  when sets 04 and 05 are re-recorded with HighAssurance receipts (before
  2027-01-29): `--require-decision-time` becomes the default with an explicit
  `--allow-verifier-clock`, and the attester pin gets a validity window.
- `examples/claude-code-hook/verify.sh` no longer exits with 141 on large
  bundles. It took the receipt for the tamper check with
  `ls evidence/*.json | head -1`; with a few hundred receipts `head` closed
  the pipe, `ls` got SIGPIPE and `pipefail` ended the script with 141 after
  every receipt had verified. It now uses a bash array from the glob. The
  policy binding is checked by `praetore-verify evidence --policy` instead of
  a Python comparison per receipt, so the exit code is 0 only when
  praetore-verify accepts every receipt and rejects the altered copy, and 1
  otherwise; the `index.json` summary is informational. New
  `examples/claude-code-hook/test-verify.sh` (in CI): 1000 receipts exit 0
  (141 before the fix), one altered receipt among them exits 1 and is named.
  `scripts/record-hook-demo.sh` had the same `ls | head` and is fixed too.
- **T-013B:** new crate `praetore-sandbox-fs` (Unix, `#![forbid(unsafe_code)]`,
  built on `rustix`, which was already in `Cargo.lock`): file effects beneath
  a sandbox root made through directory descriptors, never through a joined
  path. On Linux the parent directory is opened with one `openat2(...,
  RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
  RESOLVE_NO_XDEV)`; on `ENOSYS` and on macOS, one
  `openat(O_NOFOLLOW | O_DIRECTORY)` per component. The final component is
  created with `O_CREAT | O_EXCL | O_NOFOLLOW`, replaced with `renameat`,
  removed with `unlinkat` relative to the parent descriptor, and opened with
  `O_NOFOLLOW | O_NONBLOCK` plus an `fstat` check. Existing hard links
  (`st_nlink > 1`), symlinks, FIFOs, sockets and devices are refused.
  `praetore_gateway::sandbox::SandboxDispatcher` now performs its effects
  through it (refusal codes and receipt format unchanged; it already walked
  by descriptor, the new part is `openat2` and `RESOLVE_NO_XDEV`, which also
  refuses bind mounts). New race tests swap an intermediate directory for a
  symlink to an outside directory while writes and deletes run; they fail
  against a deliberately path-based reference
  (`PRAETORE_SANDBOX_FS_RACE_IMPL=path-based`). Not prevented: a directory
  moved out of the root while an operation is in flight, and hard links
  created after the check, both by a process that can also write outside
  the root. The ignored supervisor test `sandbox_dispatch_rejects_symlink_escape`
  is removed: it tested a layer that cannot see the Job's filesystem (#61);
  the case is covered in `praetore-sandbox-fs`.
  After independent review: the `ENOSYS` fallback is logged once and shown
  by `SandboxDispatcher::path_resolution()` (startup log and `praetore
  doctor`); `PRAETORE_SANDBOX_REQUIRE_OPENAT2=1` makes the gateway refuse to
  start without `openat2` and never fall back; `EPERM` from `openat2`
  (seccomp/LSM) is the permanent refusal `openat2_denied`, not a transient
  error. The crate refuses `TEMP_PREFIX` components itself (ASCII
  case-insensitive). New final-component race tests swap `t` with a
  symlink, a hard link or a directory during writes and deletes; the
  dispatcher race test now checks the refusal reasons.
## 0.3.1-rc.1 - 2026-10-31

- CI builds `praetore-mcp` release binaries for `x86_64-unknown-linux-gnu`,
  `aarch64-apple-darwin` and `x86_64-apple-darwin` on every run, runs
  `scripts/mcp-smoke.py` on each (a real allowed and a real denied
  `tools/call` through `@modelcontextprotocol/server-filesystem@2.1.0`, then
  `verify`), and uploads `.tar.gz` archives with `.sha256` files as workflow
  artifacts. `Release checksums` now runs on every run, not only on `v*`
  tags: `scripts/release-checksums.sh` checks each runner's `.sha256`, that
  all three targets are present, that each archive holds only the binary,
  `LICENSE` and `NOTICE`, and that nothing else is in the set, then writes
  and re-checks one `SHA256SUMS` (the three archives and `praetore-verify`).
  `scripts/test-release-checksums.sh` covers those failures. Only a `v*` tag
  keeps the result as the `release-assets-<tag>` artifact.
- A pushed `v*` tag now creates the GitHub Release (job `release-publish`):
  `SHA256SUMS` is signed with Sigstore keyless signing
  (`SHA256SUMS.sigstore.json`, verified against the workflow identity before
  publishing), the notes are the tag's `CHANGELOG.md` section
  (`scripts/release-notes.sh`, tested by `scripts/test-release-notes.sh`), an
  existing release is never overwritten, and `-` tags are pre-releases. On
  every PR the signing tooling is exercised with a throwaway key, including a
  changed `SHA256SUMS` that must not verify. CI still holds no long-lived
  signing key. The macOS binaries are not signed or notarized.
- `release-publish` now needs every other `assurance.yml` gate, not only the
  release artifacts; a tag that does not equal `v` plus the workspace version
  fails before anything is published; its checkout keeps no token; the
  signature check also pins the tagged commit
  (`--certificate-github-workflow-sha`). CONTRIBUTING documents how to recover
  from a failed release job. The smoke test runs on Node 24, which
  `@modelcontextprotocol/server-filesystem@2.1.0` requires.
- **Breaking (sandbox supervisor configuration): `schema_version` 1 → 2.**
  Every route must now declare a closed schema of its action's top-level
  `parameters`. At dispatch, before any Kubernetes request, the supervisor
  answers 400 if `parameters` is not an object, has a key the route does not
  declare, has a value of another kind, or lacks a required key. Only `path`
  and `path_list` values get the lexical path check; free text in `string`
  values is not path-checked. The check is fail-closed and much stricter
  than in 0.3.0. A `path` value, and every `path_list` element, is split on
  both `/` and `\`; every segment must match `[A-Za-z0-9._-]+`, must not
  start with `.` or `-`, and must be at most 255 bytes; the whole value must
  be at most 1024 bytes (the in-process sandbox dispatcher's
  `MAX_COMPONENT_BYTES` and `MAX_PATH_BYTES`). As a consequence the
  supervisor refuses:
  - an empty value, an empty segment (`a//b`, a trailing separator as in
    `dir/`) and the segments `.` and `..`;
  - hidden names such as `.env` or `a/.git/config`, and `...` (a leading
    `.` is rejected on purpose; this may be relaxed later);
  - option-like names such as `-rf`, `--` or `a/-n`, in case a tool profile
    passes a path to a subprocess without `--`;
  - a segment longer than 255 bytes or a value longer than 1024 bytes;
  - a leading `/`, `\` or `~`, and a drive or UNC prefix;
  - spaces and punctuation outside `._-` (`+`, `@`, `~`, `%`, `:`, ...);
    `%` is always refused, including names such as `100%.txt`;
  - every non-ASCII character, including accented letters and homoglyphs
    such as Cyrillic `а` (U+0430) or full-width `ａ` (U+FF41);
  - control characters, Unicode format (Cf) and bidi characters, and
    U+2028/U+2029 (also checked explicitly, as defense in depth).
  - Not covered, because runners are Linux only: Windows reserved device
    names (`CON`, `NUL`, `COM1`, `aux.txt`) and trailing dots (`a.`, `x..`).
  - By design, only keys declared `path` or `path_list` are path-checked: a
    `string` value such as `../../etc/passwd` is accepted. Declare as `path`
    every key the runner uses as a path.
  - Path migration for callers: send `x` instead of `./x` and `dir`
    instead of `dir/`, and rename files whose names use spaces, non-ASCII
    letters, other punctuation or a leading `.` or `-` (for example
    `informe año 2026.txt` → `informe_ano_2026.txt`, `.env` → `env`) before
    routing them through a `path` or `path_list` parameter. Free text
    belongs in a `string` key.
  - Kinds: `path`, `path_list` (array of at most 64 `path` values, each
    checked), `string`, `integer`, `boolean`. Nested objects are not
    supported.
  - Schema keys must match `[a-z0-9_]+` (at most 256 bytes); otherwise the
    configuration is refused at startup. Rename keys such as `orderId`,
    `order-id` or `Path` to `order_id` or `path`.
  - `"key": "kind"` declares a **required** key. A key is optional only when
    written as `"key": {"kind": "...", "optional": true}`.
  - A version 1 file is refused at startup, not upgraded.
    `SandboxSupervisor::new` returns, and `praetore-sandbox-supervisor`
    exits with (`main` returns the error, so it is printed as
    `Error: "<message>"`):
    ```
    sandbox supervisor configuration must have schema_version 2 (version 1 has no per-route `parameters` schema; see the CHANGELOG for the migration)
    ```
  - Migration: set `"schema_version": 2` and add `parameters` to every route.
    Before (v1):
    ```json
    {"schema_version": 1, "runner_image": "…@sha256:…", "routes": [
      {"tenant_id": "…", "action_type": "orders:create", "target": "orders-api",
       "capability": "orders:write", "tool_profile": "orders-create"}]}
    ```
    After (v2):
    ```json
    {"schema_version": 2, "runner_image": "…@sha256:…", "routes": [
      {"tenant_id": "…", "action_type": "orders:create", "target": "orders-api",
       "capability": "orders:write", "tool_profile": "orders-create",
       "parameters": {
         "order_id": "string",
         "quantity": "integer",
         "attachments": {"kind": "path_list", "optional": true}}}]}
    ```
    Declare every key the tool actually receives: after the upgrade, a
    request with an undeclared key is refused.
- `praetore journal-export --tenant` orders the journal rows by
  `(created_at, request_id, agent_id)`. `(created_at, request_id)` was not a
  total order (the key is `(tenant_id, agent_id, request_id)`), so two exports
  of the same journal could differ. It now warns on stderr when the database
  role is not the least-privilege runtime role. New PostgreSQL tests: export
  as a login member of `praetore_runtime` confined by RLS without the SQL
  filter, fail closed without the tenant setting, no writes; row order with
  ties; and `praetore journal-export --tenant` plus `praetore-verify journal`
  end to end against two gateways.
- Hash-linked JSONL export of receipts, as specified in
  `docs/proposals/journal-chain-jsonl.md` (now marked implemented):
  - `praetore_core::journal_chain`: the format, the link
    (`SHA-256("PRAETORE_JOURNAL_LINK_V1\0" || u64_be(seq) || prev ||
    context_hash || attester_signature)`), a producer (`ChainExporter`) and a
    verifier (`verify_chain`) that share it.
  - `praetore journal-export (--receipts-dir DIR | --tenant UUID)
    --attester-pin HEX_FILE --output NEW_FILE` builds a chain from a
    directory of receipts or from one tenant's `praetore.execution_journal`
    rows, checking every receipt against the pinned attester key first. It
    never overwrites the output.
  - `praetore-verify journal --journal JSONL --attester-pin HEX_FILE
    [--expected-head HEX] [--policy PATH]`, brought from
    `feat/journal-chain-verifier` (`bfeade5`) by cherry-pick. Changes from
    `bfeade5`: it uses the shared core code; adds `--expected-head`
    (`JOURNAL_HEAD_MISMATCH`); every line, including the last, must end in
    `\n` and `\r` is rejected (before, `lines()` accepted CRLF and a missing
    final newline, and a file with only `\n` failed as `JOURNAL_CHAIN_FAIL`,
    now `INVALID_REQUEST`); failures print the entry on stderr; test fixtures
    updated for `Decision::allow(reason, DecidedBy)`.
  - `examples/claude-code-hook/evidence/0{3,4,5}-*/journal-chain.jsonl`
    (22, 8 and 118 entries; receipts unchanged), heads in `VERIFY.md`,
    `verify-chain.sh`, and a `journal-chain` CI job that rejects a deleted,
    deleted-and-relinked, truncated, reordered and altered copy.
  - Limit: the link is unkeyed. Anyone with the receipts can rebuild a chain
    over a subset, and the attester key holder can rebuild anything. A head
    only detects deletion or truncation if it was published outside the
    producer's control and passed as `--expected-head`; the heads in this
    repository are not such an anchor.
- **T-014, `praetore-mcp`:** arguments covered by a `PathPrefix` rule are
  resolved through the filesystem before evaluation. Unless an absolute value
  resolves to itself (no symlink, `.`/`..`, dangling link or missing parent),
  the engine sees `praetore-mcp:path-check-failed`, which core treats as an
  unsafe path (every DENY / REQUIRE_APPROVAL `PathPrefix` rule matches, no
  ALLOW one). Receipts record `context["praetore.path_check"]`; forwarded
  bytes are unchanged. Core's `PathPrefix` stays lexical. Behavior change: on
  macOS, `/tmp/...` arguments under such a rule are now refused or not
  allowed; use resolved paths. `policy` commands and `policy check` warn
  about prefixes that resolve elsewhere. The check is point-in-time (TOCTOU).
  A path that resolves to itself but is at or under a policy `PathPrefix`
  only when compared like the filesystem compares names (case folding and/or
  NFC: APFS, HFS+, casefolded ext4/f2fs, unknown filesystems), not byte for
  byte, is `ambiguous` and hidden the same way; this covers case and NFD
  variants of a denied name that does not exist yet. Case folding is full
  Unicode case folding (new dependency `caseless`) iterated to a fixed point
  (`ẞ`/`ß`/`ss`). A path that reaches a prefix's directory under another
  spelling, compared by `(st_dev, st_ino)` (macOS `/System/Volumes/Data`
  firmlinks, a bind mount of the prefix itself), is `ambiguous` too, and so
  is a path whose other macOS spelling (`/System/Volumes/Data` added or
  removed) is under a prefix (DENY `/System/Volumes/Data` covers
  `/Users/...`). `policy check` warns about prefixes that are `/System`,
  `/System/Volumes`, or at or under `/System/Volumes/Data`. On Linux, XFS
  folds (it may be `ascii-ci`), and case-folding filesystems ignore trailing
  dots and spaces. On macOS, an argument whose first segment starts with
  `.` (`/.nofollow/...`, `/.resolve/...`, `/.vol/...`) is `unresolved`, and
  so is, on every OS, anything under `/dev` or `/proc` (per-process names
  such as `/dev/fd/N`), and on macOS under `/System/Volumes/<X>` other than
  `Data`. When names fold, Unicode 16 `Default_Ignorable_Code_Point`s and
  U+F000-F0FF are dropped from the fold key (HFS+, macOS ExFAT), and a
  segment made only of them is `unresolved`. `wrap` warns at startup when
  the server command looks like `docker`, `podman`, `ssh`, `chroot`, ...
  and the policy has path rules. This is defense in depth for local
  servers in the same namespace, not a guarantee (structural fix: T-013B).
  Not covered: Linux bind mounts of a subdirectory of a prefix, hard links
  to files inside a prefix, TOCTOU, server-side decoding; not supported:
  other namespaces or hosts, network/FUSE loopback mounts.

## 0.3.0 - 2026-10-30

- The gateway-service sandbox supervisor rejects a dispatch request when any
  string value in `action.parameters`, at any depth, contains NUL, starts at
  a root (`/` or `\`), has a drive or UNC prefix, or has a `..` segment
  (T-013 fix A, lexical only; `/` and `\` are both checked on every OS).
  Symlinks are not resolved yet (fix B, stage 2).
- `crates/praetore-mcp/GUIDE.md`: a guide for external developers with a
  first-run walkthrough, the limits (only MCP `tools/call` through a wrapped
  server is governed; LOCAL/DEV keys; no approval flow for REQUIRE_APPROVAL;
  lexical path rules; TOCTOU) and a troubleshooting table.
- `praetore-mcp install`/`uninstall` process a config file once when two
  default paths name it (Cursor's `~/.cursor/mcp.json` and
  `./.cursor/mcp.json` when run from `~`, or a symlink). Before, it was
  listed twice; the second pass was skipped as already wrapped. The
  praetore-mcp README records the real-app check on macOS (Claude Desktop
  and Cursor).
- The praetore-mcp README documents installing without a clone:
  `cargo install --git https://github.com/Mavericksantander/praetore
  praetore-mcp --locked` (checked on macOS arm64 against `9735974`).
- `praetore-mcp <command> --help` / `-h` prints that command's usage and
  exits 0 (it used to fail with `unexpected argument "--help"`). `--help`
  after `wrap ... --` is still passed to the MCP server. `praetore-mcp
  version` is an alias of `--version`. Exit codes (0, 1, 2, and `wrap`'s
  server code / 127) are documented in `--help` and the praetore-mcp README.
- `praetore-mcp wrap --mode observe` no longer forwards `tools/call` without
  receipts when the home cannot be loaded at startup (not initialized, or
  invalid keys, pins, authority or policy). Both modes now refuse every
  `tools/call` in that case and print `every tools/call will be REFUSED`;
  other MCP traffic is still relayed. Per-call evaluation errors after a
  successful start keep the documented observe behavior.
- New receipts always record what decided them in `decision.decided_by`, as
  part of the hashed and Ed25519-signed evidence payload, in the new
  **evidence schema v4**:
  - `DecidedBy::Rule { rule_id }` (a rule's declared effect applied; a
    RECOVER rule's `rule_id` equals its recovery obligation's),
    `UnboundRule { rule_id }` (a REQUIRE_APPROVAL/RECOVER rule matched
    without its required capability or target and denied instead),
    `DefaultDeny` and `EngineGuard { guard }`. Combining decisions keeps the
    decider of the higher severity (`Recover > Deny > RequireApproval >
    Allow`), the earlier one on a tie.
  - Versioning: every new evidence is v4 (with or without HighAssurance
    metadata and recovery). v1-v3 must not carry `decided_by`, so existing
    receipts, golden vectors and fixtures keep verifying byte-for-byte; v4
    must carry it. `decided_by` must be consistent with the outcome,
    recovery obligation and contributions; unknown kinds, unknown fields and
    an explicit `null` are rejected.
  - Upgrade order: binaries without v4 support reject v4 evidence (fail
    closed). Upgrade every verifier, Python binding and gateway node before
    any node starts producing v4; during a mixed-version rollout or after a
    rollback, journal rows and pending approvals written by new nodes are
    unreadable (`InvalidRecord`) on old ones.
  - Breaking: `Decision` has a required `decided_by: DecidedBy` (JSON without
    it does not deserialize); `Decision::allow/deny/require_approval` take it
    as a second argument (`Decision::recover` derives it from the
    obligation). `Evidence.decision` is now a `RecordedDecision` (the read
    path) whose `decided_by` is optional, crate-private and read via
    `decided_by()`; `Decision` converts with `.into()`. `Evidence::new` and
    `attest` reject a decision that violates these invariants. Consumers that
    compared `evidence_schema_version` to 2/3 should use
    `is_high_assurance_shape()` and `decision.recovery`.
  - Dispatch revalidation compares a legacy (pre-v4) record on every field
    except `decided_by`, so approvals pending across the upgrade can still be
    dispatched; v4 records must match `decided_by` too.
  - Test fixtures in `packages/praetore-python/tests/fixtures` were
    regenerated as v4; the previous v1/v2 bytes are kept in
    `fixtures/legacy-evidence/` and still verify.
- New crate `praetore-mcp` (binary `praetore-mcp`): a local stdio MCP proxy
  for Claude Desktop, Cursor and VS Code that needs no PostgreSQL and no Rust.
  `init` creates LOCAL/DEV issuer, agent and attester keys (0600), a signed
  authority, `praetore-verify`-compatible trust pins and a default v2 policy.
  `wrap` evaluates every client→server `tools/call` in HighAssurance mode and
  appends attested evidence to an fsynced JSONL journal. In `observe` mode
  (the default) calls are always forwarded and only recorded. In `enforce`
  mode DENY and REQUIRE_APPROVAL are blocked with an MCP `isError` result,
  and errors fail closed. The mode is bound into the signed evidence as
  `context["praetore.mode"]`. `install` / `uninstall` rewrite and restore
  client configs, writing a backup and asking for confirmation first.
  `receipts` and `verify` read and check the journal. `policy
  list|check|deny|require-approval|allow|remove` manage rules without
  hand-written JSON. Each change is validated, written atomically with a
  backup, and refused when it would create an unscoped argument rule unless
  `--any-tool` is given. Limitations: stdio
  only, REQUIRE_APPROVAL is not supported, LOCAL/DEV keys only, and receipts
  attest the proxy's view of a call, not the upstream agent's intent. See
  `crates/praetore-mcp/README.md`. `praetore-core` is unchanged.
- `praetore-verify evidence` accepts `--policy PATH`: the receipt must record
  that policy's digest (`Evidence::verify_policy`); receipts without a digest
  fail with `POLICY_MISMATCH`.
- The hash-linked journal export (`praetore-verify journal`) is a proposal
  only (`docs/proposals/journal-chain-jsonl.md`). It is not shipped: the
  verifier is kept on branch `feat/journal-chain-verifier` until a Postgres
  exporter lands with it in one PR. As specified (unkeyed links, no signed
  or published head) it does not let a third party detect deletion,
  truncation, reordering or a recomputed chain; the proposal lists what is
  missing.
- `scripts/regen-legacy-evidence-fixture.sh` regenerates the legacy receipt
  fixture (no `policy_digest`) from commit 3db7b5e.

- Breaking (core): `Evidence::sign` now refuses to sign a receipt that does
  not record the full lowercase SHA-256 digest of the active policy
  (`policy_digest`, from `Policy::digest()` over the canonical JSON). The
  engine already bound it in every mode; this makes it a hard requirement of the write path, so the
  Ed25519 attester signature always covers which policy decided. Receipts
  signed before this change (no `policy_digest`) still deserialize and verify.
  Callers that sign evidence directly (not through `PolicyEngine`) must call
  `Evidence::bind_policy_digest` first.
- New `Evidence::verify_policy(&Policy)` checks that a receipt was decided
  under a given policy (digest present and equal). Legacy receipts without a
  digest return an error.
- Known limitation (accepted): legacy receipts whose `policy_digest` was
  recorded in uppercase hex still deserialize and verify, but cannot be
  re-signed, because `Evidence::sign` only accepts the lowercase SHA-256 hex
  produced by `Policy::digest()`; `verify_policy` also rejects them.
- Security (gateway HTTP API): caller authentication. `http_api::router` and
  `serve_local` now take an `ApiAuth`. `ApiAuth::Required(ApiCredentials)`
  requires `Authorization: Bearer` on every endpoint except `/healthz`, with
  tenant-scoped credentials (SHA-256 digests, constant-time comparison) whose
  tenant must match the `{tenant_id}` path segment or, for `/v1/execute`, the
  submitted authority's tenant. Roles are disjoint: `agent` may execute and
  read status; only `approver` may read challenges, decide and dispatch.
  Unauthenticated: 401 `authentication_required`; wrong role or tenant: 403
  `caller_not_authorized`.
  - Breaking (gateway service): `PRAETORE_GATEWAY_API_CREDENTIALS_FILE` is
    required with the `http` and `sandbox` adapters and for any non-loopback
    `PRAETORE_GATEWAY_LISTEN_ADDR`. Only `local-demo` on loopback may run
    unauthenticated, and `local-demo` never listens beyond loopback.
  - The freshness snapshot is read with a bounded read (not only a
    `metadata` size check), and a snapshot whose `issued_at` is older than
    one already loaded is refused (fail closed), so a stale sync or restored
    backup cannot undo a revocation.
  - Breaking (CLI): `praetore init` creates `agent-api.token` and
    `approver-api.token`; `run`, `demo`, `approve`, `reject` and `dispatch`
    use them. Older demo directories need a fresh `init`.
- Security (gateway): approver keys can be bound to a tenant
  (`HumanApprovalVerifier::for_tenant`); the gateway accepts several
  verifiers and a key never verifies another tenant's decision. Service:
  new `PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE`; breaking: the single
  `PRAETORE_GATEWAY_APPROVER_KEY_ID`/`_PUBLIC_KEY_HEX` pair is rejected with
  `http`/`sandbox` unless exactly one tenant is issuer-bound (it is then bound
  to that tenant). The CLI demo approver is bound to the demo tenant.
- Security (gateway service): breaking: `http` and `sandbox` adapters require
  `PRAETORE_GATEWAY_FRESHNESS_FILE`, a file-based revocation snapshot
  (revoked authority IDs, agent key fingerprints, authority digests) with
  bounded staleness that fails closed when missing, invalid or stale
  (`PRAETORE_GATEWAY_FRESHNESS_RELOAD_INTERVAL_MS`, `_LEASE_MS`,
  `_MAX_SNAPSHOT_VALIDITY_MS`). The demo provider, which never checks
  revocation, is limited to `local-demo`.
- Security (gateway): `claim_dispatch` independently re-verifies the
  recorded approval (approve outcome, challenge bound to the persisted
  evidence and action digest, tenant-pinned approver signature, no
  self-approval) before dispatch, since `validate_evidence_for_dispatch`
  accepts `RequireApproval` evidence.
- Gateway: transient revalidation failures at dispatch claim (trusted clock,
  freshness source or replay storage unavailable) leave the execution
  `approved_pending_dispatch` instead of closing it as `dispatch_failed`.
- Gateway: new `ApprovalResolution::NotDispatched` (breaking for exhaustive
  matches) and `Gateway::approval_state`. The status endpoint reports
  `not_dispatched` plus `execution` and `not_dispatched_reason` for approved
  executions closed without dispatch, instead of `approved`.
- Breaking (gateway HTTP API): `GET /v1/approvals/{tenant}/{agent}/{request}`
  returns `{"challenge": ..., "action": ...}` (`ApprovalChallengeView`)
  instead of the bare challenge. `praetore approve`/`reject` show the action,
  verify its digest and policy digest, and require confirmation (`--yes` for
  scripts).
- Security (sandbox supervisor): worker callbacks are authenticated against
  the in-memory pending execution (constant time) before any Kubernetes API
  call; `serve_tls` takes `ConnectionLimits` (non-blocking accept, per-peer
  connection cap, header read timeout, 20 s worker connection lifetime).
- Dependencies: `praetore-gateway` now depends on `sha2` 0.11 and `subtle`
  2.6 (both already in the lockfile).

- Docs: HighAssurance replay claims are documented as keyed by
  `(tenant_id, agent_id, request_id)` (tenant from the signed authority, nil
  UUID when absent), matching the code; an action without a capability is
  documented as rejected (Strict/HighAssurance) or denied (Development), with
  no `action_type` fallback; canonical JSON key order is documented as UTF-8
  byte order, a deliberate deviation from RFC 8785's UTF-16 order (codec v1
  bytes unchanged).
- `AuthorizationEngine::validate_evidence_for_dispatch` is now documented as
  accepting ALLOW **and** REQUIRE_APPROVAL evidence (behavior unchanged; the
  gateway's post-approval path relies on it), and its error message says so.
  New `validate_allow_evidence_for_dispatch` additionally requires an ALLOW
  decision, for dispatch paths without a verified human approval.
- Security (breaking API): `Evidence::verify_key_rotation` now takes the
  trusted attester key (`&VerifiedPublicKey`) and requires a valid attester
  signature. It previously accepted an ALLOW decision protected only by the
  unkeyed `context_hash`, so anyone could forge an authorized rotation by
  rewriting the decision and recomputing the hash. Unsigned evidence (e.g.
  Development/Strict without an attester) no longer verifies as a rotation.
- Security (breaking for non-canonical input): uppercase or mixed-case hex is
  now rejected for authority signatures, `subject_key_hash` and
  `issuer_key_id` (`Authority::validate`), request intent signatures,
  evidence attester signatures, `Evidence::bind_policy_digest` and issuer pin
  public keys. `hex::decode` accepted both cases, so one signed document had
  several valid encodings. Everything this crate emits is lowercase.
- Fix: a gateway receipt for an executed or confirmed action whose adapter
  output was JSON `null` now verifies. `"output": null` deserializes to
  `None`, which verification rejected for those statuses although the
  attestation signs the digest of `null`. For `executed`/`confirmed`, an
  absent or `null` output is now verified as the JSON value `null`; other
  statuses still require no output. Serialization is unchanged, so existing
  receipts and fixtures are byte-identical.
- Security (behavior change, more restrictive, all semantics versions):
  DENY/REQUIRE_APPROVAL/RECOVER rules no longer stop applying because of
  their `required_capability` or `target`. An authority that lacks the rule's
  `required_capability` is still subject to the rule (previously
  `RequireApproval{transfer, payments:large, amount > 1000}` plus
  `Allow{transfer, payments:write}` let an authority without
  `payments:large` make large transfers without approval), and an action
  without a target matches a targeted restrictive rule (previously omitting
  the target bypassed `Deny target=prod-db`). ALLOW rules are unchanged.
  Targets stay exact, case-sensitive identifiers; this is now documented.
  Policies that used `required_capability` on a DENY rule to deny only the
  holders of that capability now deny everyone for that rule's scope.
  Such an *unbound* match (authority lacks the capability, or the action
  has no target) always contributes DENY, also for REQUIRE_APPROVAL and
  RECOVER rules: it never turns a default deny into an approvable request,
  and never emits a recovery obligation, for an authority the rule was not
  scoped to.
- Security (behavior change, more restrictive): an integer compared with a
  floating-point number no longer fails open in v1 policies. Previously a v1
  `Deny if amount > 10000` was bypassed with `"amount": 50000.0`, because
  every mixed integer/float comparison was "no match". Numeric operators now
  compare integer and float exactly (no lossy `f64` cast); `Exact`/`In`
  treat a numerically equal float as equal. In every semantics version the
  exact result applies to DENY/REQUIRE_APPROVAL/RECOVER rules, and an ALLOW
  rule never matches a mixed representation (unchanged). In v2 a mixed value
  that is definitively on the safe side of a restrictive rule (`5.0` against
  `> 10000`) no longer counts as unknown.
- **T-013:** `praetore_gateway::sandbox::SandboxDispatcher` (Unix), an
  `ActionDispatcher` executed by the gateway with a closed allowlist
  (`fs:write_file`, `fs:delete_file`) confined to a root directory.
  - Root: absolute, canonical, not `/`, owned by the gateway user, not
    group/other-writable and (macOS) without extended ACL entries; held open
    as a descriptor, refused (`sandbox_root_replaced`) if the path stops
    naming that directory and (`sandbox_root_insecure`) if owner, mode or
    ACL change later. Leftover temporary files are swept at open.
  - Paths: relative only; no `.`/`..`, empty components, NUL/control
    characters, `\`, Unicode bidi/zero-width format characters or the
    reserved `.praetore-tmp-` prefix (ASCII case-insensitive); bounded length and depth. Every
    component is opened with `openat(O_NOFOLLOW|O_DIRECTORY)`; symlinks at
    any level and mount points are refused. Targets must be absent or
    regular single-link files (no hard links, directories, FIFOs, sockets,
    devices).
  - Writes are atomic (`O_EXCL` temp file, `fsync`, `renameat`, directory
    `fsync`), mode `0600`, at most 16 KiB by default. Deletes use
    `unlinkat(…, 0)`: never a directory, never a symlink target.
  - Failures known to have happened before any effect reconcile as
    `not_applied`.
  - `praetore init --sandbox-root <dir>` / `sandbox_root` in `config.json`
    enables it in `praetore run` (fail closed if the root is invalid or
    contains/is inside the gateway directory); `praetore demo <dir> write
    <path> <content>` / `delete <path>` submit the two actions.
    `demo:set_value` is kept unchanged. No `exec`.
- New `ActionDispatcher::preflight` (default: admit) returning
  `DispatchRefused::terminal` / `::transient`. The gateway runs it at
  submission, on the approval challenge and decision, and in
  `claim_dispatch` after the approval is re-verified and the evidence
  revalidated, before the journal claim. Status never runs it (it reports
  journal state only).
  - A refusal at submission closes the execution (allowed or held for
    approval) as `not_dispatched` with the new signed reason
    `dispatch_refused`; a held approval closed this way is final and can
    never be approved, rejected or dispatched. HTTP 403
    `action_not_dispatchable` carries `reason` and the signed `receipt`.
  - At the claim, a terminal refusal closes `approved_pending_dispatch` as
    `not_dispatched` / `dispatch_refused`; a transient one leaves it
    `approved_pending_dispatch` (HTTP 503 `dispatch_temporarily_refused`).
  - A refused challenge or decision changes nothing and consumes nothing.
- New `NotDispatchedReason::DispatchRefused` (`dispatch_refused`, receipt
  schema v3), the only reason also valid for `allowed` executions
  (breaking for exhaustive matches; older verifiers reject it as unknown).
  Migration `0013_dispatch_refused` accepts it in the journal and
  attestation CHECKs, replaces the transition trigger with
  `validate_execution_journal_transition_v3` (the reason is write-once; an
  undecided requires_approval row may be closed with it), and refuses any
  human decision for an execution closed with a reason.
- **Breaking:** new `GatewayError::DispatchRefused { key, reason, transient,
  receipt }` variant.
- HTTP: `router_with_options` / `serve_local_with_options` (taking the same
  `ApiAuth`) with `HttpOptions::gateway_executes_effects`. Then
  `POST /v1/execute`, the approval challenge, decision, dispatch and
  `/status` require exactly one `praetore-exec-mode: gateway` header (exact
  value, at most 16 bytes), checked after caller authentication; otherwise
  409 `exec_mode_gateway_required` before the gateway is called. `/status`
  of an approved action answers 409 `cooperative_exec_rejected` with
  `resolution` and `execution` (also while `approved_pending_dispatch`), so
  an agent is never told to run it. Responses for effects performed by the
  gateway carry `praetore-executed-by: gateway`. The header is an
  unverifiable client declaration: it grants nothing and never changes who
  executes or what is journaled. The `praetore` CLI always sends it.
- Policy size and complexity limits are now public, documented constants in
  `praetore_core::policy`, and exceeding any of them rejects the whole policy
  with the typed `PraetoreError::PolicyLimitExceeded { limit: PolicyLimit, max }`
  (error code unchanged: `POLICY_EVALUATION_FAIL`). Nothing is ignored or
  partially applied.
  - Existing, now public: `MAX_CONDITIONS_PER_RULE` = 128 (per scope),
    `MAX_POLICY_TEXT_BYTES` = 1024 (ids, action type, target, condition key),
    canonical policy size `MAX_JSON_VALUE_BYTES` = 65 536.
  - `MAX_POLICY_RULES` = 512 (was 1024, unreachable). It sits above what
    fits in 64 KiB of canonical JSON (468 minimal rules with ids
    `r0`..`r467`; with minimal ids the canonical size limits it to fewer than 480 rules, below 512), so
    the canonical size remains the binding limit and no previously valid
    policy is rejected by the rule count.
  - Breaking: new `PraetoreError` variant; limit violations no longer surface
    as `PolicyEvaluationFailed(String)`.
  - Breaking: new limits that reject policies valid before this release:
    - capability longer than 1024 bytes (`MAX_POLICY_TEXT_BYTES`);
    - condition string (string or object key inside an expected value)
      longer than 1024 bytes (`MAX_CONDITION_STRING_BYTES`);
    - `In` (array value) with more than 256 values
      (`MAX_CONDITION_SET_VALUES`);
    - expected value nested deeper than 8 (`MAX_CONDITION_VALUE_DEPTH`).
  - The policy engine has no regular expressions, so there is no pattern limit.
- Policy validation now rejects contradictory `PathPrefix` conditions on the
  same key using segment semantics: two unrelated path prefixes (`/a` and
  `/b`), or an `Exact` safe path outside a `PathPrefix` (`/b/x` with `/a`).
  `PathPrefix` against `Prefix` is rejected only when the two are lexically
  unrelated (conservative).
- Documented over-restriction (fail closed): an unsafe value (`%`, `..`, and
  for `PathPrefix` anything not absolute and normalized) matches `Deny` and
  `RequireApproval` rules on `Prefix`/`PathPrefix` even if it lies outside the
  rule's prefix; for example a deny on `/srv/secret` also denies
  `/home/50%.txt`. Pinned by tests.

- Security: `MatchOperator::Prefix` treats a value with a `..` segment
  (split on `/` or `\`), any `%`, or a NUL as unsafe. Previously an allow
  rule with prefix `/srv/agent/` matched `/srv/agent/../../etc/passwd`.
- New `MatchOperator::PathPrefix` (`PolicyCondition::path_prefix`): purely
  lexical, whole-segment path prefix. Rule prefix and value must be absolute
  and normalized (no `.`, `..`, empty segments, `\`, NUL or `%`; the engine
  does not percent-decode). Invalid rule prefixes are rejected when the policy
  loads.
- Unsafe values for `Prefix` and `PathPrefix` always match `Deny` and
  `RequireApproval` rules and never match `Allow` rules, in both semantics
  v1 and v2 (fail closed; keeps v1 deny rules effective).
- Lexical limits, documented and pinned by tests: no filesystem access
  (symlinks out of scope), no Unicode folding (fullwidth `．．`, U+2215),
  spaces are significant, `...` is an ordinary name. No downstream layer may
  NFKC-normalize or percent-decode an authorized value.
- Behaviour change: allow rules using `Prefix` on values that contain `%`
  (for example percent-encoded URLs) no longer match.
- Breaking: `MatchOperator` is now `#[non_exhaustive]`; exhaustive `match`es
  outside `praetore-core` need a wildcard arm.

- Storage security (PostgreSQL journal and deployment templates):
  - Migrations: each migration and its `schema_migrations` row now commit in
    one transaction. 0007-0009 contain their own `BEGIN;`/`COMMIT;`, which
    used to end the runner's transaction early (a crash in between left the
    migration applied but unrecorded); the runner strips one enclosing
    top-level pair and refuses any other transaction control. Migration files
    and checksums are unchanged.
  - New migration 0011 creates the NOLOGIN group role `praetore_runtime`
    (needs `CREATEROLE`, or pre-create it) with least-privilege grants. New
    migration 0012 makes SQL refuse `approved_pending_dispatch -> dispatched`
    without an approve decision, with an expiration receipt, or with
    `expires_at` at or before the gateway observation time
    (`praetore.dispatch_observed_at`, set by `claim_dispatch`).
  - TLS: all PostgreSQL connections go through `DatabaseConnector`
    (rustls). Non-loopback hosts require `sslmode=verify-full` and
    `sslrootcert`; `prefer`/`require`/`verify-ca` are refused. The URL is
    checked before any socket is opened.
  - Breaking (gateway service): new `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`
    and `praetore-gateway-demo migrate`. With `PRAETORE_GATEWAY_ADAPTER=http`
    or `sandbox` the runtime URL no longer runs migrations, and startup
    refuses a runtime role that is superuser, `BYPASSRLS`, owns `praetore`
    objects or can create in the schema, or a schema that is not current.
    The loopback-only database check is replaced by the TLS rule above, so
    remote databases (for example in `praetore-data`) work with
    `verify-full`. The local demo and the CLI still migrate with the runtime
    URL when no migration URL is set and only warn (development only).
  - Breaking (public API): `MigrationError` has new variants
    `ExplicitTransactionControl` and `Pending`; new `DatabaseConnector`,
    `verify_runtime_role`, `verify_schema_current`.
  - Kubernetes templates (not cluster-tested): the execution-claim
    admission policy is scoped to claim ConfigMaps and the supervisor CA,
    handles DELETE via `oldObject`, no longer blocks `kube-root-ca.crt` or
    operator ConfigMaps, and lets a dedicated `claim-retention` identity (new
    Role) and namespace deletion remove claims. The Job policy exempts
    finalizer-only updates by the garbage collector / TTL / Job controllers
    on Jobs being deleted, so Foreground deletion can finish. Tool runners
    no longer share the gateway's proxy: the gateway uses
    `gateway-egress-proxy` (the only source protected tools accept) and
    runners keep `egress-proxy`, which may reach only allowed external
    destinations. Breaking: deploy the second proxy and update the gateway's
    `egress_proxy` route setting.

## 0.2.0 (not yet tagged or published)

Version bump from 0.1.0 to 0.2.0 (#10). Under Cargo's SemVer rules for `0.x`
releases, a minor-version bump is the breaking (major) bump; it is required
because #6 removed public API.

### Changes merged since the previous entries (#5, #6, #7, #8, #10, #11)

- **Breaking (#6):** removed the deprecated `AuthorizationEngine::new` and
  `AuthorizationEngine::with_clock` constructors. Use `development` /
  `development_with_clock`, or `production` with `HighAssuranceConfig`.
- **Breaking behavior (#6):** in Development mode, a matching `Allow` or
  `RequireApproval` rule without `required_capability` is denied unless the
  authority also grants the action's `action_type`; a caller-chosen
  capability alone no longer suffices.
- **Breaking (#11):** actions without an explicit capability are denied in all
  modes; the `action_type` fallback in Development is removed.
- **Dependencies (#5):** `praetore-gateway-service` no longer depends on
  `rustls-pemfile` (RUSTSEC-2025-0134); PEM parsing uses the
  `rustls-pki-types` PEM API.
- **Tests (#8):** the PostgreSQL replay-claim restart test now cleans up its
  claim using `TEST_TENANT_ID`.
- **Docs (#7):** added proposal SAF-09 (pre-authorized safety actions and
  audited break-glass), an optional opt-in extension outside the core with no
  roadmap or date commitment.
- **Release (#10):** version bump from 0.1.0 to 0.2.0.

### Earlier changes (previously listed as Unreleased)

#### Added

- A runnable end-to-end quick start covering signed identity, authority,
  request intents, Strict and HighAssurance evaluation, and evidence
  verification; expanded mode guidance and declarative policy documentation.
- A documented mandatory tool-gateway integration pattern covering action
  normalization, fail-closed dispatch, durable execution journaling, and
  crash/TOCTOU recovery limits.
- Versioned policy semantics v2: conditional DENY/REQUIRE_APPROVAL rules now
  match unknown or type-incompatible values conservatively; HighAssurance
  rejects legacy v1 policy semantics while v1 policy bytes remain stable.
- Ed25519 agent key generation, typed verified public keys, subject-key-bound
  authority issuance/verification, signed request intents, and strict engine
  issuer trust bindings.
- Canonical JSON encoding for authority and request signatures, policy SHA-256
  digests, and evidence integrity hashes.
- Deterministic exact, prefix, membership, and numeric policy conditions for
  action parameters and request context, plus policy validation and digesting.
- Evidence binding for request context and the evaluated policy digest.
- High-assurance production configuration with policy pins, bounded issuer
  trust pins, and required evidence attestation; stable evidence schema and
  canonical codec version fields.
- Domain-separated Ed25519 evidence signatures with offline verification,
  issuer key IDs/pin JSON import-export, and stricter duplicate-key-rejecting
  JSON import paths for policies, pins, and evidence.
- Explicit error kinds/codes and bounded canonical JSON validation. Evaluation
  now uses one clock snapshot for all validity checks in a request.
- Operator procedures for issuer rotation, agent key compromise, policy
  rollback, and clock validity.
- Offline `praetore-verify` commands for evidence, policy digests, and signed
  authorities, with machine-readable reason codes and explicit external pins.
- Bounded libFuzzer targets for canonical JSON, policy parsing, authority
  verification, evidence verification, and Development/HighAssurance
  evaluation, seeded from committed goldens and deterministic test fixtures.
- Pull-request/main CI gates for workspace tests, strict Clippy, formatting,
  RustSec audit, bounded fuzz smoke, Python verification tests, and CycloneDX
  SBOM artifacts; release tags produce a checksummed verifier binary artifact.
- Thin PyO3-backed Python evidence integrity and attester-signature verification
  functions, with fixtures generated by Rust test code.
- Required caller-owned one-time request claims in the HighAssurance profile;
  duplicate requests and unavailable replay storage fail closed.
- Optional PostgreSQL replay-guard adapter with atomic primary-key claims and
  CI integration tests for concurrency and persistence across clients.
- Strict unknown-field rejection for v1 typed documents, deterministic
  `AgentKeyFingerprint`, and proof-carrying key rotation evidence that does
  not imply revocation.
- Caller-supplied, veto-only freshness checks required by HighAssurance, with
  stable machine-readable failure codes.
- Versioned HighAssurance contracts: signed intents bind audience, expiry, and
  policy digest; HighAssurance requires policy semantics v2 and emits attested
  evidence schema v2 while retaining v1 verification/canonical bytes.
- HighAssurance freshness now binds the exact authority content digest and
  enforces a maximum lease; authorities must be bounded by validity dates and
  default to a 365-day maximum lifetime.
- Offline evidence-verifier output now explicitly marks its scope as historical
  receipt integrity/attestation and reports that it is not current
  authorization.
- Added a synchronous reference tool gateway that requires HighAssurance,
  dispatches the exact action from fresh ALLOW evidence, and fails closed on
  replay, journal, and adapter ambiguity. It includes adversarial tests but no
  network service or production deployment configuration.
- Added an optional PostgreSQL execution journal with unique execution claims,
  immutable authorization/action binding, monotonic durable transitions, and
  read-only recovery reconciliation. PostgreSQL CI covers concurrent
  gateways, server restart, ambiguous outcomes, and terminal-state rollback.
- Added `AtomicAuthorizationCommit` for the gateway path. PostgreSQL now
  commits the replay claim and completed, verified HighAssurance evidence in
  one transaction, verifies uncertain commit acknowledgements before
  dispatch, and blocks legacy orphan claims without reconstructing evidence.

#### Fixed

- Fixed the HighAssurance fuzz fixture to supply the required audience so
  fuzzing reaches request evaluation instead of panicking during setup.

#### Compatibility notes

- **Breaking:** in Strict and HighAssurance, a matching `Allow` or
  `RequireApproval` rule without `required_capability` now yields `Deny`.
  Add `with_capability(...)` (or `required_capability` in policy JSON) to
  those rules before upgrading. For Development rule handling, see #6 below.
- `AuthorizationEngine::evaluate(request) -> Result<Evidence>` is unchanged.
- **Breaking (fail-closed, #11):** in Development, an action without an explicit
  capability is now denied ("action does not declare a required capability")
  instead of falling back to its `action_type` as the required capability.
  Set `Action::with_capability(...)` on every action.
- **Breaking (#6):** constructor removal and the Development rule-capability
  change are described under "Changes merged since the previous entries" above.
- Public structs gained fields. Struct-literal construction may require source
  changes; constructors and builders are the preferred API ahead of v1.
- `Action::with_capability` separates action type from required authority
  capability. Actions without an explicit capability are denied in all modes
  (#11); Strict and HighAssurance already required an explicit capability.
- `Evidence::new` and `Evidence::new_with_context` return `Result` so oversized
  or invalid evidence cannot be constructed with an empty fallback integrity
  hash.
- HighAssurance callers must attach a durable, atomic `ReplayGuard` to
  `HighAssuranceConfig`; implementers must retain claims and fail closed on
  duplicate IDs or storage failure. The gateway additionally requires its
  journal to implement `AtomicAuthorizationCommit`; it cannot fall back to
  standalone replay-guard writes. Strict and Development modes are unchanged.
- HighAssurance callers must also attach a `FreshnessProvider`; non-current,
  unknown, revoked, expired, or unavailable results fail closed.
- Existing `FreshnessProvider` implementations must implement
  `check_authority` to bind freshness to the canonical authority digest. The
  compatibility default returns `FRESHNESS_INVALID`, so old providers compile
  but cannot authorize HighAssurance evaluations until migrated.
- PostgreSQL support is an optional crate. The deployment owns client
  construction, TLS, database provisioning, synchronous replication, backups,
  capacity monitoring, and application-role privileges.

#### Not yet delivered

- Python policy evaluation / authority issuance, signed release artifact
  attestations, and long-running fuzz campaigns remain follow-up work. The
  replay-guard trait is in core, but durable storage implementations and their
  operational validation remain deployment responsibilities. Release tag
  signing remains an operator-controlled procedure; CI does not hold signing
  keys.
