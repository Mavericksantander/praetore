# praetore-console

Local operator console for a PRÆTORE journal. It runs on the operator's computer, listens only on loopback, and has two parts:

- **Historial (D1):** past receipts in plain language. Read-only.
- **Bandeja (D2):** requests held for human approval. The operator approves, rejects, or runs the single dispatch of an approved request. The console signs the decision on this computer with the approver key, as `praetore approve` does. The gateway verifies the signature, records the decision and performs the dispatch.
- **Paquete de compliance (D3, D3.1):** a `.tar.gz` for a third party (an auditor) to check with `praetore-verify` without trusting the console: the policy decisions, and how each held request ended (approved, rejected, expired, executed). Read only.

It is not a hosted service. Linux first.

## Configuration

Required:

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_TENANT_ID` | Tenant whose journal is shown. |
| `PRAETORE_CONSOLE_DATABASE_URL` | PostgreSQL URL. In the tested setup it is the gateway's runtime role: the console opens its transactions read only (per session, not by privilege) under the tenant's row-level security. The role itself can write; the console does not. |

Optional:

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_BIND` | Loopback address, default `127.0.0.1:8090`. A non-loopback address is refused. |
| `PRAETORE_CONSOLE_AGENT_NAMES_FILE` | `agent-uuid = nombre` lines, so agents show by name. |

Approvals inbox: all four or none. A partial set is a startup error. The inbox also requires `PRAETORE_CONSOLE_POLICY_FILE` and `PRAETORE_CONSOLE_ATTESTER_PIN_FILES` (below): without them the console does not start, and the error names the missing variables. As a consequence, a console with the inbox also offers the compliance package.

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_GATEWAY_URL` | `http://127.0.0.1:<port>` (or `[::1]`) of the gateway. Host names are not accepted. |
| `PRAETORE_CONSOLE_APPROVER_KEY_ID` | The approver key id the gateway pins for this tenant. |
| `PRAETORE_CONSOLE_APPROVER_KEY_FILE` | File with the approver Ed25519 secret, 32 bytes in hex (`approver.key` of `praetore init`). It must be a regular file owned by this user, with no group or other permissions, and not a symlink. |
| `PRAETORE_CONSOLE_APPROVER_TOKEN_FILE` | The gateway's `approver` bearer token (`approver-api.token`), with the same file rules. |

Attester pins and local policy: both or none. One without the other is a startup error. With them, the compliance package is available, the history checks attester signatures, and the inbox (when configured) can verify the evidence it offers. The inbox and the history read these files once, at startup: a change takes effect when the console is restarted. The compliance package reads them again at each download. The console opens them without following a final symlink and without waiting on a FIFO, and requires a regular file. This also applies with the policy and the pins but no inbox (package only): the console reads them at startup and does not start if one cannot be read, is a symlink or is not a regular file. Before, they were first read at download; the download itself is unchanged and still follows symlinks.

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_POLICY_FILE` | The policy file the gateway loads (`policy.json` of `praetore init`). Regular file, at most 1 MiB. |
| `PRAETORE_CONSOLE_ATTESTER_PIN_FILES` | One to 16 attester public-key files (64 lowercase hex characters each, the `--attester-pin` format of `praetore journal-export`), separated like `PATH` (`:` on Unix). After an attester key rotation, list the retired key too. For `praetore run`, `praetore init` writes it as `attester-public-key.hex`; `praetore attester-pin <directory>` writes it for a directory initialized before. |

Approval and execution receipts (D3.1): optional, and only with the two above. With neither of the two variables below the package is the D3 one, without `approvals.jsonl`: `LEEME.txt` and `export.json` say the console is not configured to include approval and execution receipts, and that the package does not show how each held request ended. With at least one of them, `approvals.jsonl` is in the package, all or nothing (below).

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_EXECUTION_PIN_FILES` | Zero to 16 gateway execution-key pins, separated like `PATH`. They verify execution and expiration receipts. |
| `PRAETORE_CONSOLE_APPROVER_PIN_FILES` | Zero to 16 approver pins, separated like `PATH`. They verify approve and reject decisions. The console's own approver key (D2) is usually one of them. |

Each pin file is one JSON document, the format of the `approver-pin.json` that `praetore init` writes: `{"schema_version":1,"key_id":"...","public_key_hex":"<64 lowercase hex>"}`. The `key_id` must be the one the records name: for `praetore run`, the execution key id is `local-demo-<public key hex>`; for `praetore-gateway-demo`, `execution-attester-<public key hex>`.

Where the pins come from:

- **Attester, `praetore run`:** `praetore init` writes `attester-public-key.hex` (the evidence attester's public key, 64 lowercase hex characters, no secret) next to `evidence-attester.key`. For a directory initialized before `init` wrote it, `praetore attester-pin <directory>` writes it: it reads `evidence-attester.key` itself and never overwrites an existing file.
- **`praetore run`:** `praetore init` writes `execution-pin.json` (the execution key's public pin, key id `local-demo-<public key hex>`) next to `approver-pin.json`; neither holds a secret. For a directory initialized before `init` wrote it, `praetore execution-pin <directory>` writes it: it reads `execution-attester.key` itself, so nobody handles the secret, and it never overwrites an existing file.
- **`praetore-gateway-demo`:** its execution key is the file `PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_FILE` names, and its key id is `execution-attester-<public key hex>` (`docs/operations.md`). Record the public key when the key is generated, from the secret manager that holds it, and write the pin from it. Every execution receipt the gateway signed names that key id (`attestation_json ->> 'key_id'` in `praetore.execution_attestations`), so its hex suffix is the public key that receipt claims; a pin taken from there shows the records are consistent with that key, not that it is the gateway's: compare it with the one recorded at generation.
- **Approvers:** the `approver-pin.json` of `praetore init`, or for `praetore-gateway-demo` the public keys of `PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE` bound to this tenant, each written as a pin with the `key_id` it has there (the one decisions name in `approver_key_id`).

All of them are read again at every download.

## Opening the console

At every start the console writes a link to **stderr**:

```
Abre la consola en este computador con este enlace (vale una vez, 5 minutos):
  http://127.0.0.1:8090/#abrir=<código>
```

- **One use, five minutes at most.** The link works once and for at most five minutes. The page redeems the code once via `POST /api/sesion`.
- **Session per tab.** The session is a per-tab token kept in `sessionStorage`, sent as `Authorization: Bearer`. No session cookie is set. The token expires after 12 hours and does not survive a console restart; another tab (or the same one after 12 hours or a restart) needs a new link (press Enter in the terminal, or restart). The session lives in the tab where the link was opened.
- **New link only by the operator.** When stdin and stderr are a terminal and the console is in that terminal's foreground, pressing Enter there writes a new link and the earlier one stops working. Otherwise (started with `&`, under systemd), restart the console. Asking for the page never issues a link. The console ignores SIGTTIN: sent to the background with Ctrl-Z and `bg`, it keeps serving instead of being stopped, and Enter works again after `fg`.
- **Under systemd,** stderr goes to the journal. Whoever can read that journal can see the opening link, and can open the console with it while it is live. Restrict who can read the journal, or run the console in a terminal.
- **Headers.** Responses carry `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and a same-origin `Content-Security-Policy`.
- **Request checks.** Every request must carry the console's own `Host`. An action also needs the console's exact `Origin` and the `x-praetore-consola` header.

## What the inbox shows and checks

- **Each request:** who (agent name), what action, on what target, until when it is valid, and the action parameters. The action and the target are quoted, so a target that reads "sin objetivo indicado" is not the console's own placeholder.
- **Parameters:** shown with sorted keys, nested keys as `"clave"."subclave"`. The inbox tells apart structure, types and invisible characters; it does not flag look-alike characters from different scripts (see Limits):
  - keys and texts are quoted, with `"` and `\` escaped, so `"10"` differs from `10`, `"sí"` from `sí` (true), and a key with a trailing space shows it;
  - a list says it is a list and how long ("lista de 1 elemento:", "lista vacía []"), and each element has its own mark (`[1] "a"`), so `["a"]` is not `"a"` and `"a, b"` is never two elements;
  - characters are escaped as `\u{xxxx}` by Unicode general category, not by a closed list: Cc, Cf (bidi, zero-width, tags, BOM, soft hyphen), Zl, Zp, Co, Cn, every Zs other than U+0020 (no-break space, U+3000...), plus variation selectors, U+034F, the Hangul fillers and U+2800.
- **Parameters that can't be shown:** the signature covers the parameters, so the request can only be rejected here, and the console refuses an approval server side, in these cases:
  - more than 20 lines (each list element counts), a key or value over 200 characters once escaped, or more than 2 levels;
  - a key with a dot (it would read as a nested key);
  - keys that repeat once normalized (NFKC, lower case);
  - text not in Unicode NFC.

  To approve such a request, review it in full with `praetore approve`.
- **Confirmation:** "Aprobar y ejecutar" and "Rechazar" each ask for a confirmation inside the same card before anything is signed. The confirmation repeats the agent, the action, the target, each parameter and the deadline.
- **Before showing a request, and again before signing**, the console checks its journal evidence: the integrity hash, the attester signature against one of the configured pins (`PRAETORE_CONSOLE_ATTESTER_PIN_FILES`), and the policy digest the evidence records against the local policy (`PRAETORE_CONSOLE_POLICY_FILE`). A request that fails any of these is not offered, to approve or to reject, and the page only counts it. It then fetches the gateway challenge and requires it to be identical to the one rebuilt from that evidence: same key, evidence, action, policy and window. The gateway verifies the decision's signature.
  - **Policy change:** after the local policy file changes (and the console restarts), requests held under the earlier policy record its digest, so the inbox no longer offers them. They can still be decided with `praetore approve` or `praetore reject`.
  - **History:** with pins, a receipt counts as readable only when its attester signature verifies against one of them; the current policy is not required, so receipts decided under an earlier policy stay readable. A receipt that does not verify is shown as unreadable, and the rest of the page is shown. Without pins (history only, no policy or pins configured), the history checks the integrity hash only, not who signed it.
- **A rejection is final.** An approval is never resent. If the dispatch fails, only the dispatch is offered again.

## The compliance package

"Descargar paquete de compliance" saves `praetore-compliance.tar.gz`. Everything is in one folder, `praetore-compliance/`, with fixed names:

| File | What |
| --- | --- |
| `LEEME.txt` | In Spanish: what the package contains, how to check it with `praetore-verify` built from `main`, and what it does not show. |
| `journal.jsonl` | The tenant's chain of policy decisions. When the database has storage records, its first line is the `database_head` reference to the database chain (with that chain's record count), not a receipt; `LEEME.txt` counts the decision receipts apart. The chain: what `praetore journal-export --tenant <tenant>` writes for the same database state. The console calls `export_tenant_with_outcomes` and the CLI `export_tenant`; both read the journal with the same query in one read-only, repeatable-read snapshot and chain it with the same function (`praetore_replay_postgres::journal_export`), and the end-to-end test checks the two files are byte for byte equal; the export checks every receipt's signature against the pins. |
| `approvals.jsonl` | D3.1, only when an execution or approver pin is configured: the tenant's human decisions (approve, reject), approval-expiration receipts and execution receipts, one signed record per line (`{"schema_version":1,"human_decision":{...}}`, `"approval_expired"` or `"execution_receipt"`), read in the same snapshot as `journal.jsonl`. An execution receipt is the `GatewayReceipt` the gateway returned: the journal's evidence, and for `executed` and `confirmed` the adapter output, which its signature covers. Empty when the tenant has none. |
| `policy.json` | The configured policy file, byte for byte. |
| `policy-digest.txt` | Its digest, from `RecordedPolicy` (what the engine records and `praetore-verify policy-digest` prints). |
| `attester-pin-1.hex`, ... | The configured pins, parsed and written back as public keys. Each one verified at least one receipt of `journal.jsonl` or one record of the database chain, which is not in the package. |
| `execution-pin-1.json`, ... / `approver-pin-1.json`, ... | D3.1: the configured execution and approver pins, re-encoded from the parsed key with their `key_id`, numbered from one. Only the configured pins that verified at least one record of `approvals.jsonl`: one that verified none is left out, its position and path go to the log, and `export.json` counts it (`omitted_execution_pins`, `omitted_approver_pins`). |
| `export.json` | Tenant, generation time, entries, chain head, database head reference, policy id, version and digest; under `outcomes`, `"included": false` and a note when the console is not configured for D3.1, or how many records of each kind `approvals.jsonl` has, the held requests by outcome and the omitted pins. |
| `SHA256SUMS` | SHA-256 of every other file, for `sha256sum -c` / `shasum -a 256 -c`. |

- **Read only.** The download is a `GET`. It needs the session token (`Authorization: Bearer`) and the console's `Host`, like every other request, plus the `x-praetore-consola` header and, when the browser sends one, `Sec-Fetch-Site: same-origin`, so another local page cannot make the console build packages. Nothing is written to the database or to disk; the package is built in memory.
- **No private key.** Only the parsed public keys go in. A pin equal to the approver's public key or secret is refused (when the inbox is configured), and so is any pin that verified no receipt and no storage record of the export. A secret key's 32 bytes can decode as a public key, but they cannot verify the signatures their own key made, so a key file listed by mistake is refused instead of copied. A consequence: list only the attester keys that signed this tenant's entries; a retired key that signed none of them is refused as unused. The page names the unused pin in words by its place in `PRAETORE_CONSOLE_ATTESTER_PIN_FILES` ("la segunda clave configurada…"; the first one, saying there may be more, when several are unused); the log has its position and path, never its contents. Execution and approver pins follow the same rule: an execution pin equal to the approver's public key or secret, or an approver pin equal to the approver's secret, is refused, and so is a file that is not a JSON pin or repeats a key or key id. Unlike an attester pin, an execution or approver pin that verified no record of `approvals.jsonl` is not refused: it is left out of the package (it is not copied), and the log has its position and path. A tenant with no human decision, say, gets a package without `approver-pin-1.json`. A secret listed by mistake as such a pin verifies nothing, so it is left out too.
- **All or nothing.** The policy, the pins and the export are read and checked before anything is archived. If one cannot be read or does not check out (for example a pin that verified no entry), there is no package and the page says what failed, without ids or hex. Since D3.1 every record of `approvals.jsonl` is verified first with `praetore_receipt::outcomes`, the code `praetore-verify outcomes` runs: a record that does not verify, does not match its request of the journal or contradicts another record of the same request, or one signed by a key no pin names, means no package; so does an `approvals.jsonl` over 32 MiB or 20,480 lines. This includes execution receipts written before migration 0023, whose output digest the database did not check: if one does not match its stored output, the package is refused. List only this tenant's approvers in `PRAETORE_CONSOLE_APPROVER_PIN_FILES`: the gateway ties each approver to a tenant, the pin format does not. When the export itself fails, the message lists the possible causes (database, no receipts, more than 4096 entries or 8 MiB of chain, a signature that does not match the pins); the console's log has the detail. With real receipts (about 2.6 KB per line) the 8 MiB bound comes first, at roughly 3,200 decisions.
- **One at a time.** The export holds the console's database connection, so one package is built at a time; a second request meanwhile gets "Ya se está armando un paquete. Espera a que termine."
- **Not configured.** The page asks `/api/paquete/estado` at load; without the two settings it hides the button and says the package is not configured.
- **How each held request ended:** `praetore-verify outcomes` (step 5 of `LEEME.txt`) lists every held request of `journal.jsonl` with its outcome (`pending`, `rejected`, `expired`, `approved_pending_dispatch`, `approved_executed`, ...), so an auditor finds each one by its `request_id`.
- **What it does not show:** that `approvals.jsonl` is complete: its records are not chained, so a removed record leaves no trace and an approved or executed request can show as `pending`, `approved_pending_dispatch` or `not_dispatched` (a `dispatch_refused` close without its approval reads as `not_dispatched`). The order of its lines is not verified either; the outcomes do not depend on it. A `pending` request may also have expired without the gateway having recorded it yet (it records the expiry when it next sees the request). `LEEME.txt` lists the rest: no proof that the agent had no path around the gateway, nothing before the first record or after the export, no completeness without a head anchored outside the operator's control, no proof that the gateway used the configured `policy.json` beyond the digest each receipt records, and the database chain that the first line may reference is not included.
- **Who chose the pins:** the operator. An auditor who uses only the pins in the package learns that the journal and `approvals.jsonl` are consistent with those keys; they should get the attester's, the gateway's execution and the approvers' public keys some other way.
- **Adapter output:** execution receipts carry the adapter output of each executed action. Review it before sharing the package.

## Limits

- **Same operating system user:** a process running as the same user as the console can read `approver.key`, the token file and the console's memory or files directly, and sign without the console. The single-use link, the `Host`, `Origin` and header checks are aimed at web pages in the browser; they do not stop that process. Real separation requires running the agent under another operating system user than the console and its key files.
- **Who can see the link:** anyone who can read the console's stderr can see the opening link: under systemd, whoever can read that journal.
- **Look-alike characters:** characters from different scripts that look alike (for example a Latin `a` and a Cyrillic `а`) are shown as they are and are not flagged.
- **Emoji sequences:** an emoji with a variation selector or a zero-width joiner is shown with escapes, for example `❤\u{fe0f}` or `👩\u{200d}💻`, not as one glyph.
- **Right-to-left text:** Arabic or Hebrew text can be reordered on screen by the browser's bidirectional algorithm even without any control characters (which are escaped); neutral characters next to it, such as digits or punctuation, may appear in a different order than they are stored.
- **Not shown:** the console does not show the browser any journal ids, keys, hex digests, RFC 3339 instants or raw evidence. Parameter values are shown as the agent sent them, escaped. The compliance package, a file the browser saves and does not display, does contain ids, hex values and RFC 3339 instants: an auditor needs them.
- **Expired windows:** requests whose approval window has closed are counted and not offered. The gateway records the expiry when it next sees the request.
- **Truncation:** the inbox reads the 200 newest pending requests and says when there are more.
