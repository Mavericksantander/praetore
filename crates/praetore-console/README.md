# praetore-console

Local operator console for a PRÆTORE journal. It runs on the operator's computer, listens only on loopback, and has two parts:

- **Historial (D1):** past receipts in plain language. Read-only.
- **Bandeja (D2):** requests held for human approval. The operator approves, rejects, or runs the single dispatch of an approved request. The console signs the decision on this computer with the approver key, as `praetore approve` does. The gateway verifies the signature, records the decision and performs the dispatch.
- **Paquete de compliance (D3):** a `.tar.gz` for a third party (an auditor) to check with `praetore-verify` without trusting the console. Read only.

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

Approvals inbox: all four or none. A partial set is a startup error.

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_GATEWAY_URL` | `http://127.0.0.1:<port>` (or `[::1]`) of the gateway. Host names are not accepted. |
| `PRAETORE_CONSOLE_APPROVER_KEY_ID` | The approver key id the gateway pins for this tenant. |
| `PRAETORE_CONSOLE_APPROVER_KEY_FILE` | File with the approver Ed25519 secret, 32 bytes in hex (`approver.key` of `praetore init`). It must be a regular file owned by this user, with no group or other permissions, and not a symlink. |
| `PRAETORE_CONSOLE_APPROVER_TOKEN_FILE` | The gateway's `approver` bearer token (`approver-api.token`), with the same file rules. |

Compliance package: both or none. One without the other is a startup error.

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_POLICY_FILE` | The policy file the gateway loads (`policy.json` of `praetore init`). Regular file, at most 1 MiB. |
| `PRAETORE_CONSOLE_ATTESTER_PIN_FILES` | One to 16 attester public-key files (64 lowercase hex characters each, the `--attester-pin` format of `praetore journal-export`), separated like `PATH` (`:` on Unix). After an attester key rotation, list the retired key too. |

Both are read again at every download.

## Opening the console

At every start the console writes a link to **stderr**:

```
Abre la consola en este computador con este enlace (vale una vez, 5 minutos):
  http://127.0.0.1:8090/?abrir=<código>
```

- **One use, five minutes at most.** The link works once and for at most five minutes. Opening it sets the session cookie (HttpOnly, SameSite=Strict) and redirects to `/`.
- **Cookie per run.** The session secret is new on every start and is never written to disk, so a cookie from an earlier run stops working.
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
- **Before signing**, the console fetches the gateway challenge and requires it to be identical to the one rebuilt from the journal evidence it showed: same key, evidence, action, policy and window.
  - It checks that evidence's **integrity hash**, not its attester signature against a pin, and it does not compare the policy with a local copy. The gateway verifies the decision's signature.
- **A rejection is final.** An approval is never resent. If the dispatch fails, only the dispatch is offered again.

## The compliance package

"Descargar paquete de compliance" saves `praetore-compliance.tar.gz`. Everything is in one folder, `praetore-compliance/`, with fixed names:

| File | What |
| --- | --- |
| `LEEME.txt` | In Spanish: what the package contains, how to check it with `praetore-verify` built from `main`, and what it does not show. |
| `journal.jsonl` | The tenant's chain: what `praetore journal-export --tenant <tenant>` writes for the same database state. Both call `praetore_replay_postgres::journal_export::export_tenant` (one read-only, repeatable-read snapshot), so they cannot differ; the export checks every receipt's signature against the pins. |
| `policy.json` | The configured policy file, byte for byte. |
| `policy-digest.txt` | Its digest, from `RecordedPolicy` (what the engine records and `praetore-verify policy-digest` prints). |
| `attester-pin-1.hex`, ... | The configured pins, parsed and written back as public keys. Each one verified at least one entry of the export. |
| `export.json` | Tenant, generation time, entries, chain head, database head reference, policy id, version and digest. |
| `SHA256SUMS` | SHA-256 of every other file, for `sha256sum -c` / `shasum -a 256 -c`. |

- **Read only.** The download is a `GET`. It needs the session cookie and the console's `Host`, like every other request, plus the `x-praetore-consola` header and, when the browser sends one, `Sec-Fetch-Site: same-origin`, so another local page cannot make the console build packages. Nothing is written to the database or to disk; the package is built in memory.
- **No private key.** Only the parsed public keys go in. A pin equal to the approver's public key or secret is refused (when the inbox is configured), and so is any pin that verified no receipt and no storage record of the export. A secret key's 32 bytes can decode as a public key, but they cannot verify the signatures their own key made, so a key file listed by mistake is refused instead of copied. A consequence: list only the attester keys that signed this tenant's entries; a retired key that signed none of them is refused as unused.
- **All or nothing.** The policy, the pins and the export are read and checked before anything is archived. If one cannot be read or does not check out (for example a pin that verified no entry), there is no package and the page says what failed, without ids or hex. When the export itself fails, the message lists the possible causes (database, no receipts, more than 4096 entries, a signature that does not match the pins); the console's log has the detail.
- **What it does not show:** the journal chain carries each request's policy decision (allow, deny, hold for approval). It does not carry the human approval or rejection, nor the execution receipt; those are not in the package. `LEEME.txt` lists the rest: no proof that the agent had no path around the gateway, nothing before the first record or after the export, no completeness without a head anchored outside the operator's control, no proof that the gateway used the configured `policy.json` beyond the digest each receipt records, and the database chain that the first line may reference is not included.
- **Who chose the pins:** the operator. An auditor who uses only the pins in the package learns that the journal is consistent with those keys; they should get the attester's public key some other way.

## Limits

- **Same operating system user:** a process running as the same user as the console can read `approver.key`, the token file and the console's memory or files directly, and sign without the console. The single-use link, the `Host`, `Origin` and header checks are aimed at web pages in the browser; they do not stop that process. Real separation requires running the agent under another operating system user than the console and its key files.
- **Who can see the link:** anyone who can read the console's stderr can see the opening link: under systemd, whoever can read that journal.
- **Look-alike characters:** characters from different scripts that look alike (for example a Latin `a` and a Cyrillic `а`) are shown as they are and are not flagged.
- **Emoji sequences:** an emoji with a variation selector or a zero-width joiner is shown with escapes, for example `❤\u{fe0f}` or `👩\u{200d}💻`, not as one glyph.
- **Right-to-left text:** Arabic or Hebrew text can be reordered on screen by the browser's bidirectional algorithm even without any control characters (which are escaped); neutral characters next to it, such as digits or punctuation, may appear in a different order than they are stored.
- **Not shown:** the console does not show the browser any journal ids, keys, hex digests, RFC 3339 instants or raw evidence. Parameter values are shown as the agent sent them, escaped. The compliance package, a file the browser saves and does not display, does contain ids, hex values and RFC 3339 instants: an auditor needs them.
- **Expired windows:** requests whose approval window has closed are counted and not offered. The gateway records the expiry when it next sees the request.
- **Truncation:** the inbox reads the 200 newest pending requests and says when there are more.
