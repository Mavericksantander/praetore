# praetore-mcp evasion matrix

This page lists what an agent, or another process running as the same OS user, can try to get a `tools/call` past praetore-mcp or to remove its trace. It records what happens on main after praetore-mcp 0.3.6.

Each row names the test that pins the behaviour. They are in `crates/praetore-mcp/tests/evasion.rs`, unless the row names another file. A test pins a limitation as well as a defence. When a limitation is closed, its test fails and has to be changed together with this table.

Status:

- **bloqueado**: the call does not run.
- **detectado después**: the call or the edit is not stopped, but `praetore-mcp verify` fails on the home afterwards.
- **limitación conocida**: neither. Some rows leave a trace that a person can find; the row says where.

The threat model behind these rows is in [../threat-model.md](../threat-model.md). praetore-mcp runs as the same user as the agent. Anything that user can write (the home, the client config) the agent can write too.

| Case | Attempt | Status | Test | What would close it |
|---|---|---|---|---|
| a | The client starts the MCP server directly, without `wrap` | limitación conocida | `a_server_started_without_wrap_runs_the_call_and_leaves_no_receipt` | The server reachable only through `wrap` (OS sandbox, or the server under another user), and a check of the client config |
| b | Edit `policy.json` to allow a denied call | limitación conocida, con rastro | `an_edited_policy_allows_a_denied_call_and_shows_only_as_a_new_policy_digest` | A policy signed with a key the agent cannot use, checked by `wrap` at start |
| b | Edit `config.toml` (`report = false`) | limitación conocida | `an_edited_config_turns_reports_off_but_not_the_receipts` | A home that must keep reports would need the config signed like the policy |
| b | Set `approval_ttl_seconds` in `config.toml`, to stretch the window of new approvals (up to 86400 s) | limitación conocida, con rastro (the window is signed into each decision in `approvals/journal.jsonl`) | `the_ttl_in_config_toml_stretches_new_approvals` | The TTL set where the agent cannot write, or `verify` checking each window against a maximum kept outside the home |
| b | Set `PRAETORE_MCP_APPROVAL_TTL_SECONDS` in the `env` of the MCP client config, to stretch the window of new approvals (up to 86400 s) | limitación conocida, con rastro (the window is signed into each decision in `approvals/journal.jsonl`) | `the_ttl_env_var_in_the_client_config_stretches_new_approvals` | The TTL set where the agent cannot write, or `verify` checking each window against a maximum kept outside the home |
| b | Write `approvals/ttl-seconds` in the home, to the same end | limitación conocida, con rastro (same) | `the_ttl_seconds_file_in_the_home_stretches_new_approvals` | Same |
| c | Remove a receipt from the middle of the receipts journal | detectado después | `a_receipt_removed_from_the_middle_fails_verify` | Already detected |
| c | Cut the receipts journal in the middle of a line | detectado después | `a_receipts_journal_cut_mid_line_fails_verify` | Already detected |
| c | Drop the last receipts whole, or delete the receipts journal | detectado después con `--expected-head` (head guardado fuera de la máquina); limitación conocida sin él | `dropping_the_last_receipts_or_the_journal_fails_only_verify_with_the_expected_head` | Detected only when the head printed by an earlier `verify` is kept where the agent cannot write and passed as `--expected-head` |
| c | Delete `approvals/journal.jsonl` before the approved call runs | bloqueado | `deleting_the_approval_journal_holds_the_call_and_fails_verify_after_it_ran` | Already blocked |
| c | Delete `approvals/journal.jsonl` after the approved call ran | detectado después (the forwarded receipt names an approval with no signed decision); the next call is held | `deleting_the_approval_journal_holds_the_call_and_fails_verify_after_it_ran` | Already detected |
| c, d | Drop the execution record at the end of `approvals/journal.jsonl` so the same approval runs again | bloqueado (the forwarded receipt names the approval, and `wrap` counts it as used); detectado después (the receipt names an approval with no execution for it) | `truncating_the_approval_journal_holds_a_used_approval_and_fails_verify` | Already blocked |
| c, d | Drop the execution record and also the forwarded receipt at the end of the receipts journal, so the same approval runs again | detectado después con `--expected-head` o `--expected-approval-head` (heads guardados fuera de la máquina); limitación conocida sin ellos | `truncating_both_journals_runs_an_approval_again_and_only_the_saved_heads_find_it` | Detected only when a head printed by an earlier `verify` is kept where the agent cannot write |
| c, d | Cut the forwarded receipt in half, so its line keeps `praetore.approval_id` but is not JSON, and drop the execution record | bloqueado (`wrap` cannot read which approval the line names and holds the call); detectado después | `a_cut_receipt_line_that_names_an_approval_holds_the_retry_and_fails_verify` | Already blocked |
| c, d | Write a second receipt that names a used approval, signed with the keys in the home | detectado después | `two_receipts_naming_one_approval_fail_verify` | Already detected |
| c | Write a receipt that names a rejected approval, or a malformed approval id | detectado después; a malformed id also holds every approved call until it is removed | `a_receipt_naming_a_rejected_or_malformed_approval_fails_verify` | Already detected |
| c | Read the keys in the home and write another journal, signed and consistent from the first entry to a new head | detectado después con los dos heads guardados fuera de la máquina (`verify` exit 1); sin ellos `verify` no dice OK: dice UNANCHORED y sale con 3 | `a_journal_rewritten_with_the_keys_fails_against_the_saved_anchor` and `without_an_anchor_no_journal_is_ok`, in `crates/praetore-mcp/tests/verify_anchor.rs` | Keys the agent's user cannot read (another user, an HSM, a signer outside the machine) |
| d | Send the approved call twice | bloqueado | `an_approval_is_used_once` | Already blocked |
| e | Change the arguments after approval | bloqueado | `an_approval_does_not_cover_other_arguments` | Already blocked |
| e | Same tool and arguments under another `--name`, or another held tool with the same arguments | bloqueado | `an_approval_does_not_cover_another_server_or_another_held_tool` | Already blocked |
| f | Use another allowed tool with the same effect | limitación conocida | `another_allowed_tool_with_the_same_effect_is_forwarded` | Rules over the effect (paths, resources) for every tool of the server; `policy coverage` shows which tools a rule leaves open |

## Details

**a. Without `wrap`.** praetore-mcp sees only the calls that pass through `wrap`. If the client config is changed to start the server directly, the call runs, no receipt is written and `verify` passes with the same count. `praetore-mcp install` writes the client config, and a process running as the same user can rewrite it.

**b. Policy and config.** `wrap` reads `policy.json` when it starts, and a policy edit is also how a person changes the rules. `verify` therefore passes after an edit. Every receipt carries `evidence.policy_digest`, the digest of the policy that decided it, so the edit shows as a new digest between two receipts. Nothing checks that the edit was made by a person. `config.toml` turns reports on or off and sets the approval window (`approval_ttl_seconds`). It does not change the outcome a rule gives a call, but the window decides how long a held call can still be approved.

The window comes from the first of these that is set, from 1 to 86400 seconds: `PRAETORE_MCP_APPROVAL_TTL_SECONDS` in the environment of `wrap` (for a client, the `env` block of its config), `approval_ttl_seconds` in `config.toml`, `approvals/ttl-seconds` in the home. `wrap` checks all of them at startup and refuses to start on an invalid one. A process that can edit any of them can stretch the window of every new approval to 24 h. Each decision signs its `created_at` and `expires_at`, so the longer window is in `approvals/journal.jsonl`. `verify` checks that each execution is inside its window, not how long the window is, so it passes.

**c. Journals.** The receipts journal is a hash chain: a removed or reordered entry and a cut line fail `verify`. A shorter chain that is still valid passes plain `verify`: dropping the last entries or deleting the files leaves no gap to find. `verify` prints the journal head, and the session report records both heads at close. `verify --expected-head HEX` with a head printed earlier fails after the end is dropped and after the journal is deleted. That detects the change only if the head was kept somewhere the agent cannot write, for example off the machine.

`approvals/journal.jsonl` holds the signed decisions and execution records. `verify` reads it when it is there and checks the approver signature, the binding of each decision to its held receipt, that each execution is inside the expiry window and bound to the same call, and that one approval was not used twice. The receipt of a call forwarded on an approval names the approval id in its signed context (`praetore.approval_id`). `verify` checks those receipts against the approval journal, also when the file is gone: one receipt per approval, a signed approve decision for it, and its execution for that receipt. Deleting the approval journal before the call runs removes the decision, so the call is held again. Deleting it after the call ran fails `verify`. Truncating it is covered in the rows for the execution record.

**d. Reuse.** An approval is used by one call. The same call again is held. Before forwarding, `wrap` counts an approval as used when the approval journal has its execution or a receipt in the receipts journal names it, so dropping the execution record alone does not free it, and `verify` fails on the receipt left without its execution. A process that also drops the forwarded receipt from the end of the receipts journal gets the approval back: both journals are consistent and shorter, the same call runs again, and plain `verify` passes. `verify --expected-head HEX` or `verify --expected-approval-head HEX` with a head printed earlier fails after that, if the head was kept where the agent cannot write.

**e. Other arguments, server or tool.** An approval binds the server name, the tool and the canonical arguments. A different path, a different text or an extra argument is held. So is the same call under another `--name`, even when one rule holds the tool for every server, and so is another held tool with the same arguments.

**f. Same effect, other tool.** Rules match the tool name and arguments. They do not match what a tool does. If one tool is held and another tool with the same effect is allowed, the second one runs. The receipt records the rule that allowed it.

## Mutations

The defences above were checked by removing each one and running `tests/evasion.rs`:

| Defence removed | Test that fails |
|---|---|
| Approval used once (`first_unused_approval` ignores execution records) | `an_approval_is_used_once` |
| Approval binding (`first_unused_approval` ignores the binding) | `an_approval_does_not_cover_other_arguments` |
| Server in the binding (`first_unused_approval` compares only tool and arguments) | `an_approval_does_not_cover_another_server_or_another_held_tool` |
| Tool in the binding (`first_unused_approval` compares only server and arguments) | `an_approval_does_not_cover_another_server_or_another_held_tool` |
| Chain order in `verify` (the seq/prev problem dropped) | `a_receipt_removed_from_the_middle_fails_verify` |
| Approvals named in the receipts journal (`first_unused_approval` counts only execution records) | `truncating_the_approval_journal_holds_a_used_approval_and_fails_verify` |
| A receipts line with the key that is not JSON (`approvals_named_in_receipts` skips it, `let Ok(entry) = parse_line(..) else { continue }`, instead of holding the call) | `a_cut_receipt_line_that_names_an_approval_holds_the_retry_and_fails_verify` |
| A receipt whose approval id is malformed (`approvals_named_in_receipts` skips it instead of holding the call) | `a_receipt_naming_a_rejected_or_malformed_approval_fails_verify` |
| Two receipts naming one approval (`verify` check removed) | `two_receipts_naming_one_approval_fail_verify`, by its message only (see below) |
| A receipt naming an approval with no signed decision (`verify` check removed) | `deleting_the_approval_journal_holds_the_call_and_fails_verify_after_it_ran` |
| A receipt naming a rejected approval (`verify` check removed) | `a_receipt_naming_a_rejected_or_malformed_approval_fails_verify`, by its message only when the whole check is removed (see below) |
| A receipt naming an approval with no execution for it (`verify` check removed) | `truncating_the_approval_journal_holds_a_used_approval_and_fails_verify` |
| A malformed approval id in a receipt (`verify` ignores it) | `a_receipt_naming_a_rejected_or_malformed_approval_fails_verify` |
| The execution record that cannot be written ignored (`let _ = append_execution(..)`, the call forwarded anyway) | `an_execution_record_that_cannot_be_written_spends_the_approval_and_fails_verify` |

The duplicate and the rejected checks are caught by the message the test asserts, not by the exit code. With either check removed, `verify` still exits 1 because another check fails on the same journals:

- Duplicate: in the test each of the two receipts has an execution record, so the reuse check (`... was reused: 2 execution records ...`) fails. With one execution record, the no-execution check would fail for the other receipt.
- Rejected: with the whole check removed, the receipt falls through to the no-execution check (`... has no execution of it for that receipt`). Removing only its message while it still skips the receipt (`continue`) makes `verify` pass, and the test fails on the exit code.

So these two checks add the reason `verify` gives, not a case it would otherwise accept.
