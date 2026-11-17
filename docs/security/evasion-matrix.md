# praetore-mcp evasion matrix

This page lists what an agent, or another process running as the same OS user, can try to get a `tools/call` past praetore-mcp or to remove its trace. It records what happens today in praetore-mcp 0.3.6.

Each row names the test that pins the behaviour. All of them are in `crates/praetore-mcp/tests/evasion.rs`. A test pins a limitation as well as a defence. When a limitation is closed, its test fails and has to be changed together with this table.

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
| c | Delete `approvals/journal.jsonl` before the approved call runs | bloqueado | `deleting_the_approval_journal_holds_the_call_and_verify_still_passes` | Already blocked |
| c | Delete `approvals/journal.jsonl` after the approved call ran | limitación conocida | `deleting_the_approval_journal_holds_the_call_and_verify_still_passes` | `verify` requiring, for each receipt forwarded on an approval, the signed decision it names |
| c, d | Drop the execution record at the end of `approvals/journal.jsonl` so the same approval runs again | limitación conocida (the receipts of the held call and of each forwarded one look the same: all say REQUIRE_APPROVAL and none carries an approval_id; there is no `--expected-head` for the approval journal) | `truncating_the_approval_journal_lets_a_used_approval_run_again` | The approval head kept outside the home, or the execution bound into the receipts chain so `verify` sees two executions of one approval |
| d | Send the approved call twice | bloqueado | `an_approval_is_used_once` | Already blocked |
| e | Change the arguments after approval | bloqueado | `an_approval_does_not_cover_other_arguments` | Already blocked |
| e | Same tool and arguments under another `--name`, or another held tool with the same arguments | bloqueado | `an_approval_does_not_cover_another_server_or_another_held_tool` | Already blocked |
| f | Use another allowed tool with the same effect | limitación conocida | `another_allowed_tool_with_the_same_effect_is_forwarded` | Rules over the effect (paths, resources) for every tool of the server; `policy coverage` shows which tools a rule leaves open |

## Details

**a. Without `wrap`.** praetore-mcp sees only the calls that pass through `wrap`. If the client config is changed to start the server directly, the call runs, no receipt is written and `verify` passes with the same count. `praetore-mcp install` writes the client config, and a process running as the same user can rewrite it.

**b. Policy and config.** `wrap` reads `policy.json` when it starts, and a policy edit is also how a person changes the rules. `verify` therefore passes after an edit. Every receipt carries `evidence.policy_digest`, the digest of the policy that decided it, so the edit shows as a new digest between two receipts. Nothing checks that the edit was made by a person. `config.toml` turns reports on or off and sets the approval window (`approval_ttl_seconds`). It does not change the outcome a rule gives a call, but the window decides how long a held call can still be approved.

The window comes from the first of these that is set, from 1 to 86400 seconds: `PRAETORE_MCP_APPROVAL_TTL_SECONDS` in the environment of `wrap` (for a client, the `env` block of its config), `approval_ttl_seconds` in `config.toml`, `approvals/ttl-seconds` in the home. `wrap` checks all of them at startup and refuses to start on an invalid one. A process that can edit any of them can stretch the window of every new approval to 24 h. Each decision signs its `created_at` and `expires_at`, so the longer window is in `approvals/journal.jsonl`. `verify` checks that each execution is inside its window, not how long the window is, so it passes.

**c. Journals.** The receipts journal is a hash chain: a removed or reordered entry and a cut line fail `verify`. A shorter chain that is still valid passes plain `verify`: dropping the last entries or deleting the files leaves no gap to find. `verify` prints the journal head, and the session report records both heads at close. `verify --expected-head HEX` with a head printed earlier fails after the end is dropped and after the journal is deleted. That detects the change only if the head was kept somewhere the agent cannot write, for example off the machine.

`approvals/journal.jsonl` holds the signed decisions and execution records. `verify` reads it when it is there and checks the approver signature, the binding of each decision to its held receipt, that each execution is inside the expiry window and bound to the same call, and that one approval was not used twice. Deleting it before the call runs removes the decision, so the call is held again. Deleting it after the call ran leaves no record to check, and no receipt names the approval, so `verify` passes. Truncating it is covered in the row for the execution record.

**d. Reuse.** An approval is used by one call. The same call again is held. This holds only while the execution record stays in the approval journal (see c). When that record is dropped, nothing else shows the second run: the receipt of the held call and the receipts of the forwarded calls all record REQUIRE_APPROVAL, none of them carries the approval id, and `--expected-head` covers only the receipts journal, not `approvals/journal.jsonl`.

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
| Not a defence, a pinned fact of case c, d: a receipt key naming an approval (`praetore.approval_id` added to every receipt's context) | `truncating_the_approval_journal_lets_a_used_approval_run_again` |
