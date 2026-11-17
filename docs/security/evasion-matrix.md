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
| b | Edit `config.toml` (`report = false`) | limitación conocida | `an_edited_config_turns_reports_off_but_not_the_receipts` | Not needed for decisions (the config decides nothing). A home that must keep reports would need the config signed like the policy |
| c | Remove a receipt from the middle of the receipts journal | detectado después | `a_receipt_removed_from_the_middle_fails_verify` | Already detected |
| c | Cut the receipts journal in the middle of a line | detectado después | `a_receipts_journal_cut_mid_line_fails_verify` | Already detected |
| c | Drop the last receipts whole, or delete the receipts journal | limitación conocida | `dropping_the_last_receipts_or_the_whole_journal_passes_verify` | `verify` against a head kept outside the home, or the head sent off the machine |
| c | Delete `approvals/journal.jsonl` before the approved call runs | bloqueado | `deleting_the_approval_journal_holds_the_call_and_verify_still_passes` | Already blocked |
| c | Delete `approvals/journal.jsonl` after the approved call ran | limitación conocida | `deleting_the_approval_journal_holds_the_call_and_verify_still_passes` | `verify` requiring, for each receipt forwarded on an approval, the signed decision it names |
| c, d | Drop the execution record at the end of `approvals/journal.jsonl` so the same approval runs again | limitación conocida | `truncating_the_approval_journal_lets_a_used_approval_run_again` | The approval head kept outside the home, or the execution bound into the receipts chain so `verify` sees two executions of one approval |
| d | Send the approved call twice | bloqueado | `an_approval_is_used_once` | Already blocked |
| e | Change the arguments after approval | bloqueado | `an_approval_does_not_cover_other_arguments` | Already blocked |
| e | Same tool and arguments under another `--name`, or another held tool with the same arguments | bloqueado | `an_approval_does_not_cover_another_server_or_another_held_tool` | Already blocked |
| f | Use another allowed tool with the same effect | limitación conocida | `another_allowed_tool_with_the_same_effect_is_forwarded` | Rules over the effect (paths, resources) for every tool of the server; `policy coverage` shows which tools a rule leaves open |

## Details

**a. Without `wrap`.** praetore-mcp sees only the calls that pass through `wrap`. If the client config is changed to start the server directly, the call runs, no receipt is written and `verify` passes with the same count. `praetore-mcp install` writes the client config, and a process running as the same user can rewrite it.

**b. Policy and config.** `wrap` reads `policy.json` when it starts, and a policy edit is also how a person changes the rules. `verify` therefore passes after an edit. Every receipt carries `evidence.policy_digest`, the digest of the policy that decided it, so the edit shows as a new digest between two receipts. Nothing checks that the edit was made by a person. `config.toml` only turns reports on or off. It never changes a decision.

**c. Journals.** The receipts journal is a hash chain: a removed or reordered entry and a cut line fail `verify`. A shorter chain that is still valid passes. Dropping the last entries or deleting the files leaves no gap to find. `verify` prints the journal head, and the session report records both heads at close, but `verify` has no flag to compare against a head kept elsewhere.

`approvals/journal.jsonl` holds the signed decisions and execution records, and `verify` does not read it. Deleting it before the call runs removes the decision, so the call is held again. Deleting or truncating it after the call ran is not detected.

**d. Reuse.** An approval is used by one call. The same call again is held. This holds only while the execution record stays in the approval journal (see c).

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
