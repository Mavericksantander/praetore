# 05 · Real session, final

Real Claude Code session in `~/Desktop/Paco&Ladrón`: the agents checked sources
and closed design gaps. 118 receipts in `evidence/`: 117 Allow, 0 Deny,
1 RequireApproval (`index.json` lists them all).

Hook version: signed with the attester and recorded the denials of agents
without a profile, but did **not** yet resolve paths before evaluating (that
change arrived later and appears in set 03). All 118 receipts have paths
inside `~/Desktop/Paco&Ladrón`.

The RequireApproval case is `0093-coder-Bash-RequireApproval.json`: a Python
heredoc that the hook cannot analyze, held by
`approval-unanalyzable-command`. Nobody could approve it in headless mode, so
it did not run.

Known defect in that receipt: `decision.reason` says
`Policy rule 'approval-git-push' matched`, but the command contains no
`git push`. The hook omitted the `git_push` parameter for unanalyzable
commands, and under policy semantics v2 a missing parameter matches a
restrictive rule as unknown. The outcome (RequireApproval) was right; the
named reason was not. The receipt is left as recorded (editing it would break
its signature); the hook code is fixed so new receipts name only
`approval-unanalyzable-command`.

Verify: see [../VERIFY.md](../VERIFY.md).
