# Claude Code hook evidence

Receipts recorded by `praetore-claude-hook` (this example) during real and demo
sessions. How to check them, with real outputs: [VERIFY.md](VERIFY.md).

| Set | What it is | Receipts | Checked with |
| --- | --- | --- | --- |
| [`05-sesion-real-final/`](05-sesion-real-final/) | Real session in `~/Desktop/Paco&Ladrón` | 118: 117 Allow, 0 Deny, 1 RequireApproval | `praetore-verify` (CI) |
| [`04-sesion-real-bloqueada-web-fetch/`](04-sesion-real-bloqueada-web-fetch/) | Real session that stopped: the `web-fetch` agent had no profile | 8: 8 Allow | `praetore-verify` (CI) |
| [`03-bundle-demo-reproducible/`](03-bundle-demo-reproducible/) | The 22 fixed tool calls of `demo.sh` | 22: 5 Allow, 11 Deny, 6 RequireApproval | `praetore-verify` (CI) |
| [`unverified-v0/`](unverified-v0/) | Sets 01 and 02, hook v0, **no attester signature** | 47 and 5 | **Not verifiable** with `praetore-verify` |

What these files are: receipts, the public attester key, the public issuer
pins, `policy.json` and `index.json`. No private key is included.

Limits:

- The keys ship with the evidence, so a successful check proves the
  receipts were not altered after signing (integrity). It does not prove who
  signed them: anyone holding the matching private keys could have produced
  them.
- The agent signature identifies the agent **profile**, not which process
  used it; the profile keys lived in the same user account as the agents.
  These sets predate SAF-14: the profile name is signed by the agent key and
  the attester (`context.profile`), not by the issuer. `verify.sh` checks
  that `index.json` names the same agent as each signed receipt.
- Only tool calls that went through the hook are covered.
- Session 04 left 33 denials without a receipt (see its README).
- Paths under `/Users/...` are kept as recorded: they are part of the signed
  content, and changing them would break the signatures.
- Receipt `0093` of set 05 names `approval-git-push` although the command has
  no `git push`. The receipt is kept unchanged; the hook code was fixed
  afterwards (see the set 05 README).
