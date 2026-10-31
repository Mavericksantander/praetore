# Sets 01 and 02 · hook v0 · NOT VERIFIABLE with praetore-verify

These receipts were written by the first version (v0) of the hook. They have
**no attester signature** (`attester_signature` is `null`) and no attester
public key. `praetore-verify evidence` requires an attester pin and signature,
so it cannot verify them, and CI does not check them.

| Set | What it is | Receipts |
| --- | --- | --- |
| `01-sesion-diseno-paco-ladron/` | First real session: the agents designed "Paco y Ladrón" | 47: 46 Allow, 1 Deny |
| `02-prueba-en-worktree-praetore/` | First real test: the coder tries to edit `.claude/agents/explorer.md` and is denied | 5: 4 Allow, 1 Deny |

They were checked at the time with a `praetore-claude-hook-v0 verify` binary
that is not in this repository. Nothing in this repository verifies them
today. Treat them as a historical record, not as verified evidence.
