#!/bin/sh
# Claude Code PreToolUse hook: authorizes every tool call with PRÆTORE.
# Install it in a project as .claude/hooks/praetore-hook.sh, with the binary
# at .claude/bin/praetore-claude-hook (or set PRAETORE_HOOK_BIN) and the state
# created by `praetore-claude-hook init .claude/praetore`.
# Fails closed when the binary or the state is missing: a hook that merely
# errors would let the tool call through.
root="${CLAUDE_PROJECT_DIR:?}"
bin="${PRAETORE_HOOK_BIN:-$root/.claude/bin/praetore-claude-hook}"
state="$root/.claude/praetore"
if [ ! -x "$bin" ] || [ ! -f "$state/policy.json" ]; then
  cat >/dev/null
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"PRÆTORE hook is not set up: install the praetore-claude-hook binary and run init .claude/praetore"}}'
  exit 0
fi
exec "$bin" hook "$state"
