#!/bin/sh
# Claude Code PreToolUse hook: authorizes every tool call with PRÆTORE.
# Install it in a project as .claude/hooks/praetore-hook.sh, with the binary
# at .claude/bin/praetore-claude-hook (or set PRAETORE_HOOK_BIN) and the state
# created by `praetore-claude-hook init .claude/praetore`. Register it with
# "onFailure": "block" (Claude Code 2.1.295 or later), so that a failure of
# this script itself also blocks the tool call.
#
# Fails closed: if the project directory, the binary or the state is
# missing, or the binary cannot start, panics, is killed by a signal or
# exits with any status other than 0, this script prints a deny decision and
# exits 0. A hook that merely errors would let the tool call through.
#
# PRAETORE_HOOK_BIN, when set and not empty, must be an absolute path to an
# executable regular file; anything else is a deny. It is not otherwise checked:
# whoever controls the environment of the hook process chooses the binary
# that decides, as with PATH.

deny() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$1"
  exit 0
}

root="${CLAUDE_PROJECT_DIR:-}"
if [ -z "$root" ]; then
  cat >/dev/null
  deny "PRÆTORE hook: CLAUDE_PROJECT_DIR is not set"
fi
bin="$root/.claude/bin/praetore-claude-hook"
if [ -n "${PRAETORE_HOOK_BIN:-}" ]; then
  case "$PRAETORE_HOOK_BIN" in
    /*) ;;
    *)
      cat >/dev/null
      deny "PRÆTORE hook: PRAETORE_HOOK_BIN must be an absolute path"
      ;;
  esac
  bin="$PRAETORE_HOOK_BIN"
fi
state="$root/.claude/praetore"
if [ ! -f "$bin" ] || [ ! -x "$bin" ] || [ ! -f "$state/policy.json" ]; then
  cat >/dev/null
  deny "PRÆTORE hook is not set up: install the praetore-claude-hook binary and run init .claude/praetore"
fi

# No exec: the binary's status is checked before its output is passed on.
# The binary reads the event on stdin; stderr goes straight through.
output="$("$bin" hook "$state")"
status=$?
if [ "$status" -ne 0 ]; then
  cat >/dev/null
  deny "PRÆTORE hook binary failed (exit status $status); the tool call is denied"
fi
case "$output" in
  '') ;;                       # no decision: Claude Code's permissions apply
  '{'*'}') printf '%s\n' "$output" ;;
  *) deny "PRÆTORE hook binary printed something other than a JSON object; the tool call is denied" ;;
esac
exit 0
