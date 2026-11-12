#!/usr/bin/env bash
# Tests scripts/check-k8s-default-deny.rb: the repository templates pass,
# and each removed or weakened floor fails.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/scripts/check-k8s-default-deny.rb"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

check() { # <expected: pass|fail> <description> <ruby expression editing the text of file $1>
  rm -rf "$work/k8s" && cp -R "$root/deploy/kubernetes" "$work/k8s"
  if [[ -n "${4:-}" ]]; then
    ruby -e 'path = ARGV[0]; text = File.read(path); edited = eval(ARGV[1]); abort "unchanged: #{path}" if edited == text; File.write(path, edited)' \
      "$work/k8s/$3" "$4"
  fi
  local result=pass
  ruby "$script" "$work/k8s" > /dev/null 2>&1 || result=fail
  if [[ "$result" != "$1" ]]; then
    echo "FAIL: expected $1, got ${result}: $2"
    exit 1
  fi
  echo "ok: $1: $2"
}

check pass "repository templates"
check fail "sandbox floor without Egress (generic)" sandbox-network-policy.yaml \
  'text.sub(/(name: praetore-sandbox-default-deny\n.*?    - Ingress\n)    - Egress\n/m, "\\1")'
check fail "agents floor removed (generic)" mandatory-enforcement.yaml \
  'text.sub(/name: praetore-agents-default-deny\n  namespace: praetore-agents\nspec:\n  podSelector: \{\}/, "name: praetore-agents-default-deny\n  namespace: praetore-agents\nspec:\n  podSelector:\n    matchLabels:\n      praetore.io/role: agent")'
check fail "egress floor with an allow rule (generic)" mandatory-enforcement.yaml \
  'text.sub(/(name: praetore-egress-default-deny\n.*?    - Egress\n)/m, "\\1  egress:\n    - {}\n")'
check fail "sandbox floor with empty lists (Cilium)" cilium-mandatory-enforcement.yaml \
  'text.sub(/(name: praetore-sandbox-default-deny\n.*?endpointSelector: \{\}\n)  ingress:\n    - \{\}\n  egress:\n    - \{\}\n/m, "\\1  ingress: []\n  egress: []\n")'
check fail "tools floor without egress (Cilium)" cilium-mandatory-enforcement.yaml \
  'text.sub(/(name: praetore-tools-default-deny\n.*?    - \{\}\n)  egress:\n    - \{\}\n/m, "\\1")'
