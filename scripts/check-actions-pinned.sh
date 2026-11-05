#!/usr/bin/env bash
# Fails if a `uses:` in the workflows is not pinned to a full 40-character
# commit SHA. A tag or a branch can be moved by whoever controls that repository;
# a commit SHA cannot. A version may follow in a comment, for the reader and for
# Dependabot. Any line that looks like a `uses` key in another form, or a local
# action, also fails: the check must not be avoidable by the way it is written.
#
# Usage: scripts/check-actions-pinned.sh [workflows-dir]
set -euo pipefail

dir="${1:-.github/workflows}"
shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "error: no workflows in ${dir}" >&2
  exit 1
fi

pinned='^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}([[:space:]]+#.*)?$'
key='(^|[[:space:]{,"'"'"'-])uses["'"'"']?[[:space:]]*:'
comment='^[[:space:]]*#'
total=0
bad=0
for file in "${files[@]}"; do
  number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$((number + 1))
    [[ "$line" =~ $comment ]] && continue
    [[ "$line" =~ $key ]] || continue
    total=$((total + 1))
    if ! [[ "$line" =~ $pinned ]]; then
      echo "error: ${file}:${number}: not pinned to a 40-character commit SHA: ${line}" >&2
      bad=$((bad + 1))
    fi
  done < "$file"
done

if [[ "$total" -eq 0 ]]; then
  echo "error: no uses: found in ${dir}" >&2
  exit 1
fi
if [[ "$bad" -ne 0 ]]; then
  echo "error: ${bad} of ${total} uses: are not pinned" >&2
  exit 1
fi
echo "${total} uses: pinned to a commit SHA"
