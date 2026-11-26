#!/usr/bin/env bash
# Print the CHANGELOG.md section for a release tag, for the GitHub Release body.
#
# Usage: scripts/release-notes.sh <tag> [changelog]
#
# <tag> is vX.Y.Z (or vX.Y.Z-suffix). The section is the text after the line
# `## X.Y.Z` or `## X.Y.Z - <date>` up to the next `## ` heading. A missing or
# empty section fails, so a tag cannot be released without its notes. The
# heading of a released section must be exactly `## X.Y.Z - YYYY-MM-DD`: no
# date, a placeholder (anything with `<`) or another date form fails, so a
# release cannot publish a placeholder date.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <tag> [changelog]" >&2
  exit 2
fi
tag=$1 changelog=${2:-CHANGELOG.md}
version=${tag#v}
if [[ "$version" == "$tag" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: $tag is not a vX.Y.Z tag" >&2
  exit 1
fi

notes=$(awk -v version="$version" '
  /^## / {
    if (found) exit
    if ($2 == version && (NF == 2 || $3 == "-")) { found = 1; next }
  }
  found && !started && /^[[:space:]]*$/ { next }
  found { started = 1; print }
' "$changelog")

if ! grep -q '[^[:space:]]' <<<"$notes"; then
  echo "error: no CHANGELOG section for $version in $changelog" >&2
  exit 1
fi
heading=$(awk -v version="$version" '
  /^## / && $2 == version && (NF == 2 || $3 == "-") { print; exit }
' "$changelog")
date_re='[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
# Exactly one date after the version: a placeholder (`<...>`) never matches.
if [[ "$heading" != "## $version - "* || ! "${heading#"## $version - "}" =~ ^${date_re}$ ]]; then
  echo "error: the heading of $version must be '## $version - YYYY-MM-DD', got: $heading" >&2
  exit 1
fi
printf '%s\n' "$notes"
