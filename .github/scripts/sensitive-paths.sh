#!/usr/bin/env bash
# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Helpers for .github/workflows/sensitive-paths.yml. The workflow runs this
# file from main (pull_request_target), never from the pull request.
#
#   sensitive-paths.sh filter
#       Reads file names on stdin and prints the sensitive ones, sorted.
#   sensitive-paths.sh fingerprint < compare.json
#       Reads a compare API response and prints one line per sensitive file:
#       name, old name of a rename, and the SHA-256 of its patch. Prints
#       UNKNOWN when the response cannot be trusted to be complete: a
#       sensitive file without a patch, or the API's 300-file limit.
#   sensitive-paths.sh unchanged <repo> <base> <before> <after>
#       Exits 0 when the pull request's diff on the sensitive paths is the
#       same at <before> and <after> (#1089), 1 otherwise or when unsure.
set -euo pipefail
export LC_ALL=C # byte order for sort, whatever the runner locale

filter() {
  grep -E \
    -e '^(hooks|bin|skills|mega-linter-plugin-glsec|\.claude-plugin)/' \
    -e '^\.github/(workflows|actions|instructions|agents|skills|scripts)/' \
    -e '^(\.goreleaser\.ya?ml|Dockerfile|\.pre-commit-hooks\.ya?ml)$' \
    -e '(^|/)(CLAUDE|CLAUDE\.local|AGENTS|AGENT|GEMINI)\.md$' \
    -e '^(\.claude|\.agents|\.cursor|\.vscode|\.devcontainer)/' \
    -e '^(\.mcp\.json|\.envrc|\.cursorrules|\.github/copilot-instructions\.md)$' \
    -e '^\.markdownlint(-cli2|-site)?\.(jsonc|ya?ml|json)$' \
    -e '^(\.gitignore|REUSE\.toml|\.golangci\.ya?ml|\.github/(dependabot|secret_scanning)\.yml|\.github/allowed_signers|(\.github/|docs/)?CODEOWNERS)$' \
    | sort -u || true
}

fingerprint() {
  local json
  json=$(cat)
  if [ "$(jq '.files | length' <<<"$json")" -ge 300 ]; then
    echo UNKNOWN
    return
  fi
  # A file is sensitive when its name or the old name of a rename is.
  local names
  names=$(jq -r '.files[] | .filename, (.previous_filename // empty)' <<<"$json" | filter)
  [ -z "$names" ] && return
  jq -c '.files[]' <<<"$json" | while IFS= read -r f; do
    name=$(jq -r .filename <<<"$f")
    prev=$(jq -r '.previous_filename // ""' <<<"$f")
    if ! grep -qxF -e "$name" <<<"$names" && { [ -z "$prev" ] || ! grep -qxF -e "$prev" <<<"$names"; }; then
      continue
    fi
    if [ "$(jq 'has("patch")' <<<"$f")" != true ]; then
      echo UNKNOWN
      continue
    fi
    sum=$(jq -j .patch <<<"$f" | sha256sum | cut -d' ' -f1)
    printf '%s\t%s\t%s\n' "$name" "$prev" "$sum"
  done | sort -u
}

unchanged() {
  local repo=$1 base=$2 before=$3 after=$4 a b
  a=$(gh api "repos/$repo/compare/$base...$before" | fingerprint) || return 1
  b=$(gh api "repos/$repo/compare/$base...$after" | fingerprint) || return 1
  if printf '%s\n%s\n' "$a" "$b" | grep -qx UNKNOWN; then
    echo "a sensitive file has no patch or the diff is too large to compare"
    return 1
  fi
  if [ "$a" != "$b" ]; then
    echo "the pull request's changes to sensitive paths differ from the reviewed state"
    return 1
  fi
  echo "the pull request's changes to sensitive paths are the same as when they were reviewed"
}

cmd=${1:-}
shift || true
case "$cmd" in
  filter) filter ;;
  fingerprint) fingerprint ;;
  unchanged) unchanged "$@" ;;
  *) echo "usage: sensitive-paths.sh filter | fingerprint | unchanged <repo> <base> <before> <after>" >&2; exit 2 ;;
esac
