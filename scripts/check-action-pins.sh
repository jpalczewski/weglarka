#!/usr/bin/env bash
# Check every SHA-pinned `uses: owner/repo[/path]@<40-hex> # <tag>` in the workflows and composite actions:
#   1. the SHA exists in owner/repo (a SHA that does not resolve fails every job using it before its first step);
#   2. the tag named in the trailing comment resolves to exactly that SHA (an annotated tag is dereferenced), which
#      also rules out an impostor commit living only in a fork of the same network.
# References that are not SHA-pinned (`@v7`, local `./` actions) are out of scope here; actionlint/zizmor cover them.
#
#   scripts/check-action-pins.sh [FILE...]    default: .github/workflows/*.yml .github/actions/*/action.yml
#
# Needs `gh` (authenticated; in CI set GH_TOKEN) and network access.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=(.github/workflows/*.yml .github/actions/*/action.yml)
fi

problems=0
checked=0
fail() {
  printf 'action pin: %s\n' "$*" >&2
  problems=$((problems + 1))
}

# Prints the commit SHA a tag points to (dereferencing annotated tags), or nothing when the tag does not exist.
resolve_tag() {
  local repo=$1 tag=$2 type sha
  read -r type sha < <(gh api "repos/$repo/git/ref/tags/$tag" --jq '[.object.type, .object.sha] | join(" ")' 2>/dev/null) || return 0
  while [ "$type" = tag ]; do
    read -r type sha < <(gh api "repos/$repo/git/tags/$sha" --jq '[.object.type, .object.sha] | join(" ")')
  done
  printf '%s\n' "$sha"
}

# `file:line:owner/repo/path sha tag` for every pinned reference (a missing tag comment yields an empty field).
refs=$(grep -nHE '^\s*(-\s+)?uses:\s*[^./ ][^@ ]*@[0-9a-f]{40}\b' "${files[@]}" |
  sed -E 's/^([^:]+):([0-9]+):.*uses:[[:space:]]*([^@ ]+)@([0-9a-f]{40})[[:space:]]*(#[[:space:]]*([^[:space:]]+))?.*$/\1:\2 \3 \4 \6/')

declare -A seen
while read -r where action sha tag; do
  [ -n "${where:-}" ] || continue
  repo=$(cut -d/ -f1,2 <<<"$action")
  key="$repo@$sha#${tag:-}"
  if [ -n "${seen[$key]:-}" ]; then
    [ "${seen[$key]}" = ok ] || fail "$where: $action@$sha (same as an earlier failure)"
    continue
  fi
  checked=$((checked + 1))
  if [ -z "${tag:-}" ]; then
    fail "$where: $action@$sha has no '# <tag>' comment to verify the pin against"
    seen[$key]=bad
    continue
  fi
  if ! gh api "repos/$repo/commits/$sha" --jq .sha >/dev/null 2>&1; then
    fail "$where: commit $sha does not exist in $repo"
    seen[$key]=bad
    continue
  fi
  target=$(resolve_tag "$repo" "$tag")
  if [ -z "$target" ]; then
    fail "$where: tag '$tag' does not exist in $repo"
    seen[$key]=bad
  elif [ "$target" != "$sha" ]; then
    fail "$where: $repo tag '$tag' points to $target, not the pinned $sha"
    seen[$key]=bad
  else
    seen[$key]=ok
  fi
done <<<"$refs"

if [ "$problems" -gt 0 ]; then
  printf 'action pin: %d problem(s) in %d distinct pin(s)\n' "$problems" "$checked" >&2
  exit 1
fi
printf 'action pin: %d distinct pin(s) verified\n' "$checked"
