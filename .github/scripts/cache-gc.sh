#!/usr/bin/env bash
# Deletes superseded GitHub Actions cache entries, so the repository stays well below its 10 GB quota.
#
# Every Cargo.lock change (release-plz bumps it with each release) writes a new generation of the Rust caches
# (`v0-rust-<shared-key>-<os>-<env hash>-<lock hash>`) and the old ones linger until GitHub evicts them by least
# recent use, which with a full quota also hits the entries `main` is still using. rust-cache restores by prefix
# (without the lock hash) and picks the newest, so on `main` only the newest entry of each family is ever restored.
#
# Deleted:
#  - on refs/heads/main, every entry of a family except the newest one (by creation time);
#  - on any other ref, an entry whose exact key also exists on main (a pure duplicate: the ref can restore main's).
# Keys outside the known families are their own family, so they are never deleted as "superseded".
#
# Usage: cache-gc.sh            (needs GH_TOKEN with `actions: write` and GITHUB_REPOSITORY)
#        CACHE_GC_DRY_RUN=1 cache-gc.sh   (only prints what it would delete)
set -euo pipefail

repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}

entries=$(gh api --paginate "repos/$repo/actions/caches?per_page=100" --jq '.actions_caches[]' | jq -s .)

doomed=$(jq -r '
  def family:
    if test("^v0-rust-") then sub("-[^-]+$"; "")
    elif startswith("playwright-") then "playwright"
    elif startswith("podman-debs-") then "podman-debs"
    elif startswith("bun-") then "bun"
    else . end;
  (map(select(.ref == "refs/heads/main"))) as $main
  | ($main | map(.key)) as $main_keys
  | (
      ($main | group_by(.key | family) | map(sort_by(.created_at) | .[:-1]) | add // [])
      + map(select(.ref != "refs/heads/main" and (.key as $k | $main_keys | index($k))))
    )
  | .[]
  | "\(.id)\t\(.size_in_bytes)\t\(.ref)\t\(.key)"
' <<<"$entries")

if [ -z "$doomed" ]; then
  echo "nothing to delete ($(jq length <<<"$entries") entries)"
  exit 0
fi

total=0
while IFS=$'\t' read -r id size ref key; do
  total=$((total + size))
  printf 'delete %s (%d MB) %s %s\n' "$id" $((size / 1048576)) "$ref" "$key"
  if [ "${CACHE_GC_DRY_RUN:-}" != 1 ]; then
    # An entry already gone (evicted, or deleted by a concurrent run) is not an error.
    gh api -X DELETE "repos/$repo/actions/caches/$id" >/dev/null || echo "  (already gone)"
  fi
done <<<"$doomed"
echo "freed $((total / 1048576)) MB"
