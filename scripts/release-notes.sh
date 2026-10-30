#!/usr/bin/env bash
# Builds the GitHub Release description for a daemon tag from the per-crate CHANGELOG.md files.
#
#   scripts/release-notes.sh vX.Y.Z
#
# The daemon section for that version comes first. Every other crate that released on the same day
# (the release PR bumps them together) follows under its own heading. Run from a checkout of the tag.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

tag=${1:?usage: release-notes.sh vX.Y.Z}
ver=${tag#v}
repo=${GITHUB_REPOSITORY:-jpalczewski/weglarka}

# Body of the `## [<version>]` section: the lines after its heading, up to the next `## `.
section() { # file version
  awk -v v="$2" '
    /^## \[/ { on = index($0, "[" v "]") == 4; next }
    on { print }
  ' "$1" | sed '/./,$!d'
}

date_of() { # file version
  awk -v v="$2" '/^## \[/ && index($0, "[" v "]") == 4 { print $NF; exit }' "$1"
}

daemon=crates/weglarka-daemon/CHANGELOG.md
day=$(date_of "$daemon" "$ver")
[ -n "$day" ] || { echo "no $ver section in $daemon" >&2; exit 1; }

cat <<MD
## Installation

- Container images: \`ghcr.io/$repo:$ver\` and \`ghcr.io/$repo-panel:$ver\` (cosign-signed).
- Binaries: the \`.tar.gz\` assets below, verified with \`SHA256SUMS\` and its \`.sigstore.json\` bundle.

See [docs/install.md](https://github.com/$repo/blob/$tag/docs/install.md).

## weglarka-daemon $ver

$(section "$daemon" "$ver")
MD

for f in crates/*/CHANGELOG.md; do
  [ "$f" = "$daemon" ] && continue
  crate=$(basename "$(dirname "$f")")
  # The newest entry of the crate, if it was released on the daemon's day.
  v=$(sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' "$f" | head -1)
  [ -n "$v" ] && [ "$(date_of "$f" "$v")" = "$day" ] || continue
  body=$(section "$f" "$v")
  [ -n "$body" ] || continue
  printf '\n## %s %s\n\n%s\n' "$crate" "$v" "$body"
done
