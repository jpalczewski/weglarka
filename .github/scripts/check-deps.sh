#!/usr/bin/env bash
# Dependency guards for the daemon's static musl graph (#219):
#  - no C crypto or system TLS (the image is `scratch`: `ring` + bundled roots only);
#  - `reqwest` stays out of the CLI (only network-facing crates may depend on `weglarka-http`).
set -euo pipefail

target=x86_64-unknown-linux-musl
tree=$(cargo tree -p weglarka-daemon --target "$target" -e normal --prefix none)

status=0
for banned in aws-lc-rs aws-lc-sys openssl-sys native-tls; do
  if grep -q "^$banned v" <<<"$tree"; then
    echo "error: banned crate '$banned' is in the weglarka-daemon ($target) dependency graph:" >&2
    cargo tree -p weglarka-daemon --target "$target" -e normal -i "$banned" >&2 || true
    status=1
  fi
done

# `cargo tree -i` exits non-zero when the package is not in the graph, which is what we want.
if cli=$(cargo tree -p weglarka-cli -e normal -i reqwest 2>/dev/null); then
  echo "error: 'reqwest' is in the weglarka-cli dependency graph:" >&2
  echo "$cli" >&2
  status=1
fi

[ "$status" -eq 0 ] && echo "dependency guards passed"
exit "$status"
