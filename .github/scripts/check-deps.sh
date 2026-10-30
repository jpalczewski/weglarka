#!/usr/bin/env bash
# Dependency guards for the daemon's static musl graph (#219):
#  - no C crypto or system TLS (the image is `scratch`: `ring` + bundled roots only);
#  - the panel's tree obeys the same rules, has no `weglarka-engine`, and nothing depends on it;
#  - `reqwest` stays out of the CLI (only network-facing crates may depend on `weglarka-http`); same for `weglarka-unix-http`.
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

cli_tree=$(cargo tree -p weglarka-cli -e normal --prefix none)
if grep -q '^reqwest v' <<<"$cli_tree"; then
  echo "error: 'reqwest' is in the weglarka-cli dependency graph:" >&2
  cargo tree -p weglarka-cli -e normal -i reqwest >&2 || true
  status=1
fi

unix_tree=$(cargo tree -p weglarka-unix-http -e normal --prefix none)
if grep -q '^reqwest v' <<<"$unix_tree"; then
  echo "error: 'reqwest' is in the weglarka-unix-http dependency graph:" >&2
  status=1
fi

# The shared OIDC logic (docs/decisions/0060) is transport-agnostic: the CLI uses it, so it must carry no HTTP
# client or TLS stack of its own.
oidc_tree=$(cargo tree -p weglarka-oidc -e normal --prefix none)
for banned in reqwest hyper rustls tokio-rustls weglarka-http weglarka-engine weglarka-panel; do
  if grep -q "^$banned v" <<<"$oidc_tree"; then
    echo "error: '$banned' is in the weglarka-oidc dependency graph:" >&2
    cargo tree -p weglarka-oidc -e normal -i "$banned" >&2 || true
    status=1
  fi
done

# The panel (docs/decisions/0057) is a network-facing leaf: same crypto rules as the daemon, and
# never the engine (it holds no Podman access; it only talks to the admin API).
panel_tree=$(cargo tree -p weglarka-panel --target "$target" -e normal --prefix none)
for banned in aws-lc-rs aws-lc-sys openssl-sys native-tls weglarka-engine; do
  if grep -q "^$banned v" <<<"$panel_tree"; then
    echo "error: banned crate '$banned' is in the weglarka-panel ($target) dependency graph:" >&2
    cargo tree -p weglarka-panel --target "$target" -e normal -i "$banned" >&2 || true
    status=1
  fi
done

# Nothing may depend on the panel: it is a leaf binary, and the daemon works with it gone. `-i` lists
# the panel and everything that reaches it; the panel alone is the passing answer.
dependents=$(cargo tree --workspace -i weglarka-panel -e normal --prefix none | grep -v '^weglarka-panel v' || true)
if [ -n "$dependents" ]; then
  echo "error: these crates depend on weglarka-panel:" >&2
  echo "$dependents" >&2
  status=1
fi

[ "$status" -eq 0 ] && echo "dependency guards passed"
exit "$status"
