#!/usr/bin/env bash
# Forwarded headers through the generated nginx.conf (docs/decisions/0007), with plain Docker on a CI runner:
# a trusted peer's X-Forwarded-{Proto,For,Host} reach the app, an untrusted peer's are overwritten.
#
#   test-forwarded-headers.sh <nginx-conf-trusted> <nginx-conf-untrusted>
#
# Both configs come from `cargo run -p weglarka-ingress --example dump -- nginx 127.0.0.11 <trusted>`:
# the first trusts Docker's bridge (the source address of a published-port request), the second does not.
# The sample config has the app `blog` on port 3000 and the domain blog.example.eu.
set -euo pipefail

trusted_conf=$1
untrusted_conf=$2
net=wg-fwd-test
fail=0

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-fwd-nginx 2>&1 || true; echo "::endgroup::"
    echo "::group::blog logs"; docker logs wg-fwd-blog 2>&1 || true; echo "::endgroup::"
  fi
  docker rm -f wg-fwd-blog wg-fwd-nginx >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-fwd-blog wg-fwd-nginx >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true

docker network create "$net" >/dev/null
docker run -d --name wg-fwd-blog --network "$net" --network-alias blog docker.io/traefik/whoami:v1.10.4 --port 3000 >/dev/null

# Status + redirect target for a request carrying the given extra curl args (HTTPS redirect, docs/decisions/0005).
status_of() { # extra curl args... -> "<code> <redirect url>"
  curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: blog.example.eu' "$@" 'http://127.0.0.1:18099/p/a?x=1&y=2'
}

expect_status() { # label actual expected
  if [ "$2" = "$3" ]; then echo "ok   $1: $2"; else echo "FAIL $1: got '$2', expected '$3'"; fail=1; fi
}

request() { # conf -> whoami body for a request carrying forged forwarded headers
  docker rm -f wg-fwd-nginx >/dev/null 2>&1 || true
  docker run -d --name wg-fwd-nginx --network "$net" -p 127.0.0.1:18099:8080 \
    -v "$1:/etc/nginx/nginx.conf:ro" docker.io/library/nginx:1-alpine >/dev/null
  for _ in $(seq 30); do
    curl -fsS -o /dev/null -H 'Host: blog.example.eu' http://127.0.0.1:18099/ 2>/dev/null && break
    sleep 1
  done
  curl -fsS -H 'Host: blog.example.eu' -H 'X-Forwarded-Proto: https' \
    -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Forwarded-Host: forged.example' http://127.0.0.1:18099/ | tr -d '\r'
}

expect() { # label body pattern
  if grep -qiF -- "$3" <<<"$2"; then echo "ok   $1: $3"; else echo "FAIL $1: missing $3"; fail=1; fi
}
reject() {
  if grep -qiF -- "$3" <<<"$2"; then echo "FAIL $1: unexpected $3"; fail=1; else echo "ok   $1: no $3"; fi
}

body=$(request "$trusted_conf")
expect trusted "$body" 'X-Forwarded-Proto: https'
expect trusted "$body" 'X-Forwarded-For: 203.0.113.9'
expect trusted "$body" 'X-Forwarded-Host: forged.example'
expect trusted "$body" 'X-Real-Ip: 203.0.113.9'

# HTTP → HTTPS: only an explicit `http` from a trusted peer redirects; HTTPS and "no header" (the daemon's
# health probe: trusted peer, no forwarded headers) do not. The trusted conf is still running from request().
expect_status 'trusted + http' "$(status_of -H 'X-Forwarded-Proto: http')" '301 https://blog.example.eu/p/a?x=1&y=2'
expect_status 'trusted + ws (plain-HTTP websocket)' "$(status_of -H 'X-Forwarded-Proto: ws')" '301 https://blog.example.eu/p/a?x=1&y=2'
expect_status 'trusted + wss' "$(status_of -H 'X-Forwarded-Proto: wss')" '200 '
expect_status 'trusted + https' "$(status_of -H 'X-Forwarded-Proto: https')" '200 '
expect_status 'trusted, no header (health probe)' "$(status_of)" '200 '

body=$(request "$untrusted_conf")
expect untrusted "$body" 'X-Forwarded-Proto: http'
reject untrusted "$body" 'X-Forwarded-Proto: https'
reject untrusted "$body" '203.0.113.9'
reject untrusted "$body" 'forged.example'
expect untrusted "$body" 'X-Forwarded-Host: blog.example.eu'

expect_status 'untrusted + http (header ignored)' "$(status_of -H 'X-Forwarded-Proto: http')" '200 '

echo "--- nginx access log (untrusted run)"
docker logs wg-fwd-nginx 2>&1 | tail -3
exit "$fail"
