#!/usr/bin/env bash
# Security headers of a container app through the generated nginx.conf (#497, docs/decisions/0076), with
# plain Docker on a CI runner:
#
#   * an app that sends no `X-Frame-Options`/`Content-Security-Policy` gets the ingress values;
#   * an app that sends its own header keeps it — exactly one header, the app's value, never two
#     (`map $upstream_http_*` decides per response);
#   * the baseline preset and HSTS are on every answer, also where the app sent something else.
#
#   test-security-headers.sh <nginx-conf>
#
# The config comes from `cargo run -p weglarka-ingress --example dump -- nginx 127.0.0.11 172.16.0.0/12`
# (its `secure` app proxies to `http://secure:3000` on the Docker network below).
set -euo pipefail

conf=$1
net=wg-security-test
port=18097
fail=0
work=$(mktemp -d "${TMPDIR:-/tmp}/wg-security.XXXXXX")

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-security-nginx 2>&1 | tail -80 || true; echo "::endgroup::"
    echo "::group::upstream logs"; docker logs wg-security-app 2>&1 | tail -40 || true; echo "::endgroup::"
  fi
  docker rm -f wg-security-app wg-security-nginx >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-security-app wg-security-nginx >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true

# The upstream app. `/own` and `/own-csp` set a header of their own; everything else answers without
# them. nginx:alpine is already the image the ingress tests use, so this pulls nothing new.
cat >"$work/app.conf" <<'EOF'
server {
    listen 3000;
    location = /own {
        add_header X-Frame-Options SAMEORIGIN always;
        return 200 "own\n";
    }
    location = /own-csp {
        add_header Content-Security-Policy "default-src 'self' https://app.example" always;
        return 200 "own-csp\n";
    }
    location / {
        return 200 "plain\n";
    }
}
EOF
chmod -R a+rX "$work"

docker network create "$net" >/dev/null
docker run -d --name wg-security-app --network "$net" --network-alias secure \
  -v "$work/app.conf:/etc/nginx/conf.d/default.conf:ro" docker.io/library/nginx:1-alpine >/dev/null
docker run -d --name wg-security-nginx --network "$net" -p "127.0.0.1:$port:8080" \
  --read-only --tmpfs /tmp:rw,size=16m -v /run/weglarka-probe -v wg-nginx-logs:/var/log/weglarka \
  -v "$conf:/etc/nginx/nginx.conf:ro" docker.io/library/nginx:1-alpine >/dev/null

ready=0
for _ in $(seq 30); do
  if curl -fsS -o /dev/null -H 'Host: secure.example.eu' "http://127.0.0.1:$port/plain" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL: nginx did not serve secure.example.eu through the upstream"
  exit 1
fi

# headers <path>: the response headers of one request.
headers() {
  curl -sS -D - -o /dev/null -H 'Host: secure.example.eu' "http://127.0.0.1:$port$1" || true
}

# header_values <headers> <name>: every value of one header, one per line (empty when absent).
header_values() {
  printf '%s\n' "$1" | tr -d '\r' | awk -v want="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')" '
    { line = tolower($0) }
    index(line, want ":") == 1 { sub(/^[^:]*:[ ]*/, ""); print }
  '
}

expect_header() { # expect_header <description> <headers> <name> <want>
  local values count
  values=$(header_values "$2" "$3")
  count=$(printf '%s' "$values" | grep -c . || true)
  if [ "$count" = 1 ] && [ "$values" = "$4" ]; then
    echo "ok   $1: $3: $values"
  else
    echo "FAIL $1: want exactly one '$3: $4', got $(printf '%s' "$values" | paste -sd'|' -)"
    fail=1
  fi
}

plain=$(headers /plain)
expect_header "app without the header gets the ingress value" "$plain" X-Frame-Options DENY
expect_header "baseline preset" "$plain" X-Content-Type-Options nosniff
expect_header "referrer policy" "$plain" Referrer-Policy strict-origin-when-cross-origin
expect_header "HSTS in behind mode too" "$plain" Strict-Transport-Security max-age=31536000
expect_header "CSP from the spec" "$plain" Content-Security-Policy "default-src 'self'"

# The app wins: its own `X-Frame-Options` is the only one, not DENY and not a duplicate.
own=$(headers /own)
expect_header "app's own X-Frame-Options wins" "$own" X-Frame-Options SAMEORIGIN
expect_header "the app's answer still gets the CSP" "$own" Content-Security-Policy "default-src 'self'"

own_csp=$(headers /own-csp)
expect_header "app's own CSP wins" "$own_csp" Content-Security-Policy "default-src 'self' https://app.example"
expect_header "the app's answer still gets X-Frame-Options" "$own_csp" X-Frame-Options DENY

if [ "$fail" -ne 0 ]; then
  echo "FAILED"
  exit 1
fi
echo "ok: security headers for a container app"
