#!/usr/bin/env bash
# Smoke test of the Węglarka panel image on Podman: the container starts under the hardening an operator
# applies (read-only root, no capabilities, no-new-privileges, numeric non-root user), `/healthz` answers with the
# security headers, nothing but the login flow is reachable without a session, embedded assets carry `nosniff`,
# a bad configuration is refused without echoing the secret, and SIGTERM stops the container promptly.
#
#   smoke-panel.sh <image>
#
# The panel dials the daemon's token socket lazily and the OIDC provider only on login, so neither has to run.
set -euo pipefail

image=$1
name=weglarka-panel-smoke
port=18090
base="http://127.0.0.1:$port"
secret=smoke-secret-value-do-not-print

hardening=(--read-only --cap-drop=ALL --security-opt=no-new-privileges)
# A loopback http issuer is accepted for tests only; the rest is what the daemon injects for an app with `oidc`.
env_args=(
  -e OIDC_CLIENT_ID=panel-smoke
  -e "OIDC_CLIENT_SECRET=$secret"
  -e OIDC_ISSUER=http://127.0.0.1:9
  -e "PANEL_PUBLIC_URL=$base"
  -e PANEL_API_AUDIENCE=https://admin.example.test/api/
)

tmp=$(mktemp -d)
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  status=$?
  echo "::group::panel logs"; podman logs "$name" 2>&1 || true; echo "::endgroup::"
  podman rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

# --- a bad configuration: non-zero exit, a readable reason, and never the secret
echo "--- bad configuration is refused without printing the secret"
set +e
podman run --rm --name "$name-bad" --pull=never "${hardening[@]}" \
  -e OIDC_CLIENT_ID=panel-smoke -e "OIDC_CLIENT_SECRET=$secret" -e OIDC_ISSUER=not-a-url \
  -e "PANEL_PUBLIC_URL=$base" -e PANEL_API_AUDIENCE=https://admin.example.test/api/ \
  "$image" > "$tmp/bad.out" 2>&1
rc=$?
set -e
cat "$tmp/bad.out"
[ "$rc" -ne 0 ] || fail "the panel started with an invalid OIDC_ISSUER"
grep -q 'OIDC_ISSUER' "$tmp/bad.out" || fail "the error does not name OIDC_ISSUER"
if grep -qF "$secret" "$tmp/bad.out"; then fail "the client secret was printed"; fi

# --- the real thing
echo "--- starting the panel (read-only root, no capabilities, no-new-privileges)"
podman run -d --pull=never --name "$name" -p "127.0.0.1:$port:8080" "${hardening[@]}" "${env_args[@]}" "$image" >/dev/null

for _ in $(seq 30); do
  curl -fsS -o /dev/null "$base/healthz" 2>/dev/null && break
  sleep 1
done

# curl -D prints the headers to a file; -o discards the body unless a check needs it.
echo "--- GET /healthz"
code=$(curl -sS -D "$tmp/health.h" -o "$tmp/health.b" -w '%{http_code}' "$base/healthz")
[ "$code" = 200 ] || fail "/healthz returned $code"
grep -qx 'ok' "$tmp/health.b" || fail "/healthz body is not 'ok'"
header() { grep -i "^$1:" "$2" | head -1 | tr -d '\r' || true; }
csp=$(header content-security-policy "$tmp/health.h")
case $csp in
  *"default-src 'none'"*"script-src 'self'"*"frame-ancestors 'none'"*) ;;
  *) fail "/healthz has no strict Content-Security-Policy: '$csp'" ;;
esac
case $csp in *unsafe-inline* | *unsafe-eval*) fail "the CSP allows unsafe-inline/unsafe-eval: '$csp'" ;; esac
for want in 'x-content-type-options: nosniff' 'referrer-policy: no-referrer' 'cross-origin-opener-policy: same-origin'; do
  header "${want%%:*}" "$tmp/health.h" | tr '[:upper:]' '[:lower:]' | grep -qF "$want" || fail "/healthz is missing '$want'"
done
echo "healthz ok with: $csp"

# --- nothing is served without a session
echo "--- GET / without a session"
code=$(curl -sS -D "$tmp/root.h" -o "$tmp/root.b" -w '%{http_code}' "$base/")
case $code in
  302 | 303 | 307) header location "$tmp/root.h" | grep -qi '/auth/login' || fail "GET / redirects, but not to the login: $(header location "$tmp/root.h")" ;;
  401 | 403) ;;
  *) fail "an unauthenticated GET / returned $code (expected a redirect to login or 401/403)" ;;
esac
if grep -qi '<html' "$tmp/root.b"; then
  case $code in 401 | 403) ;; *) fail "an unauthenticated GET / served a page" ;; esac
fi
[ -n "$(header content-security-policy "$tmp/root.h")" ] || fail "the redirect/deny response has no CSP"
for path in /config /apps /events/stream; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$base$path")
  case $code in 302 | 303 | 307 | 401 | 403 | 404) ;; *) fail "unauthenticated $path returned $code" ;; esac
done
echo "no page is served without a session"

# --- embedded assets
echo "--- /static/ assets"
code=$(curl -sS -D "$tmp/css.h" -o "$tmp/css.b" -w '%{http_code}' "$base/static/app.css")
[ "$code" = 200 ] || fail "/static/app.css returned $code"
[ -s "$tmp/css.b" ] || fail "/static/app.css is empty"
header x-content-type-options "$tmp/css.h" | tr '[:upper:]' '[:lower:]' | grep -qF nosniff || fail "/static/app.css has no nosniff"
header content-type "$tmp/css.h" | grep -qi 'text/css' || fail "/static/app.css has the wrong content type: $(header content-type "$tmp/css.h")"
code=$(curl -sS -o /dev/null -w '%{http_code}' "$base/static/no-such-file")
[ "$code" = 404 ] || fail "an unknown asset returned $code"
echo "assets ok"

# --- the hardening really applied
[ "$(podman inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$name")" = true ] || fail "the rootfs is not read-only"
podman inspect -f '{{.HostConfig.SecurityOpt}}' "$name" | grep -q 'no-new-privileges' || fail "no-new-privileges is not set"
[ "$(podman inspect -f '{{.Config.User}}' "$name")" = 65532:65532 ] || fail "the image does not run as 65532:65532"

# --- SIGTERM stops it cleanly and quickly
echo "--- SIGTERM"
start=$(date +%s)
podman kill --signal TERM "$name" >/dev/null
podman wait "$name" > "$tmp/exit" 2>&1 || true
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -le 5 ] || fail "the panel took ${elapsed}s to stop on SIGTERM"
[ "$(cat "$tmp/exit")" = 0 ] || fail "the panel exited with $(cat "$tmp/exit") after SIGTERM (expected 0)"
echo "stopped in ${elapsed}s with exit 0"
