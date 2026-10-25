#!/usr/bin/env bash
# Edge ingress through the generated nginx.conf (issue #95), with plain Docker on a CI runner: nginx owns
# the public web ports, terminates TLS, serves the ACME HTTP-01 webroot, redirects every routed domain
# from plain HTTP to HTTPS, fails closed for routed domains without a certificate and for unknown SNI,
# and rebuilds X-Forwarded-* from the connection instead of trusting the client.
#
#   test-edge.sh <edge-nginx-conf> [cert-dir]
#
# The config comes from `cargo run -p weglarka-ingress --example dump -- nginx-edge <cert-domain>`:
# it routes the sample apps (ntfy, blog, sse, upload, capped) and the webhook domain, and has TLS
# material only for the domains passed to `dump`. Pass an *app* domain (e.g. blog.example.eu): the
# webhook domain's TLS server only answers `/webhook/` paths, so it cannot show forwarded headers — and
# at least one routed domain must stay uncertified to check the fail-closed path. The optional cert dir
# must hold <domain>.crt/<domain>.key for the domains the config references; when it is omitted (or a
# pair is missing) self-signed certificates (EC P-256, subjectAltName=DNS:<domain>, key 0600) are
# generated into a temp dir.
set -euo pipefail

conf=${1:-}
cert_dir=${2:-}
if [ -z "$conf" ]; then
  echo "usage: test-edge.sh <edge-nginx-conf> [cert-dir]" >&2
  exit 2
fi
[ -r "$conf" ] || { echo "FAIL config: cannot read $conf" >&2; exit 1; }

net=wg-edge-test
subnet=172.29.78.0/24
http_port=18090
https_port=18443
work=$(mktemp -d "${TMPDIR:-/tmp}/wg-edge.XXXXXX")
chmod 755 "$work"
fail=0

# Absolute paths: `docker run -v` rejects relative ones.
abs() { case $1 in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
conf=$(abs "$conf")
[ -z "$cert_dir" ] || cert_dir=$(abs "$cert_dir")

# The dumped edge config targets Podman's aardvark-dns through a fixed resolver (`resolver 10.89.0.1`),
# which does not exist on a Docker bridge; Docker's embedded DNS is 127.0.0.11. The runtime copy that the
# nginx container mounts gets exactly that one directive rewritten — listeners, server blocks, TLS paths
# and the ACME webroot stay byte-for-byte the dumped config. (`nginx -t` in CI runs on the undedited dump.)
runtime_conf=$work/nginx.conf
sed -E 's|^([[:space:]]*resolver)[[:space:]]+[^;]+;|\1 127.0.0.11 valid=1s ipv6=off;|' "$conf" >"$runtime_conf"
chmod 644 "$runtime_conf"
if ! cmp -s "$conf" "$runtime_conf"; then
  echo "--- runtime config: resolver rewritten to Docker's embedded DNS (127.0.0.11)"
fi
conf=$runtime_conf

# `docker run -d` names of the upstream containers; filled below.
ups=()

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-edge-nginx 2>&1 | tail -80 || true; echo "::endgroup::"
    for name in ${ups[@]+"${ups[@]}"}; do
      echo "::group::$name logs"; docker logs "$name" 2>&1 | tail -20 || true; echo "::endgroup::"
    done
  fi
  docker rm -f wg-edge-nginx ${ups[@]+"${ups[@]}"} >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-edge-nginx >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true

expect() { # label actual expected
  if [ "$2" = "$3" ]; then echo "ok   $1: $2"; else echo "FAIL $1: got '$2', expected '$3'"; fail=1; fi
}

body_contains() { # label body pattern
  if grep -qiF -- "$3" <<<"$2"; then echo "ok   $1: $3"; else echo "FAIL $1: missing $3"; fail=1; fi
}

# A whole header line, case-insensitively: `X-Forwarded-Proto: http` is a prefix of `...: https`, so a
# substring check would claim a forged value survived when nginx actually overwrote it.
body_lacks_line() { # label body line
  local body
  body=$(tr -d '\r' <<<"$2")
  if grep -qixF -- "$3" <<<"$body"; then echo "FAIL $1: unexpected line '$3'"; fail=1; else echo "ok   $1: no '$3'"; fi
}

# ── What the config routes ───────────────────────────────────────────────────
# The generated edge config has one `server` per domain, so the plain extractors below are exact:
# `server_name` lists the routed domains, `ssl_certificate /etc/nginx/tls/<domain>.crt` the TLS ones.

routed_domains=$(sed -nE 's/^[[:space:]]*server_name[[:space:]]+(.*);[[:space:]]*$/\1/p' "$conf" |
  tr -s '[:space:]' '\n' | grep -vE '^_?$' | sort -u)
cert_domains=$(grep -oE '/etc/nginx/tls/[A-Za-z0-9._-]+\.crt' "$conf" |
  sed 's|.*/||; s|\.crt$||' | sort -u)

if [ -z "$routed_domains" ]; then
  echo "FAIL config: no server_name in $conf — not an edge nginx config?" >&2
  exit 1
fi
if [ -z "$cert_domains" ]; then
  echo "FAIL config: no ssl_certificate under /etc/nginx/tls — pass a routed domain to" >&2
  echo "     'dump -- nginx-edge <domain>' so the sample config has a TLS server" >&2
  exit 1
fi

tls_domain=$(head -n1 <<<"$cert_domains")
# A routed domain without TLS material: it must still redirect on HTTP and its TLS handshake must fail
# (fail closed — no certificate, no HTTPS server).
plain_domain=
while IFS= read -r domain; do
  if ! grep -qxF "$domain" <<<"$cert_domains"; then
    plain_domain=$domain
    break
  fi
done <<<"$routed_domains"
if [ -z "$plain_domain" ]; then
  echo "FAIL config: every routed domain has a certificate — no way to check the fail-closed TLS path;" >&2
  echo "     pass exactly one certificate domain, e.g. 'dump -- nginx-edge $tls_domain'" >&2
  exit 1
fi
echo "--- tls domain: $tls_domain, domain without a cert: $plain_domain"
echo "--- routed: $(tr '\n' ' ' <<<"$routed_domains")"

# ── Certificates and ACME webroot ────────────────────────────────────────────

if [ -n "$cert_dir" ]; then
  tls_dir=$cert_dir
  mkdir -p "$tls_dir"
else
  tls_dir=$work/tls
  mkdir -p "$tls_dir"
fi
chmod 755 "$tls_dir"

make_cert() { # domain dir
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes -days 2 \
    -keyout "$2/$1.key" -out "$2/$1.crt" -subj "/CN=$1" \
    -addext "subjectAltName=DNS:$1" >/dev/null 2>&1
  chmod 600 "$2/$1.key"
  chmod 644 "$2/$1.crt"
}

while IFS= read -r domain; do
  [ -n "$domain" ] || continue
  if [ -s "$tls_dir/$domain.crt" ] && [ -s "$tls_dir/$domain.key" ]; then
    echo "ok   certificate: using $tls_dir/$domain.crt"
  else
    make_cert "$domain" "$tls_dir"
    echo "ok   certificate: generated a self-signed pair for $domain"
  fi
done <<<"$cert_domains"

acme_dir=$work/acme
mkdir -p "$acme_dir"
token="wg-edge-token-$$-$(date +%s)"
token_body="wg-edge-challenge-body-$$"
printf '%s' "$token_body" >"$acme_dir/$token"
chmod 644 "$acme_dir/$token"

# ── Containers ───────────────────────────────────────────────────────────────
docker network create --subnet "$subnet" "$net" >/dev/null

# One whoami per upstream the config proxies to (`set $upstream "http://host:port"`): the sample config
# has several app ports, and nginx resolves each by container name. Alias + port are what nginx dials.
i=0
while IFS= read -r target; do
  [ -n "$target" ] || continue
  host=${target%:*}
  port=${target##*:}
  i=$((i + 1))
  ups+=("wg-edge-up$i")
  docker run -d --name "wg-edge-up$i" --network "$net" --network-alias "$host" \
    docker.io/traefik/whoami:v1.10.4 --port "$port" >/dev/null
done < <(grep -oE 'http://[A-Za-z0-9._-]+:[0-9]+' "$conf" | sed 's|http://||' | sort -u)
if [ "${#ups[@]}" -eq 0 ]; then
  echo "FAIL config: no upstream (http://host:port) found in $conf" >&2
  exit 1
fi
echo "--- upstreams: ${ups[*]}"

docker run -d --name wg-edge-nginx --network "$net" \
  -p "127.0.0.1:$http_port:8080" -p "127.0.0.1:$https_port:8443" \
  -v "$conf:/etc/nginx/nginx.conf:ro" -v "$tls_dir:/etc/nginx/tls:ro" \
  -v "$acme_dir:/etc/nginx/acme:ro" docker.io/library/nginx:1-alpine >/dev/null

# Readiness through the ACME path: once it answers 200, nginx runs and the upstreams resolve.
ready=0
probe="http://127.0.0.1:$http_port/.well-known/acme-challenge/$token"
for _ in $(seq 30); do
  if curl -fsS -o /dev/null -H "Host: $tls_domain" "$probe" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL readiness: nginx on 127.0.0.1:$http_port did not serve the ACME challenge within 30 s"
  fail=1
  exit "$fail"
fi
echo "ok   readiness: nginx serves the ACME webroot"

# The webhook domain's TLS server answers only `/webhook/` paths (404 elsewhere), so its certificate cannot
# show the X-Forwarded-* headers: this test needs a certificate for an app domain. Fail with an actionable
# message instead of a cascade of status/header failures (`dump nginx-edge` with no argument certifies the
# webhook domain by default).
probe_code=$(curl -sS -k -o "$work/probe.body" -w '%{http_code}' --max-time 10 \
  --resolve "$tls_domain:$https_port:127.0.0.1" "https://$tls_domain:$https_port/" 2>/dev/null || true)
if [ "$probe_code" != 200 ] || ! grep -qi 'X-Forwarded-For' "$work/probe.body"; then
  echo "FAIL tls domain: https://$tls_domain:$https_port/ → $probe_code, expected a proxied app (200)" >&2
  echo "     pass an app domain to 'dump -- nginx-edge', e.g. blog.example.eu: the webhook domain's TLS" >&2
  echo "     server only answers /webhook/ paths, so it cannot show the forwarded headers" >&2
  fail=1
  exit "$fail"
fi

# One HTTPS request to the TLS domain (self-signed: `-k`), extra curl args appended.
tls_request() { # path [curl args...] -> body on stdout
  local path=$1
  shift
  curl -sS -k --max-time 10 --resolve "$tls_domain:$https_port:127.0.0.1" "$@" \
    "https://$tls_domain:$https_port$path" 2>/dev/null
}

tls_status() { # path [curl args...] -> "<code> <redirect url>"
  local path=$1
  shift
  curl -sS -k -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 \
    --resolve "$tls_domain:$https_port:127.0.0.1" "$@" "https://$tls_domain:$https_port$path" 2>/dev/null || true
}

http_status() { # domain path -> "<code> <redirect url>" on the plain-HTTP publish
  curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 \
    -H "Host: $1" "http://127.0.0.1:$http_port$2" 2>/dev/null || true
}

# ── (a) plain HTTP → 301 https://<domain>$request_uri ────────────────────────

out=$(http_status "$plain_domain" '/p/a?x=1&y=2')
expect "http redirect ($plain_domain, no cert)" "$out" "301 https://$plain_domain/p/a?x=1&y=2"
out=$(http_status "$tls_domain" '/p/a?x=1&y=2')
expect "http redirect ($tls_domain, has cert)" "$out" "301 https://$tls_domain/p/a?x=1&y=2"

# ── (b) ACME HTTP-01 over plain HTTP: 200, the token body, and NO redirect ───

code=$(http_status "$tls_domain" "/.well-known/acme-challenge/$token")
expect "acme challenge ($tls_domain): 200, no redirect" "$code" "200 "
acme_body=$(curl -sS --max-time 10 -H "Host: $tls_domain" "$probe" 2>/dev/null)
expect "acme challenge: body" "$acme_body" "$token_body"

# ── (c) HTTPS with SNI for a domain that has a certificate ───────────────────

body=$(tls_request /)
body_contains "https $tls_domain" "$body" "X-Forwarded-Proto: https"
body_contains "https $tls_domain" "$body" "X-Forwarded-Host: $tls_domain"
body_contains "https $tls_domain" "$body" "X-Forwarded-For:"
out=$(tls_status /)
expect "https $tls_domain: status" "${out%% *}" "200"

# ── (d) routed domain WITHOUT a certificate: 301 on HTTP, no TLS listener ────

out=$(http_status "$plain_domain" /)
expect "http redirect ($plain_domain, root)" "${out%% *}" "301"

# ── (e)/(f) unknown SNI and failed handshakes on the TLS publish ─────────────

# `ssl_reject_handshake on` in the default 8443 server: the handshake of an unknown (or certless) SNI
# must fail — if openssl completes a handshake, nginx served a certificate it must not have served.
tls_rejected() { # label servername expected-friendly-message
  local out rc=0 line
  out=$(openssl s_client -connect "127.0.0.1:$https_port" -servername "$2" -brief </dev/null 2>&1) || rc=$?
  if [ "$rc" -ne 0 ] && ! grep -qiE 'Server certificate|subject=' <<<"$out"; then
    echo "ok   $1: TLS handshake rejected (openssl exit $rc)"
  else
    echo "FAIL $1: TLS handshake was not rejected (openssl exit $rc)"
    while IFS= read -r line; do echo "     | $line"; done <<<"$out"
    fail=1
  fi
}
tls_rejected "unknown SNI" "unknown.example.invalid"
tls_rejected "no certificate ($plain_domain)" "$plain_domain"

# ── (f) a client cannot forge the headers nginx rebuilds ─────────────────────

forged=$(tls_request / -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-For: 203.0.113.9' \
  -H 'X-Forwarded-Host: forged.example')
out=$(tls_status / -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-For: 203.0.113.9' \
  -H 'X-Forwarded-Host: forged.example')
expect "forged headers ($tls_domain): status" "${out%% *}" "200"
body_contains "forged headers" "$forged" "X-Forwarded-Proto: https"
body_lacks_line "forged headers" "$forged" "X-Forwarded-Proto: http"
body_contains "forged headers" "$forged" "X-Forwarded-Host: $tls_domain"
body_lacks_line "forged headers" "$forged" "X-Forwarded-Host: forged.example"
body_lacks_line "forged headers" "$forged" "X-Forwarded-For: 203.0.113.9"
body_contains "forged headers" "$forged" "X-Forwarded-For:"

# ── Unknown Host on the plain-HTTP publish is dropped (444) ──────────────────

out=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: unknown.example.invalid' \
  "http://127.0.0.1:$http_port/" 2>/dev/null || true)
case $out in
  000 | 444) echo "ok   unknown Host on plain HTTP: $out (connection dropped)" ;;
  *) echo "FAIL unknown Host on plain HTTP: got '$out', expected 444 or a dropped connection"; fail=1 ;;
esac

# ── Optional: HTTP/2 advertised on the TLS listener ──────────────────────────

h2=$(curl -sS -k -o /dev/null -w '%{http_version}' --max-time 10 \
  --resolve "$tls_domain:$https_port:127.0.0.1" "https://$tls_domain:$https_port/" 2>/dev/null || true)
echo "info HTTP version on the TLS listener: $h2 (HTTP/2 is expected, not asserted)"

echo "--- nginx access log (last lines)"
docker logs wg-edge-nginx 2>&1 | tail -5 || true
exit "$fail"
