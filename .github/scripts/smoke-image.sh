#!/usr/bin/env bash
# Smoke test of the Węglarka image on rootless Podman 6: the daemon starts, the CLI answers over the admin
# socket, `doctor` returns a result, and ingress brings up the nginx container — `behind` mode (a Traefik
# file in a tempdir) by default, `edge` mode (issue #95: nginx owns the public ports, TLS, ACME webroot)
# when asked for as the fifth argument.
#
#   smoke-image.sh <image> <path-to-weglarka-binary> <podman-socket> [acceptance-script] [behind|edge]
#
# With a fourth argument (scripts/acceptance.sh) the acceptance script runs against the same daemon:
# canary, traffic through nginx, webhooks, rollback, cleanup. In `edge` mode it runs over TLS and without
# the local-registry/volume legs: those do not depend on the ingress mode and the `behind` run covers them.
set -euo pipefail

image=$1
cli=$2
podman_sock=$3
acceptance=${4:-}
mode=${5:-behind}
case $mode in
  behind | edge) ;;
  *)
    echo "usage: smoke-image.sh <image> <path-to-weglarka> <podman-socket> [acceptance-script] [behind|edge]" >&2
    exit 2
    ;;
esac

dir=$(mktemp -d)
chmod 755 "$dir"
admin_sock="$dir/run/admin.sock"
canary_domain=wg-canary.example.test
# The same form as docs/install.md: tag + digest.
nginx_image="docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"

# A self-signed certificate in the layout the daemon mounts at /etc/nginx: `<state dir>/nginx/tls/<domain>.crt|key`
# (issue #95). In edge mode nginx renders a TLS server only for a routed domain that already has a certificate
# pair, so the canary's certificate must exist before the canary is added (and before the daemon starts).
make_cert() { # domain
  mkdir -p "$dir/nginx/tls"
  chmod 755 "$dir/nginx" "$dir/nginx/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes -days 2 \
    -keyout "$dir/nginx/tls/$1.key" -out "$dir/nginx/tls/$1.crt" -subj "/CN=$1" \
    -addext "subjectAltName=DNS:$1" >/dev/null 2>&1
  chmod 600 "$dir/nginx/tls/$1.key"
  chmod 644 "$dir/nginx/tls/$1.crt"
}

if [ "$mode" = behind ]; then
  touch "$dir/traefik.yml" # plik zakłada się z góry (docs/decisions/0005)
  cat > "$dir/weglarka.toml" <<TOML
[runtime]
user = "$(id -un)"
socket = "$podman_sock"

[ingress]
mode = "behind"
bind = "127.0.0.1:18080"
traefik_dynamic_file = "$dir/traefik.yml"
# ta sama forma co w docs/install.md: tag + digest
nginx_image = "$nginx_image"

[admin]
socket = "$admin_sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.test"
TOML
else
  make_cert "$canary_domain"
  cat > "$dir/weglarka.toml" <<TOML
[runtime]
user = "$(id -un)"
socket = "$podman_sock"

[ingress]
mode = "edge"
bind = "127.0.0.1:18080"
https_bind = "127.0.0.1:18443"
# ta sama forma co w docs/install.md: tag + digest
nginx_image = "$nginx_image"

[admin]
socket = "$admin_sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.test"
TOML
fi

cleanup() {
  status=$?
  echo "::group::weglarka logs"; podman logs weglarka-smoke 2>&1 || true; echo "::endgroup::"
  echo "::group::weglarka-nginx logs"; podman logs weglarka-nginx 2>&1 || true; echo "::endgroup::"
  echo "::group::containers"; podman ps -a || true; echo "::endgroup::"
  echo "::group::weglarka-forwarder logs"; podman logs weglarka-forwarder 2>&1 || true; echo "::endgroup::"
  podman rm -f weglarka-smoke weglarka-nginx weglarka-forwarder wg-edge-rel >/dev/null 2>&1 || true
  podman network rm -f net-weglarka >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

# Paths are mounted 1:1 (as in the quadlet); the container root = the same user as on the host.
podman run -d --pull=never --name weglarka-smoke -p 127.0.0.1:19180:9180 \
  -v "$podman_sock:$podman_sock" -v "$dir:$dir" \
  "$image" run --config "$dir/weglarka.toml"

echo "waiting for admin socket"
for _ in $(seq 30); do [ -S "$admin_sock" ] && break; sleep 1; done
[ -S "$admin_sock" ] || { echo "admin socket did not appear"; exit 1; }

echo "--- weglarka status (CLI z hosta, przez socket)"
"$cli" --socket "$admin_sock" status
echo "--- weglarka status (CLI z obrazu, podman exec)"
podman exec weglarka-smoke /usr/local/bin/weglarka --socket "$admin_sock" status

echo "waiting for nginx container (ingress apply: sieć, pull, create)"
for _ in $(seq 90); do
  [ "$(podman inspect -f '{{.State.Running}}' weglarka-nginx 2>/dev/null || true)" = true ] && break
  sleep 1
done
[ "$(podman inspect -f '{{.State.Running}}' weglarka-nginx 2>/dev/null || true)" = true ] \
  || { echo "nginx container is not running"; exit 1; }

# The ingress container is the only one facing outside traffic, so it is hardened (docs/decisions/0014):
# read-only root, no-new-privileges and exactly the capabilities nginx needs (CHOWN, SETGID, SETUID —
# the worker uid drop and chowning its temp dirs), with `nginx -t` still passing inside. The daemon runs
# `nginx -t` on a reload too; here it is explicit so a broken profile fails early.
[ "$(podman inspect -f '{{.HostConfig.ReadonlyRootfs}}' weglarka-nginx)" = true ] \
  || { echo "weglarka-nginx rootfs is not read-only"; exit 1; }
podman inspect -f '{{.HostConfig.SecurityOpt}}' weglarka-nginx | grep -q 'no-new-privileges' \
  || { echo "weglarka-nginx runs without no-new-privileges"; exit 1; }
caps=$(podman inspect -f '{{json .EffectiveCaps}}' weglarka-nginx)
[ "$(printf '%s' "$caps" | grep -o 'CAP_[A-Z_]*' | sort -u | tr '\n' ' ' || true)" = "CAP_CHOWN CAP_SETGID CAP_SETUID " ] \
  || { echo "weglarka-nginx capabilities are not exactly CHOWN+SETGID+SETUID: $caps"; exit 1; }
podman exec weglarka-nginx nginx -t -c /etc/nginx/nginx.conf \
  || { echo "nginx -t fails inside the hardened container"; exit 1; }
echo "weglarka-nginx is hardened: read-only root, no-new-privileges, CHOWN+SETGID+SETUID only"

if [ "$mode" = edge ]; then
  # Edge mode publishes both web ports on the host, but through the forwarder (issue #162): plain HTTP
  # (the redirects and the ACME webroot) and TLS (the proxied apps, the fail-closed default server).
  # nginx itself publishes nothing and listens on the forwarder's unix sockets with proxy_protocol.
  for _ in $(seq 1 30); do podman inspect weglarka-forwarder >/dev/null 2>&1 && break; sleep 1; done
  bindings=$(podman inspect -f '{{json .HostConfig.PortBindings}}' weglarka-forwarder)
  for pair in '8080/tcp:18080' '8443/tcp:18443'; do
    container_port=${pair%:*}
    host_port=${pair##*:}
    printf '%s' "$bindings" | grep -qF "\"$container_port\"" \
      || { echo "weglarka-forwarder does not publish $container_port: $bindings"; exit 1; }
    printf '%s' "$bindings" | grep -qE "\"HostPort\"[[:space:]]*:[[:space:]]*\"$host_port\"" \
      || { echo "weglarka-forwarder does not publish $container_port on host port $host_port: $bindings"; exit 1; }
  done
  nginx_bindings=$(podman inspect -f '{{json .HostConfig.PortBindings}}' weglarka-nginx)
  case "$nginx_bindings" in
    '{}'|'null'|'') ;;
    *) echo "weglarka-nginx must not publish ports in edge mode: $nginx_bindings"; exit 1 ;;
  esac
  podman exec weglarka-nginx grep -qF 'listen unix:/run/weglarka-ingress/https.sock' /etc/nginx/nginx.conf \
    || { echo "nginx.conf has no forwarder socket listener"; exit 1; }
  echo "weglarka-forwarder publishes plain HTTP on 18080 and TLS on 18443; nginx listens on unix sockets"

fi

echo "--- weglarka doctor (kody 0/1/2 = ok/warn/fail to wynik, nie awaria smoke testu)"
set +e
"$cli" --socket "$admin_sock" doctor --json > "$dir/doctor.json"
rc=$?
set -e
cat "$dir/doctor.json"
[ "$rc" -le 2 ] || { echo "doctor failed to run (exit $rc)"; exit 1; }
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$dir/doctor.json"

nginx_id=$(podman inspect -f '{{.Id}}' weglarka-nginx)

if [ -n "$acceptance" ]; then
  echo "--- skrypt odbioru (acceptance.sh) na demonie ze smoke testu"
  if [ "$mode" = behind ]; then
    # No Traefik and no TLS: traffic goes straight to nginx (Host: domain), webhooks straight to the daemon
    # listener; preflight is skipped — the CI runner is not the target host layout.
    PATH="$(cd "$(dirname "$cli")" && pwd):$PATH" "$acceptance" --config "$dir/weglarka.toml" \
      --canary-domain "$canary_domain" \
      --direct http://127.0.0.1:18080 --webhook-base http://127.0.0.1:19180 \
      --skip-preflight --with-local-registry --with-volume \
      --health-window 4 --dup-wait 5
  else
    # Edge mode is detected from the config: traffic over https on https_bind (`--resolve`/`-k`), the canary
    # certificate in <state dir>/nginx/tls, ACME over the plain-HTTP publish. No Traefik file to check.
    PATH="$(cd "$(dirname "$cli")" && pwd):$PATH" "$acceptance" --config "$dir/weglarka.toml" \
      --canary-domain "$canary_domain" \
      --webhook-base http://127.0.0.1:19180 \
      --skip-preflight --health-window 4 --dup-wait 5
  fi
fi

# Adding and removing apps (the acceptance canary) only connects/disconnects networks and reloads:
# the nginx container must be the same one (docs/decisions/0007).
[ "$(podman inspect -f '{{.Id}}' weglarka-nginx)" = "$nginx_id" ] \
  || { echo "weglarka-nginx was recreated by an ingress change"; exit 1; }
echo "weglarka-nginx survived app add/remove without recreation"

if [ "$mode" = edge ]; then
  # Issue #95: the daemon rescans `<nginx_conf_dir>/tls` on every apply and reloads nginx (nginx -t + SIGHUP)
  # when the certificate set changes. Another domain's certificate plus a routed app is what changes the
  # rendered config — and the container must stay the same one.
  echo "--- edge: a new certificate is picked up by a reload, not by recreating the container"
  conf_before=$(podman exec weglarka-nginx cat /etc/nginx/nginx.conf)
  make_cert wg-edge-rel.example.test
  "$cli" --socket "$admin_sock" apps add wg-edge-rel docker.io/traefik/whoami:v1.10.4 \
    --domain wg-edge-rel.example.test --port 80
  for _ in $(seq 60); do
    podman exec weglarka-nginx grep -qF 'tls/wg-edge-rel.example.test.crt' /etc/nginx/nginx.conf && break
    sleep 1
  done
  podman exec weglarka-nginx grep -qF 'tls/wg-edge-rel.example.test.crt' /etc/nginx/nginx.conf \
    || { echo "the daemon did not render a TLS server for wg-edge-rel.example.test (no tls/ rescan)"; exit 1; }
  conf_after=$(podman exec weglarka-nginx cat /etc/nginx/nginx.conf)
  [ "$conf_before" != "$conf_after" ] \
    || { echo "nginx.conf did not change after the certificate set changed"; exit 1; }
  [ "$(podman inspect -f '{{.Id}}' weglarka-nginx)" = "$nginx_id" ] \
    || { echo "weglarka-nginx was recreated by a certificate change"; exit 1; }
  echo "a new domain's certificate changed nginx.conf without recreating weglarka-nginx"
  # The probe app is not part of the test result: removing it now lets the daemon clean its network up.
  "$cli" --socket "$admin_sock" apps remove --ignore-missing wg-edge-rel || true
fi
