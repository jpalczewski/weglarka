#!/usr/bin/env bash
# Smoke test „jak na produkcji”: Węglarka startuje z argumentów wygenerowanych przez
# `weglarka-daemon platform run-args` (te same środki utwardzenia i env co w quadlecie), a
# weglarka.toml NIE ma `runtime.socket` — socket przekazuje env z quadletu (obraz nie ma /etc/passwd).
#
#   smoke-quadlet.sh <obraz> <binarka-weglarka> <binarka-weglarka-daemon> <socket-podmana>
set -euo pipefail

image=$1
cli=$2
daemon=$3
podman_sock=$4

dir=$(mktemp -d)
chmod 755 "$dir"
admin_sock="$dir/run/admin.sock"
touch "$dir/traefik.yml"

cat > "$dir/weglarka.toml" <<TOML
[runtime]
user = "$(id -un)"
# celowo bez socket — scenariusz z produkcji

[ingress]
mode = "behind"
bind = "127.0.0.1:18081"
traefik_dynamic_file = "$dir/traefik.yml"
nginx_image = "docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"

[state]
dir = "$dir"

[admin]
socket = "$admin_sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.test"
TOML

cleanup() {
  status=$?
  echo "::group::weglarka logs"; podman logs weglarka 2>&1 || true; echo "::endgroup::"
  echo "::group::weglarka-nginx logs"; podman logs weglarka-nginx 2>&1 || true; echo "::endgroup::"
  podman rm -f weglarka weglarka-nginx >/dev/null 2>&1 || true
  podman network rm -f net-weglarka >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

# Socket Podmana liczy host (platform install robi to samo); sieć quadlet zakłada z pliku .network.
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
mapfile -t args < <("$daemon" --config "$dir/weglarka.toml" platform run-args --image "$image" 2>/dev/null)
printf '%s\n' "podman run -d --pull=never ${args[*]}"
podman network create net-weglarka >/dev/null 2>&1 || true
podman run -d --pull=never "${args[@]}"

echo "waiting for admin socket"
for _ in $(seq 30); do [ -S "$admin_sock" ] && break; sleep 1; done
[ -S "$admin_sock" ] || { echo "admin socket did not appear"; podman ps -a; exit 1; }

"$cli" --socket "$admin_sock" status

echo "waiting for nginx container"
for _ in $(seq 90); do
  [ "$(podman inspect -f '{{.State.Running}}' weglarka-nginx 2>/dev/null || true)" = true ] && break
  sleep 1
done
[ "$(podman inspect -f '{{.State.Running}}' weglarka-nginx 2>/dev/null || true)" = true ] \
  || { echo "nginx container is not running"; exit 1; }

# Utwardzenie faktycznie zastosowane.
[ "$(podman inspect -f '{{.HostConfig.ReadonlyRootfs}}' weglarka)" = true ] || { echo "rootfs not read-only"; exit 1; }
[ "$(podman inspect -f '{{.HostConfig.Memory}}' weglarka)" -gt 0 ] || { echo "no memory limit"; exit 1; }
[ "$(podman inspect -f '{{.State.Running}}' weglarka)" = true ] || { echo "weglarka not running"; exit 1; }
[ -s "$dir/traefik.yml" ] || { echo "traefik file not written"; exit 1; }
[ -s "$dir/nginx/nginx.conf" ] || { echo "nginx.conf not written"; exit 1; }
echo "OK"
