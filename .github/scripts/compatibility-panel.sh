#!/usr/bin/env bash
# Compatibility matrix leg: this daemon image × one panel image.
#
#   compatibility-panel.sh <daemon-image-ref> <panel-image-ref>
#
# Both arguments are digest references (`ghcr.io/…@sha256:…`) so the leg tests exactly the bytes the
# release set will name. The images are not in the local store of this job, so they are pulled by
# digest on first use (`--pull=missing`); a digest cannot resolve to different bytes. The daemon is started the way an operator runs it (rootless Podman socket,
# state directory mounted 1:1); the panel then starts against that daemon's admin socket and must
# answer `/healthz` under the operator hardening. The exit status is the matrix result.
#
# This proves the pair boots and the panel is pointed at a live daemon. It does not exercise an
# authenticated panel session (that needs an OIDC provider), so it is not a substitute for the
# engine's own panel/daemon protocol tests.
set -euo pipefail

daemon=$1
panel=$2
podman_sock=${WEGLARKA_PODMAN_SOCKET:-}
[ -n "$podman_sock" ] || {
  echo "WEGLARKA_PODMAN_SOCKET is not set; the compatibility matrix needs rootless Podman" >&2
  exit 2
}

dir=$(mktemp -d)
chmod 755 "$dir"
admin_sock="$dir/run/admin.sock"
traefik="$dir/traefik.yml"
nginx_image="docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"
touch "$traefik"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

cleanup() {
  status=$?
  echo "::group::daemon logs"
  podman logs wg-compat-daemon 2>&1 || true
  echo "::endgroup::"
  echo "::group::panel logs"
  podman logs wg-compat-panel 2>&1 || true
  echo "::endgroup::"
  podman rm -f wg-compat-daemon wg-compat-panel weglarka-nginx >/dev/null 2>&1 || true
  podman network rm -f net-weglarka >/dev/null 2>&1 || true
  rm -rf "$dir"
  exit "$status"
}
trap cleanup EXIT

cat > "$dir/weglarka.toml" <<TOML
[runtime]
user = "$(id -un)"
socket = "$podman_sock"

[ingress]
mode = "behind"
bind = "127.0.0.1:18180"
traefik_dynamic_file = "$traefik"
nginx_image = "$nginx_image"

[admin]
socket = "$admin_sock"

[webhook]
listen = "0.0.0.0:19181"
domain = "weglarka.example.test"
TOML

echo "--- starting the daemon image $daemon"
podman run -d --pull=missing --name wg-compat-daemon -p 127.0.0.1:19181:19181 \
  -v "$podman_sock:$podman_sock" -v "$dir:$dir" \
  "$daemon" run --config "$dir/weglarka.toml" >/dev/null

# The daemon image is `FROM scratch` (no shell, no coreutils), so the socket is checked from the
# host: `$dir` is mounted 1:1 and the container's root maps to the runner user (rootless Podman).
for _ in $(seq 60); do
  [ -S "$admin_sock" ] && break
  sleep 1
done
[ -S "$admin_sock" ] ||
  fail "the daemon did not create its admin socket"
podman exec wg-compat-daemon /usr/local/bin/weglarka --socket "$admin_sock" status >/dev/null ||
  fail "the CLI inside the daemon image cannot query the daemon"

echo "--- starting the panel image $panel against $admin_sock"
podman run -d --pull=missing --name wg-compat-panel -p 127.0.0.1:18091:8080 \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v "$dir:$dir" \
  -e "WEGLARKA_PANEL_SOCKET=$admin_sock" \
  -e OIDC_CLIENT_ID=compat-matrix \
  -e OIDC_CLIENT_SECRET=compat-matrix-secret \
  -e OIDC_ISSUER=http://127.0.0.1:9 \
  -e PANEL_PUBLIC_URL=http://127.0.0.1:18091 \
  -e PANEL_API_AUDIENCE=https://admin.example.test/api/ \
  "$panel" >/dev/null

for _ in $(seq 30); do
  curl -fsS -o /dev/null http://127.0.0.1:18091/healthz 2>/dev/null && break
  sleep 1
done
curl -fsS http://127.0.0.1:18091/healthz | grep -qx 'ok' ||
  fail "the panel /healthz did not answer 'ok' against this daemon image"

echo "compatible: $daemon × $panel"
