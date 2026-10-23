#!/usr/bin/env bash
# Smoke test obrazu Węglarki na rootless Podmanie 6: demon wstaje, CLI odpowiada przez socket
# admina, `doctor` zwraca wynik, a ingress podnosi kontener nginx (tryb `behind`, plik Traefika w tempdir).
#
#   smoke-image.sh <obraz> <ścieżka-do-binarki-weglarka> <socket-podmana> [skrypt-odbioru]
#
# Z czwartym argumentem (scripts/acceptance.sh) na tym samym demonie biegnie skrypt odbioru:
# kanarek, ruch przez nginx (bez Traefika/TLS), webhooki, rollback, sprzątanie.
set -euo pipefail

image=$1
cli=$2
podman_sock=$3
acceptance=${4:-}

dir=$(mktemp -d)
chmod 755 "$dir"
admin_sock="$dir/run/admin.sock"
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
nginx_image = "docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"

[admin]
socket = "$admin_sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.test"
TOML

cleanup() {
  status=$?
  echo "::group::weglarka logs"; podman logs weglarka-smoke 2>&1 || true; echo "::endgroup::"
  echo "::group::weglarka-nginx logs"; podman logs weglarka-nginx 2>&1 || true; echo "::endgroup::"
  echo "::group::containers"; podman ps -a || true; echo "::endgroup::"
  podman rm -f weglarka-smoke weglarka-nginx >/dev/null 2>&1 || true
  podman network rm -f net-weglarka >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

# Ścieżki montujemy 1:1 (jak w quadlecie); root kontenera = ten sam użytkownik co na hoście.
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

echo "--- weglarka doctor (kody 0/1/2 = ok/warn/fail to wynik, nie awaria smoke testu)"
set +e
"$cli" --socket "$admin_sock" doctor --json > "$dir/doctor.json"
rc=$?
set -e
cat "$dir/doctor.json"
[ "$rc" -le 2 ] || { echo "doctor failed to run (exit $rc)"; exit 1; }
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$dir/doctor.json"

if [ -n "$acceptance" ]; then
  echo "--- skrypt odbioru (acceptance.sh) na demonie ze smoke testu"
  # Bez Traefika i TLS: ruch bezpośrednio do nginx (Host: domena), webhooki prosto na listener demona;
  # preflight pomijamy — runner CI to nie docelowy układ hosta.
  PATH="$(cd "$(dirname "$cli")" && pwd):$PATH" "$acceptance" --config "$dir/weglarka.toml" \
    --canary-domain wg-canary.example.test \
    --direct http://127.0.0.1:18080 --webhook-base http://127.0.0.1:19180 \
    --skip-preflight --with-local-registry
fi
