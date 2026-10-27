#!/usr/bin/env bash
# Acceptance script for Węglarka on a real host (docs/install.md, "Acceptance test").
#
# Run as the runtime user (`weglarka`) with XDG_RUNTIME_DIR set; dependencies:
# weglarka, curl, openssl, jq, podman (+ tar for --with-volume). Touches only the instances `wg-canary`,
# `wg-webhook`, `wg-rollback`, `wg-volume`, `wg-nostart` and the `wg-accept-registry` container (local test registry) — never any other apps.
#
# In `[ingress] mode = "edge"` (issue #95) nginx owns the public ports and terminates TLS: the script
# bootstraps a certificate for the canary domain into `<nginx_conf_dir>/tls`, waits until nginx has reloaded
# (the domain's `ssl_certificate` is in nginx.conf), then drives traffic over `https://<domain>:<https port>`
# (`curl --resolve`, `-k`) and checks the ACME HTTP-01 webroot. Mode and ports come from `weglarka.toml`
# (`[ingress] mode`, `bind`, `https_bind`, `nginx_conf_dir`), so the same script runs on a host and in CI.
#
#   scripts/acceptance.sh --canary-domain wg-test.example.com
#
# Exit codes: 0 all PASS, 1 at least one FAIL, 64 invalid invocation / missing dependency.
set -euo pipefail

# traefik/whoami v1.10.4 (multi-arch index) — pinned by digest.
DEFAULT_CANARY_IMAGE='docker.io/traefik/whoami:v1.10.4@sha256:1699d99cb4b9acc17f74ca670b3d8d0b7ba27c948b3445f0593b58ebece92f04'
# docker.io/library/registry:2 — helper registry whose tags can be moved (webhook, rollback).
REGISTRY_IMAGE='docker.io/library/registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'

CANARY=wg-canary
WEBHOOK_APP=wg-webhook
ROLLBACK_APP=wg-rollback
VOLUME_APP=wg-volume
NOSTART_APP=wg-nostart
REGISTRY_CONTAINER=wg-accept-registry

CONFIG=/etc/weglarka/weglarka.toml
CANARY_DOMAIN=
IMAGE=$DEFAULT_CANARY_IMAGE
WEBHOOK_BASE=
DIRECT=
EDGE=0
EDGE_FORCE=0
EXPECT_CLIENT_IP=
EDGE_HTTP_HOST=
EDGE_HTTP_PORT=
EDGE_HTTPS_HOST=
EDGE_HTTPS_PORT=
NGINX_CONF_DIR=
EDGE_TLS_DIR=
EDGE_ACME_DIR=
KEEP=0
LOCAL_REGISTRY=0
WITH_VOLUME=0
SKIP_ROLLBACK=0
SKIP_PREFLIGHT=0
STRICT=0
JSON=0
REGISTRY_PORT=15099
CERT_TIMEOUT=180
DEPLOY_WAIT=120
DUP_WAIT=25
HEALTH_WINDOW=

usage() {
  cat <<'EOF'
Użycie: acceptance.sh --canary-domain DOMENA [opcje]

  --config PLIK          weglarka.toml (domyślnie /etc/weglarka/weglarka.toml)
  --canary-domain DOM    domena kanarka: w DNS i na allowliście walidatora (weglarka_allowed_domains)
  --canary-image REF     obraz kanarka (domyślnie traefik/whoami przypięty po digeście)
  --webhook-base URL     baza URL webhooków (domyślnie https://<webhook.domain> z configu)
  --direct URL           zamiast https://<domena>/ pytaj nginx Węglarki bezpośrednio (Host: <domena>),
                         bez Traefika i TLS — do testów lokalnych/CI, np. http://127.0.0.1:8088
                         (tylko tryb behind; w trybie edge jest odrzucane)
  --expect-client-ip IP  tryb edge (issue #162): uruchom skrypt z INNEJ maszyny niż host i sprawdź, że apka
                         widzi w X-Forwarded-For dokładnie ten adres (a nie adres nginx/forwardera).
                         Z tej samej maszyny nie ma czego sprawdzać, więc CI tej flagi nie używa.
  --edge                 wymuś tryb edge, gdy [ingress] mode nie jest widoczne w configu (normalnie tryb
                         wykrywany jest z configu). W trybie edge adresy publikacji biorą się z
                         [ingress] bind (HTTP) i https_bind (TLS), certyfikat kanarka ląduje w
                         <nginx_conf_dir>/tls, a ruch idzie po https z `curl --resolve ... -k`.
  --keep                 nie usuwaj kanarka na końcu (instancje pomocnicze i tak znikają)
  --with-local-registry  dodatkowo: webhook z realnym deployem + duplikat dostarczenia i wymuszony rollback.
                         Stawia tymczasowy rejestr na 127.0.0.1:<port>; usługa Podmana użytkownika musi
                         mieć wpis `insecure` dla tego adresu w registries.conf (robi to CI; na produkcji
                         nie zalecane). Bez flagi te kroki są pomijane (SKIP).
  --with-volume          dodatkowo: wolumeny (import tara obcego; remove + add zachowuje dane i zakres UID,
                         eksport, --purge-volumes) oraz apka `start = false` (provisioning bez kontenera,
                         import przed pierwszym startem, `apps start`, eksport i sprawdzenie danych).
                         Używa instancji wg-volume i wg-nostart na obrazie kanarka. Wymaga tar.
  --skip-rollback        pomiń test wymuszonego rollbacku
  --skip-preflight       pomiń `doctor --preflight` (np. gdy host to nie docelowy układ)
  --strict               ostrzeżenia `doctor` traktuj jak błąd
  --registry-port PORT   port lokalnego rejestru testowego na 127.0.0.1 (domyślnie 15099)
  --cert-timeout SEK     ile czekać na certyfikat Traefika (domyślnie 180)
  --dup-wait SEK         jak długo obserwować, że duplikat dostarczenia nie wdraża (domyślnie 25)
  --health-window SEK    okno bramki zdrowia kanarka (domyślnie z AppSpec: 30 s); do testów CI,
                         gdzie wolne czekanie na obraz bez healthchecka nic nie weryfikuje
  --json                 raport maszynowy (JSON) na stdout; opis kroków na stderr
  -h, --help             ta pomoc

Socket admina: WEGLARKA_SOCKET albo `admin.socket` z configu (jak w CLI).
EOF
}

die_usage() {
  echo "acceptance.sh: $*" >&2
  exit 64
}

while [ $# -gt 0 ]; do
  case $1 in
    --config) CONFIG=${2:?--config wymaga wartości}; shift 2 ;;
    --canary-domain) CANARY_DOMAIN=${2:?--canary-domain wymaga wartości}; shift 2 ;;
    --canary-image) IMAGE=${2:?--canary-image wymaga wartości}; shift 2 ;;
    --webhook-base) WEBHOOK_BASE=${2:?--webhook-base wymaga wartości}; shift 2 ;;
    --direct) DIRECT=${2:?--direct wymaga wartości}; shift 2 ;;
    --edge) EDGE_FORCE=1; shift ;;
    --expect-client-ip) EXPECT_CLIENT_IP=${2:?--expect-client-ip wymaga wartości}; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --with-local-registry) LOCAL_REGISTRY=1; shift ;;
    --with-volume) WITH_VOLUME=1; shift ;;
    --skip-rollback) SKIP_ROLLBACK=1; shift ;;
    --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
    --strict) STRICT=1; shift ;;
    --registry-port) REGISTRY_PORT=${2:?--registry-port wymaga wartości}; shift 2 ;;
    --cert-timeout) CERT_TIMEOUT=${2:?--cert-timeout wymaga wartości}; shift 2 ;;
    --dup-wait) DUP_WAIT=${2:?--dup-wait wymaga wartości}; shift 2 ;;
    --health-window) HEALTH_WINDOW=${2:?--health-window wymaga wartości}; shift 2 ;;
    --json) JSON=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die_usage "nieznana opcja: $1 (--help)" ;;
  esac
done

[ -n "$CANARY_DOMAIN" ] || die_usage "wymagane --canary-domain"
case $CANARY_DOMAIN in
  *[!a-z0-9.-]* | .* | -*) die_usage "niepoprawna domena: $CANARY_DOMAIN" ;;
esac
for tool in weglarka curl openssl jq podman; do
  command -v "$tool" >/dev/null 2>&1 || die_usage "brak wymaganego narzędzia: $tool"
done
[ -r "$CONFIG" ] || die_usage "nie mogę czytać configu: $CONFIG"

# ── Konfiguracja pochodna ────────────────────────────────────────────────────

# Minimal reader for simple `key = "value"` entries from weglarka.toml (no full TOML parser).
toml_get() {
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$CONFIG" | head -n1
}

# Splits a publish address from the config (`<ip>:<port>`, `[v6]:<port>`) into $BIND_HOST/$BIND_PORT.
# A wildcard address (0.0.0.0, ::) is reached through loopback: that is where the script connects from.
split_bind() { # wartość etykieta
  local value=$1 label=$2
  case $value in
    \[*\]:*) BIND_HOST=${value%:*}; BIND_HOST=${BIND_HOST#[}; BIND_HOST=${BIND_HOST%]} ;;
    *:*) BIND_HOST=${value%:*}; BIND_PORT=${value##*:} ;;
    *) die_usage "$label: oczekuję <ip>:<port>, mam '$value'" ;;
  esac
  case $BIND_HOST in
    0.0.0.0 | :: | '[::]' | localhost) BIND_HOST=127.0.0.1 ;;
    '') die_usage "$label: brak adresu w '$value'" ;;
  esac
  case $BIND_PORT in
    '' | *[!0-9]*) die_usage "$label: brak portu w '$value'" ;;
  esac
}

if [ -z "$WEBHOOK_BASE" ]; then
  webhook_domain=$(toml_get domain)
  [ -n "$webhook_domain" ] || die_usage "brak [webhook] domain w $CONFIG — podaj --webhook-base"
  WEBHOOK_BASE=https://$webhook_domain
fi
WEBHOOK_BASE=${WEBHOOK_BASE%/}
DIRECT=${DIRECT%/}
TRAEFIK_FILE=$(toml_get traefik_dynamic_file)

# ── Tryb ingressu (behind / edge) ────────────────────────────────────────────

# Detection comes from the config (`[ingress] mode`); `--edge` only forces it (e.g. a stripped config).
case $(toml_get mode) in
  edge) EDGE=1 ;;
  behind | '') ;;
  *) die_usage "nieznany [ingress] mode w $CONFIG: $(toml_get mode)" ;;
esac
[ "$EDGE_FORCE" = 0 ] || EDGE=1
if [ "$EDGE" = 1 ]; then
  [ -z "$DIRECT" ] || die_usage "--direct nie ma zastosowania w trybie edge: ruch idzie po https na [ingress] https_bind"
  split_bind "$(toml_get bind)" "[ingress] bind"
  EDGE_HTTP_HOST=$BIND_HOST
  EDGE_HTTP_PORT=$BIND_PORT
  https_bind=$(toml_get https_bind)
  [ -n "$https_bind" ] || die_usage "tryb edge wymaga [ingress] https_bind = \"<ip>:<port>\" w $CONFIG"
  split_bind "$https_bind" "[ingress] https_bind"
  EDGE_HTTPS_HOST=$BIND_HOST
  EDGE_HTTPS_PORT=$BIND_PORT
  # <nginx_conf_dir> is the host directory the daemon mounts at /etc/nginx: `[ingress] nginx_conf_dir` or
  # `<state dir>/nginx`; the state dir is `[state] dir` or the directory of weglarka.toml.
  NGINX_CONF_DIR=$(toml_get nginx_conf_dir)
  if [ -z "$NGINX_CONF_DIR" ]; then
    state_dir=$(toml_get dir)
    if [ -z "$state_dir" ]; then
      state_dir=$(cd -- "$(dirname -- "$CONFIG")" && pwd)
    elif [ "${state_dir#/}" = "$state_dir" ]; then
      state_dir=$(cd -- "$(dirname -- "$CONFIG")" && pwd)/$state_dir
    fi
    NGINX_CONF_DIR=$state_dir/nginx
  fi
  EDGE_TLS_DIR=$NGINX_CONF_DIR/tls
  EDGE_ACME_DIR=$NGINX_CONF_DIR/acme
fi

REG=127.0.0.1:$REGISTRY_PORT
WORK=$(mktemp -d)
: >"$WORK/results.tsv"

# Repo i tag kanarka (do payloadu webhooka): `repo:tag[@digest]` → `repo:tag`.
canary_ref=${IMAGE%%@*}
case ${canary_ref##*/} in
  *:*) ;;
  *) canary_ref=$canary_ref:latest ;;
esac
canary_repo=${canary_ref%:*}

wg() { weglarka --config "$CONFIG" "$@"; }

# ── Step skeleton ───────────────────────────────────────────────────────────

# Steps run in a subshell (die = exit from the step); state between steps goes through files in $WORK.
put() { printf '%s' "$2" >"$WORK/$1"; }
get() { cat "$WORK/$1" 2>/dev/null || true; }
note() { put note "$*"; }
log() { printf '%s\n' "$*"; }
die() {
  printf 'BŁĄD: %s\n' "$*"
  exit 1
}

# Opis przebiegu: stdout, a z --json stderr (stdout zostaje na raport).
human() {
  if [ "$JSON" = 1 ]; then printf '%s\n' "$*" >&2; else printf '%s\n' "$*"; fi
}

skip_step() { # opis powód
  printf '%s\tSKIP\t0\t%s\n' "$1" "$2" >>"$WORK/results.tsv"
  human "SKIP  $1 ($2)"
}

# run_step <klucz> <opis> <funkcja> [wymagane-klucze...]
run_step() {
  local key=$1 title=$2 fn=$3 dep start secs status line rc
  shift 3
  for dep in "$@"; do
    if [ "$(get "status.$dep")" != PASS ]; then
      put "status.$key" SKIP
      printf '%s\tSKIP\t0\t%s\n' "$title" "wymaga kroku: $dep" >>"$WORK/results.tsv"
      human "SKIP  $title (wymaga kroku: $dep)"
      return 0
    fi
  done
  : >"$WORK/note"
  start=$(date +%s)
  # `set -e` does not work in an `if`/`||` context, so the step runs in a subshell with its own `set -e`.
  set +e
  (
    set -e
    "$fn"
  ) >"$WORK/step.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" = 0 ]; then status=PASS; else status=FAIL; fi
  secs=$(($(date +%s) - start))
  put "status.$key" "$status"
  if [ "$status" = FAIL ] && [ ! -s "$WORK/note" ]; then
    note "$(tail -n1 "$WORK/step.log")"
  fi
  printf '%s\t%s\t%s\t%s\n' "$title" "$status" "$secs" "$(get note)" >>"$WORK/results.tsv"
  line=$(printf '%-5s %s (%ss)' "$status" "$title" "$secs")
  [ ! -s "$WORK/note" ] || line="$line — $(get note)"
  human "$line"
  if [ "$status" = FAIL ] || [ -n "${ACCEPTANCE_VERBOSE:-}" ]; then
    human "$(sed 's/^/        /' "$WORK/step.log")"
  fi
}

# ── Cleanup (also on interrupt) ─────────────────────────────────────────────

cleanup_helpers() {
  local app
  for app in "$WEBHOOK_APP" "$ROLLBACK_APP"; do
    wg apps remove --ignore-missing "$app" >/dev/null 2>&1 || true
  done
  wg apps remove --purge-volumes --ignore-missing "$VOLUME_APP" >/dev/null 2>&1 || true
  wg apps remove --purge-volumes --ignore-missing "$NOSTART_APP" >/dev/null 2>&1 || true
  podman rm -f "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
  podman rmi -f "$REG/wg-accept/wh:t" "$REG/wg-accept/rb:t" >/dev/null 2>&1 || true
}

# Edge mode only: the canary's certificate and the ACME token are test artifacts of this run.
# A certificate that was already in <nginx_conf_dir>/tls (a real one) is left alone.
remove_edge_canary_artifacts() {
  [ "$EDGE" = 1 ] || return 0
  if [ "$(get created_cert)" = 1 ]; then
    rm -f "$EDGE_TLS_DIR/$CANARY_DOMAIN.crt" "$EDGE_TLS_DIR/$CANARY_DOMAIN.key" 2>/dev/null || true
  fi
  acme_token=$(get acme_token)
  [ -z "$acme_token" ] || rm -f "$EDGE_ACME_DIR/$acme_token" 2>/dev/null || true
  return 0
}

on_exit() {
  local rc=$?
  trap - EXIT INT TERM
  cleanup_helpers
  if [ "$KEEP" != 1 ]; then
    wg apps remove --ignore-missing "$CANARY" >/dev/null 2>&1 || true
    remove_edge_canary_artifacts
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

# ── Pomocnicze ───────────────────────────────────────────────────────────────

# jq na `apps show --json` instancji.
show_field() { # app filtr
  wg --json apps show "$1" | jq -r "$2"
}

# Waits (up to $2 s) until the command returns 0.
wait_for() { # opis timeout polecenie...
  local what=$1 timeout=$2 i=0
  shift 2
  while ! "$@" >/dev/null 2>&1; do
    i=$((i + 2))
    [ "$i" -le "$timeout" ] || return 1
    sleep 2
  done
  log "$what: ok po ~${i}s"
}

# One request to the canary → HTTP code ("000" on a transport error); body in $WORK/body.
# Extra curl arguments (e.g. forged headers) come from the caller.
canary_request() {
  local rc=0 code url=https://$CANARY_DOMAIN/
  local -a extra=("$@")
  if [ "$EDGE" = 1 ]; then
    # nginx terminates TLS here: the certificate is the one bootstrapped for the canary (self-signed in
    # tests), so `-k`; `--resolve` points the domain at the published https port (DNS is not needed).
    url=https://$CANARY_DOMAIN:$EDGE_HTTPS_PORT/
    extra+=(--resolve "$CANARY_DOMAIN:$EDGE_HTTPS_PORT:$EDGE_HTTPS_HOST" -k)
  elif [ -n "$DIRECT" ]; then
    url=$DIRECT/
    # Impersonate Traefik: the request reaches nginx through the port forwarder, which dials from one of
    # nginx's own addresses — trusted by default — so the header must arrive at the app (docs/decisions/0032).
    extra=(-H "Host: $CANARY_DOMAIN" -H 'X-Forwarded-Proto: https')
  fi
  code=$(curl -sS --max-time 10 -o "$WORK/body" -w '%{http_code}' ${extra[@]+"${extra[@]}"} "$url" 2>"$WORK/curl_err") || rc=$?
  put curl_rc "$rc"
  printf '%s' "$code"
}

# A whole header line from whoami: `X-Forwarded-Proto: http` is a prefix of `...: https`, so a substring
# check would report a forged value that nginx actually overwrote.
body_has_line() { # pełna linia
  tr -d '\r' <"$WORK/body" | grep -qixF -- "$1"
}

# Predicates for wait_for (called indirectly).
# shellcheck disable=SC2329
digest_changed_from() { [ "$(show_field "$WEBHOOK_APP" '.state.current // empty')" != "$1" ]; }
# shellcheck disable=SC2329
router_gone() { ! grep -qF "$CANARY_DOMAIN" "$TRAEFIK_FILE"; }

# whoami prints the request headers; ignore case and a possible trailing CR on the line.
body_has() { # początek linii
  tr -d '\r' <"$WORK/body" | grep -qiF -- "$1"
}

# The canary answers 200 and a header from nginx/Traefik is visible (X-Forwarded-Host = the domain).
canary_ok() {
  [ "$(canary_request)" = 200 ] && body_has "X-Forwarded-Host: $CANARY_DOMAIN"
}

# Edge mode: a self-signed certificate for the canary domain under <nginx_conf_dir>/tls. nginx renders a
# TLS server only for a routed domain that has a cert pair, and a changed certificate set reloads nginx
# (nginx -t + SIGHUP) instead of recreating its container (issue #95).
edge_make_cert() { # domena
  # The daemon creates <nginx_conf_dir>/{tls,acme} on its first apply (`tls/` is 0700): only the files are
  # ours, the directory modes stay as the daemon made them.
  mkdir -p "$EDGE_TLS_DIR"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes -days 2 \
    -keyout "$EDGE_TLS_DIR/$1.key" -out "$EDGE_TLS_DIR/$1.crt" -subj "/CN=$1" \
    -addext "subjectAltName=DNS:$1" >/dev/null 2>&1
  chmod 600 "$EDGE_TLS_DIR/$1.key"
  chmod 644 "$EDGE_TLS_DIR/$1.crt"
  put created_cert 1
}

edge_ensure_cert() { # domena
  if [ -s "$EDGE_TLS_DIR/$1.crt" ] && [ -s "$EDGE_TLS_DIR/$1.key" ]; then
    log "certyfikat dla $1 już jest w $EDGE_TLS_DIR"
  else
    edge_make_cert "$1"
    log "zapisano testowy certyfikat dla $1 w $EDGE_TLS_DIR"
  fi
}

hmac_hex() { # sekret plik → hex. Sekret jest jednorazowy i testowy (argv widoczny lokalnie przez chwilę).
  openssl dgst -sha256 -mac HMAC -macopt "key:$1" -r "$2" | cut -d' ' -f1
}

# `registry_package` payload in the format the adapter accepts (docs/decisions/0004).
payload_file() { # plik repo:tag action
  local repo=${2%:*} tag=${2##*:} name
  name=${repo#*/}
  jq -nc --arg action "$3" --arg url "$2" --arg tag "$tag" --arg name "${name##*/}" --arg ns "$(dirname "$name")" \
    '{action:$action, registry_package:{name:$name, namespace:$ns, package_type:"CONTAINER",
      package_version:{package_url:$url, container_metadata:{tag:{name:$tag}}}}}' >"$1"
}

# send_webhook <instance> <secret> <event> <delivery> <payload-file> → HTTP code
send_webhook() {
  local sig
  sig=$(hmac_hex "$2" "$5")
  curl -sS --max-time 15 -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -H "X-GitHub-Event: $3" -H "X-GitHub-Delivery: $4" \
    -H "X-Hub-Signature-256: sha256=$sig" \
    --data-binary "@$5" "$WEBHOOK_BASE/webhook/github/$1"
}

set_secret() { # app nazwa wartość — przez stdin, nigdy z argumentu
  printf '%s' "$3" | wg secrets set "$1" "$2" >/dev/null
}

# Buduje wariant obrazu na bazie kanarka i wypycha go pod `$REG/wg-accept/<repo>:t` (przestawia tag).
push_variant() { # repo numer [unhealthy]
  local ref=$REG/wg-accept/$1:t ctx=$WORK/build-$1-$2
  mkdir -p "$ctx"
  {
    echo "FROM $IMAGE"
    echo "LABEL wg-accept=$2"
    if [ "${3:-}" = unhealthy ]; then
      echo 'HEALTHCHECK --interval=1s --timeout=2s --retries=1 CMD ["/whoami","--wg-unhealthy"]'
    fi
  } >"$ctx/Containerfile"
  podman build -q --pull=never --format docker -t "$ref" "$ctx" >/dev/null
  podman push -q --tls-verify=false "$ref" >/dev/null
}

REGISTRY_HINT="usługa Podmana nie ufa rejestrowi $REG po http — dodaj do registries.conf użytkownika wpis [[registry]] location=\"$REG\" insecure=true PRZED startem usługi (tak robi CI)"

# Short health gate so the steps do not wait for the default 30 s.
write_spec() { # plik obraz
  cat >"$1" <<EOF
image = "$2"
port = 80

[health]
attempts = 2
window_secs = 4
EOF
}

# ── Kroki ────────────────────────────────────────────────────────────────────

report_doctor() { # json rc
  local out=$1 rc=$2
  printf '%s' "$out" | jq -e '.checks' >/dev/null 2>&1 || die "doctor nie zwrócił raportu (kod $rc)"
  printf '%s' "$out" | jq -r '.checks[] | select(.status != "ok") | "\(.status) \(.id): \(.message)"'
  case $rc in
    0) note "wszystko ok" ;;
    1)
      note "ostrzeżenia: $(printf '%s' "$out" | jq -r '[.checks[] | select(.status == "warn") | .id] | join(", ")')"
      [ "$STRICT" != 1 ] || die "ostrzeżenia przy --strict"
      ;;
    *) die "doctor zgłasza fail (kod $rc)" ;;
  esac
}

step_preflight() {
  local out rc=0
  out=$(wg --json doctor --preflight) || rc=$?
  report_doctor "$out" "$rc"
}

step_doctor() {
  local out rc=0
  out=$(wg --json doctor) || rc=$?
  report_doctor "$out" "$rc"
}

step_canary() {
  local out outcome digest runtime rc=0
  if [ "$EDGE" = 1 ]; then
    # The certificate must exist before the app is added: the ingress apply only renders a TLS server for
    # a routed domain that already has a cert pair (fail closed otherwise).
    edge_ensure_cert "$CANARY_DOMAIN"
  fi
  wg apps remove --ignore-missing "$CANARY" >/dev/null
  # `health.http` makes the deploy gate go through the real prober and nginx's probe socket (issue #221):
  # in `edge` the plain port only redirects, so before the socket this gate could never pass. The spec
  # file is the only way to set it; a shortened health window (the default is 30 s) is optional.
  cat >"$WORK/canary-spec.toml" <<EOF
image = "$IMAGE"
domains = ["$CANARY_DOMAIN"]
port = 80
EOF
  if [ -n "$HEALTH_WINDOW" ]; then
    printf '\n[health]\nattempts = 2\nwindow_secs = %s\n' "$HEALTH_WINDOW" >>"$WORK/canary-spec.toml"
  fi
  printf '\n[health.http]\npath = "/"\n' >>"$WORK/canary-spec.toml"
  wg apps add "$CANARY" --spec "$WORK/canary-spec.toml" >/dev/null
  out=$(wg --json deploy "$CANARY") || rc=$?
  [ "$rc" = 0 ] || die "deploy kanarka zakończył się kodem $rc: $out"
  outcome=$(printf '%s' "$out" | jq -r .outcome)
  case $outcome in
    deployed | unchanged) ;;
    *) die "deploy kanarka: $outcome" ;;
  esac
  runtime=$(show_field "$CANARY" .runtime)
  digest=$(show_field "$CANARY" '.state.current // empty')
  [ "$runtime" = running ] || die "kanarek nie działa (runtime=$runtime)"
  case $digest in sha256:*) ;; *) die "brak digestu w apps show" ;; esac
  log "outcome=$outcome runtime=$runtime digest=$digest"
  if [ "$EDGE" = 1 ]; then
    # The daemon rerenders nginx.conf and reloads it (nginx -t + SIGHUP, no container recreate) on an
    # ingress change; a TLS server for the canary domain proves both the certificate rescan and the reload.
    wait_for "serwer TLS w nginx.conf" 30 \
      podman exec weglarka-nginx grep -qF "tls/$CANARY_DOMAIN.crt" /etc/nginx/nginx.conf \
      || die "brak 'ssl_certificate .../tls/$CANARY_DOMAIN.crt' w nginx.conf po 30s — certyfikat nie trafił do $EDGE_TLS_DIR albo reload nginx się nie wykonał"
    note "$outcome, $digest, serwer TLS w nginx.conf"
  elif [ -n "$TRAEFIK_FILE" ] && [ -r "$TRAEFIK_FILE" ]; then
    wait_for "router w pliku Traefika" 30 grep -qF "$CANARY_DOMAIN" "$TRAEFIK_FILE" \
      || die "domena kanarka nie pojawiła się w $TRAEFIK_FILE"
    note "$outcome, $digest"
  else
    log "plik Traefika niedostępny — pomijam sprawdzenie routera"
    note "$outcome, $digest"
  fi
  return 0
}

step_traffic() {
  local i=0 code
  while :; do
    code=$(canary_request)
    [ "$code" != 200 ] || break
    i=$((i + 5))
    if [ "$i" -gt "$CERT_TIMEOUT" ]; then
      if [ "$EDGE" = 1 ]; then
        die "brak 200 po ${CERT_TIMEOUT}s (ostatni: https=$code, curl=$(get curl_rc): $(tr '\n' ' ' <"$WORK/curl_err")) — certyfikat w $EDGE_TLS_DIR, reload nginx, [ingress] https_bind?"
      fi
      die "brak 200 po ${CERT_TIMEOUT}s (ostatni: http=$code, curl=$(get curl_rc): $(tr '\n' ' ' <"$WORK/curl_err")) — DNS, allowlista walidatora, certyfikat Traefika (curl 60 = cert jeszcze niewystawiony)?"
    fi
    sleep 5
  done
  log "200 po ~${i}s"
  body_has "X-Forwarded-Host: $CANARY_DOMAIN" \
    || { sed 's/^/  | /' "$WORK/body"; die "brak X-Forwarded-Host: $CANARY_DOMAIN w odpowiedzi whoami (nginx/Traefik nie przekazały nagłówka)"; }
  body_has 'X-Forwarded-For:' || die "brak X-Forwarded-For w odpowiedzi whoami"
  body_has 'X-Forwarded-Proto: https' \
    || die "brak X-Forwarded-Proto: https (nginx nie ufa peerowi? porównaj \`remote_addr\` z logu nginx z własnymi adresami kontenera i sprawdź [ingress] trusted_proxies, docs/decisions/0032)"
  if [ "$EDGE" = 1 ]; then
    # Edge mode terminates TLS, so nginx rebuilds the forwarded headers from the connection ($scheme,
    # $remote_addr, $host) and must not trust what the client sent: a forged chain has to be overwritten,
    # and `X-Forwarded-Proto: http` must not trigger the HTTP→HTTPS redirect on the TLS listener.
    code=$(canary_request -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-For: 203.0.113.9' \
      -H 'X-Forwarded-Host: forged.example')
    [ "$code" = 200 ] || die "żądanie https z podszytymi X-Forwarded-* → $code zamiast 200 (przekierowanie po X-Forwarded-Proto: http?)"
    body_has_line 'X-Forwarded-Proto: https' \
      || die "przy podszytym X-Forwarded-Proto: http apka nie widzi 'X-Forwarded-Proto: https' (nginx ma je nadpisać ze \$scheme)"
    if body_has_line 'X-Forwarded-Host: forged.example'; then
      die "podszyty X-Forwarded-Host (forged.example) dotarł do apki — w trybie edge nginx ma go nadpisać"
    fi
    if body_has_line 'X-Forwarded-For: 203.0.113.9'; then
      die "podszyty X-Forwarded-For (203.0.113.9) dotarł do apki — w trybie edge nginx ma go nadpisać"
    fi
    if [ -n "$EXPECT_CLIENT_IP" ]; then
      # The point of the forwarder (issue #162): the app must see the *client's* address, not nginx's own.
      body_has_line "X-Forwarded-For: $EXPECT_CLIENT_IP" \
        || die "apka nie widzi 'X-Forwarded-For: $EXPECT_CLIENT_IP' — nginx w trybie edge gubi adres klienta (forwarder z PROXY protocol?)"
      note "X-Forwarded-For = $EXPECT_CLIENT_IP (prawdziwy adres klienta)"
    fi
    note "https://$CANARY_DOMAIN:$EDGE_HTTPS_PORT/ → 200, cert (testowy), X-Forwarded-* przebudowane z połączenia"
  elif [ -z "$DIRECT" ]; then
    note "https://$CANARY_DOMAIN/ → 200, cert ważny, nagłówki forwardowane"
  else
    note "$DIRECT (Host: $CANARY_DOMAIN) → 200, nagłówki forwardowane (X-Forwarded-Proto od zaufanego peera); TLS nie sprawdzany"
  fi
}

# Streaming (issue #64): `--streaming` is ingress-only (outside the spec-hash), so the config is
# re-rendered and nginx reloaded while the container stays. A changed generation or spec-hash would
# mean a recreate — the regression this step guards against; `--no-streaming` restores the defaults.
step_streaming() {
  local gen hash out
  gen=$(show_field "$CANARY" '.state.generation // empty')
  hash=$(show_field "$CANARY" '.state.spec_hash // empty')
  out=$(wg --json apps update "$CANARY" --streaming) \
    || die "apps update --streaming nie powiodło się: $out"
  printf '%s' "$out" | jq -e '.deploy == null' >/dev/null \
    || die "apps update --streaming wdrożyło apkę (deploy ≠ null) — ingress ma tylko przeładować nginx"
  wait_for "streaming w nginx.conf" 30 \
    podman exec weglarka-nginx grep -qF 'proxy_buffering off;' /etc/nginx/nginx.conf \
    || die "brak 'proxy_buffering off;' w nginx.conf po 30s — reload nginx się nie wykonał"
  wait_for "proxy_read_timeout 180s w nginx.conf" 30 \
    podman exec weglarka-nginx grep -qF 'proxy_read_timeout 180s;' /etc/nginx/nginx.conf \
    || die "brak 'proxy_read_timeout 180s;' w nginx.conf po 30s — domyślny timeout streamingu nie dotarł do configu"
  [ "$(show_field "$CANARY" '.state.generation // empty')" = "$gen" ] \
    || die "generation zmieniło się ($gen → $(show_field "$CANARY" .state.generation)): --streaming odtworzyło kontener zamiast przeładować nginx"
  [ "$(show_field "$CANARY" '.state.spec_hash // empty')" = "$hash" ] \
    || die "spec-hash zmienił się przy --streaming — kontener został odtworzony zamiast samego reloadu nginx"
  log "streaming: generation=$gen spec-hash=$hash (bez zmian)"

  wg apps update "$CANARY" --no-streaming >/dev/null
  wait_for "brak streamingu w nginx.conf" 30 \
    bash -c "! podman exec weglarka-nginx cat /etc/nginx/nginx.conf | grep -qF 'proxy_buffering off;'" \
    || die "streaming nadal w nginx.conf po 30s od --no-streaming — reload nie wrócił do domyślnych opcji"
  [ "$(show_field "$CANARY" '.state.generation // empty')" = "$gen" ] \
    || die "generation zmieniło się przy --no-streaming ($gen → $(show_field "$CANARY" .state.generation)): odtworzenie kontenera zamiast reloadu nginx"
  note "streaming: nginx reload bez odtworzenia kontenera (generation i spec-hash bez zmian)"
}

# Plain HTTP on the canary domain redirects to HTTPS (no -L). Through Traefik this proves the `http`
# router exists; with --direct we impersonate Traefik's http entrypoint (X-Forwarded-Proto: http).
# In edge mode nginx itself owns the HTTP publish, so the request carries no forwarded headers at all:
# the redirect must come from the connection, not from anything the client claims.
step_http_redirect() {
  local url=http://$CANARY_DOMAIN/ code loc
  local -a extra=()
  if [ "$EDGE" = 1 ]; then
    url=http://$EDGE_HTTP_HOST:$EDGE_HTTP_PORT/
    extra=(-H "Host: $CANARY_DOMAIN")
  elif [ -n "$DIRECT" ]; then
    url=$DIRECT/
    extra=(-H "Host: $CANARY_DOMAIN" -H 'X-Forwarded-Proto: http')
  fi
  code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code} %{redirect_url}' ${extra[@]+"${extra[@]}"} "$url" 2>"$WORK/curl_err") \
    || die "curl $url: $(tr '\n' ' ' <"$WORK/curl_err")"
  loc=${code#* }
  code=${code%% *}
  if [ "$code" != 301 ]; then
    if [ "$EDGE" = 1 ]; then
      die "http://$EDGE_HTTP_HOST:$EDGE_HTTP_PORT/ (Host: $CANARY_DOMAIN) → $code zamiast 301 (poza prefiksem ACME każda routowana domena na porcie HTTP przekierowuje na https)"
    fi
    die "http://$CANARY_DOMAIN/ → $code zamiast 301 (brak routera na entrypoincie http? 404 z Traefika = stary plik/obraz, docs/decisions/0005)"
  fi
  [ "$loc" = "https://$CANARY_DOMAIN/" ] || die "redirect na '$loc' zamiast https://$CANARY_DOMAIN/"
  if [ "$EDGE" = 1 ]; then
    note "http://$EDGE_HTTP_HOST:$EDGE_HTTP_PORT/ (Host: $CANARY_DOMAIN) → 301 https://$CANARY_DOMAIN/"
  else
    note "http://$CANARY_DOMAIN/ → 301 https://$CANARY_DOMAIN/"
  fi
}

# ACME HTTP-01 (issue #95): a token in `<nginx_conf_dir>/acme/<token>` is served over the plain-HTTP publish
# at /.well-known/acme-challenge/<token> — the one path that must answer instead of redirecting, or the
# certificate flow cannot complete. Edge mode only (behind mode has no ACME webroot).
step_acme() {
  local token body code loc
  token=wg-accept-$$-acme
  body=wg-accept-acme-body-$$
  mkdir -p "$EDGE_ACME_DIR"
  printf '%s' "$body" >"$EDGE_ACME_DIR/$token"
  chmod 644 "$EDGE_ACME_DIR/$token"
  put acme_token "$token"
  code=$(curl -sS --max-time 10 -o "$WORK/acme.body" -w '%{http_code} %{redirect_url}' \
    -H "Host: $CANARY_DOMAIN" 2>"$WORK/curl_err" \
    "http://$EDGE_HTTP_HOST:$EDGE_HTTP_PORT/.well-known/acme-challenge/$token") \
    || die "curl http://$EDGE_HTTP_HOST:$EDGE_HTTP_PORT/.well-known/acme-challenge/$token nie powiódł się: $(tr '\n' ' ' <"$WORK/curl_err")"
  loc=${code#* }
  code=${code%% *}
  [ "$code" = 200 ] || die "ACME HTTP-01 → $code zamiast 200 (redirect na '$loc'? prefiks ACME nie może być przekierowany)"
  [ -z "$loc" ] || die "ACME HTTP-01 → redirect na '$loc'; prefiks ACME nie może być przekierowany"
  [ "$(cat "$WORK/acme.body")" = "$body" ] \
    || die "ACME HTTP-01 zwróciło '$(cat "$WORK/acme.body")' zamiast '$body' — webroot $EDGE_ACME_DIR nie jest podpięty?"
  note "ACME HTTP-01: token z <nginx_conf_dir>/acme → 200 bez redirectu"
}

step_registry() {
  podman rm -f "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
  podman run -d --name "$REGISTRY_CONTAINER" -p "127.0.0.1:$REGISTRY_PORT:5000" "$REGISTRY_IMAGE" >/dev/null
  # We do NOT add an `insecure` entry: the pull is done by the long-lived Podman service, which reads registries.conf
  # at startup. The precondition (entry before the service starts) is ensured by the operator/CI; absence = a clear FAIL in the deploy.
  wait_for "rejestr testowy" 60 curl -fsS "http://$REG/v2/" || die "rejestr testowy nie odpowiada na $REG"
  note "lokalny rejestr na $REG"
}

step_webhook_protocol() {
  local secret f code
  secret=$(openssl rand -hex 32)
  set_secret "$CANARY" webhook-hmac "$secret"
  f=$WORK/canary-payload.json
  payload_file "$f" "$canary_ref" published

  code=$(send_webhook "$CANARY" "$secret" registry_package "wg-accept-$$-ok" "$f")
  [ "$code" = 202 ] || die "poprawny webhook: oczekiwano 202, jest $code"
  log "poprawny podpis → 202"

  code=$(send_webhook "$CANARY" "$(openssl rand -hex 32)" registry_package "wg-accept-$$-sig" "$f")
  [ "$code" = 401 ] || die "zły podpis: oczekiwano 401, jest $code"
  log "zły podpis → 401"

  code=$(send_webhook "$CANARY" "$secret" ping "wg-accept-$$-ping" "$f")
  [ "$code" = 204 ] || die "zdarzenie ping: oczekiwano 204, jest $code"
  log "nieobsługiwane zdarzenie (ping) → 204"

  payload_file "$f" "$canary_repo:wg-accept-obcy-tag" published
  code=$(send_webhook "$CANARY" "$secret" registry_package "wg-accept-$$-tag" "$f")
  [ "$code" = 204 ] || die "tag, którego apka nie śledzi: oczekiwano 204, jest $code"
  log "obcy tag → 204"
  note "202 / 401 / 204 / 204 jak w 0004"
}

# Secret removal (issue #80): a throwaway secret set on the canary must disappear from `secrets list`
# again. The canary spec binds no secret under `wg-probe`, so no `--force` is needed and the app is
# untouched; the secret is removed also so the canary cleanup leaves no orphan behind.
step_secrets() {
  local out
  set_secret "$CANARY" wg-probe "wg-accept-$$"
  out=$(wg --json secrets list "$CANARY")
  printf '%s' "$out" | jq -e '.secrets | any(.name == "wg-probe")' >/dev/null \
    || die "secrets list nie zawiera wg-probe po secrets set: $out"
  wg secrets remove "$CANARY" wg-probe >/dev/null || die "secrets remove $CANARY wg-probe nie powiodło się"
  out=$(wg --json secrets list "$CANARY")
  printf '%s' "$out" | jq -e '.secrets | any(.name == "wg-probe") | not' >/dev/null \
    || die "secrets list nadal zawiera wg-probe po secrets remove: $out"
  log "secrets set → list → remove → list: wg-probe zniknął"
  note "usuwanie sekretu: wg-probe set → list → remove → list"
}

# A webhook that really deploys: the app tracks a tag in the local registry; we move the tag and poke it.
step_webhook_deploy() {
  local secret spec f ref gen0 cur0 cur1 cur2 gen1 code i
  ref=$REG/wg-accept/wh:t
  secret=$(openssl rand -hex 32)
  spec=$WORK/wh-spec.toml
  push_variant wh 1
  write_spec "$spec" "$ref"
  wg apps remove --ignore-missing "$WEBHOOK_APP" >/dev/null
  wg apps add "$WEBHOOK_APP" --spec "$spec" >/dev/null
  set_secret "$WEBHOOK_APP" webhook-hmac "$secret"
  wg --json deploy "$WEBHOOK_APP" >/dev/null || die "pierwszy deploy $WEBHOOK_APP nie przeszedł; $REGISTRY_HINT"
  gen0=$(show_field "$WEBHOOK_APP" .state.generation)
  cur0=$(show_field "$WEBHOOK_APP" '.state.current // empty')
  [ -n "$cur0" ] || die "brak digestu po pierwszym deployu"
  log "start: generation=$gen0 digest=$cur0"

  # 1) nowy obraz + webhook → deploy
  push_variant wh 2
  f=$WORK/wh-payload.json
  payload_file "$f" "$ref" published
  code=$(send_webhook "$WEBHOOK_APP" "$secret" registry_package "wg-accept-$$-d1" "$f")
  [ "$code" = 202 ] || die "webhook: oczekiwano 202, jest $code"
  wait_for "deploy z webhooka" "$DEPLOY_WAIT" digest_changed_from "$cur0" \
    || die "webhook 202, ale digest się nie zmienił w ${DEPLOY_WAIT}s"
  cur1=$(show_field "$WEBHOOK_APP" '.state.current')
  gen1=$(show_field "$WEBHOOK_APP" .state.generation)
  [ "$gen1" -gt "$gen0" ] || die "generacja nie wzrosła ($gen0 → $gen1)"
  [ "$(show_field "$WEBHOOK_APP" .runtime)" = running ] || die "$WEBHOOK_APP nie działa po deployu"
  log "deploy z webhooka: generation $gen0 → $gen1, digest $cur1"

  # 2) the same X-GitHub-Delivery with a new image → duplicate, no deploy
  push_variant wh 3
  code=$(send_webhook "$WEBHOOK_APP" "$secret" registry_package "wg-accept-$$-d1" "$f")
  [ "$code" = 202 ] || die "duplikat: oczekiwano 202 (0004: odpowiedź idzie przed wykryciem duplikatu), jest $code"
  i=0
  while [ "$i" -lt "$DUP_WAIT" ]; do
    sleep 5
    i=$((i + 5))
    [ "$(show_field "$WEBHOOK_APP" '.state.current')" = "$cur1" ] || die "duplikat dostarczenia wywołał deploy"
  done
  log "duplikat (to samo X-GitHub-Delivery) → 202, ale bez deployu przez ${DUP_WAIT}s"

  # 3) nowe dostarczenie → deploy
  code=$(send_webhook "$WEBHOOK_APP" "$secret" registry_package "wg-accept-$$-d2" "$f")
  [ "$code" = 202 ] || die "nowe dostarczenie: oczekiwano 202, jest $code"
  wait_for "deploy z nowego dostarczenia" "$DEPLOY_WAIT" digest_changed_from "$cur1" \
    || die "nowe dostarczenie nie wdrożyło obrazu w ${DEPLOY_WAIT}s"
  cur2=$(show_field "$WEBHOOK_APP" '.state.current')
  note "deploy z webhooka, duplikat odrzucony, nowe dostarczenie wdrożone ($cur0 → $cur1 → $cur2)"
}

# Forced rollback: the same tag in the local registry starts pointing at an image with a healthcheck
# that always fails; the container runs, but the health gate rejects it → the previous digest comes back.
step_rollback() {
  local spec ref good out rc=0 now
  ref=$REG/wg-accept/rb:t
  spec=$WORK/rb-spec.toml
  push_variant rb 1
  write_spec "$spec" "$ref"
  wg apps remove --ignore-missing "$ROLLBACK_APP" >/dev/null
  wg apps add "$ROLLBACK_APP" --spec "$spec" >/dev/null
  wg --json deploy "$ROLLBACK_APP" >/dev/null || die "deploy dobrej wersji nie przeszedł; $REGISTRY_HINT"
  good=$(show_field "$ROLLBACK_APP" '.state.current // empty')
  [ -n "$good" ] || die "brak digestu dobrej wersji"
  log "dobra wersja: $good"

  push_variant rb 2 unhealthy
  out=$(wg --json deploy "$ROLLBACK_APP") || rc=$?
  [ "$rc" = 6 ] || die "oczekiwano kodu wyjścia 6 (rolled_back), jest $rc: $out"
  [ "$(printf '%s' "$out" | jq -r .outcome)" = rolled_back ] || die "outcome ≠ rolled_back: $out"
  now=$(show_field "$ROLLBACK_APP" '.state.current // empty')
  [ "$now" = "$good" ] || die "po rollbacku digest to $now, miał być $good"
  [ "$(show_field "$ROLLBACK_APP" .runtime)" = running ] || die "po rollbacku $ROLLBACK_APP nie działa"
  [ -n "$(show_field "$ROLLBACK_APP" '.state.failed.digest // empty')" ] || die "brak zapisu nieudanego deployu w stanie"
  log "kod 6, wrócono do $good, zła wersja: $(show_field "$ROLLBACK_APP" '.state.failed.digest')"
  canary_ok || die "kanarek nie odpowiada 200 po rollbacku"
  note "kod 6, powrót do $good, kanarek nadal 200"
}

# Volumes (iteration 2): a foreign tar (uid 1000, as a Coolify backup would have) is imported into a
# fresh volume, `apps remove` + `apps add` keep the data and the uid range, the export carries the file
# at namespace uid <range start> (the image runs as root; foreign files take the container user's owner), and `--purge-volumes` leaves nothing behind.
add_volume_app() {
  cat >"$WORK/vol-spec.toml" <<EOF
image = "$IMAGE"
port = 80
volumes = [{ name = "data", target = "/data" }]

[health]
attempts = 2
window_secs = ${HEALTH_WINDOW:-4}
EOF
  wg apps add "$VOLUME_APP" --spec "$WORK/vol-spec.toml" >/dev/null
  wg --json deploy "$VOLUME_APP" >/dev/null || die "deploy $VOLUME_APP nie przeszedł"
}

step_volume() {
  local start start2 expect
  wg apps remove --purge-volumes --ignore-missing "$VOLUME_APP" >/dev/null
  add_volume_app
  [ "$(wg --json volumes list "$VOLUME_APP" | jq -r '.volumes[0].exists')" = true ] \
    || die "wolumen nie istnieje po deployu"
  start=$(show_field "$VOLUME_APP" '.state.uid_range.start // empty')
  case $start in '' | *[!0-9]*) die "brak zakresu UID w stanie ($start)" ;; esac

  mkdir -p "$WORK/vol-src"
  printf 'v1\n' >"$WORK/vol-src/f"
  tar -cf "$WORK/vol-in.tar" -C "$WORK/vol-src" --owner=1000 --group=1000 --numeric-owner f
  wg volumes import "$VOLUME_APP" data --from "$WORK/vol-in.tar" >/dev/null || die "volumes import nie przeszedł"
  [ "$(show_field "$VOLUME_APP" .runtime)" = running ] || die "aplikacja nie działa po imporcie (powinna wstać ponownie)"

  wg apps remove "$VOLUME_APP" >/dev/null
  podman volume exists "$VOLUME_APP.data" || die "apps remove skasował wolumen"
  add_volume_app
  start2=$(show_field "$VOLUME_APP" '.state.uid_range.start // empty')
  [ "$start2" = "$start" ] || die "zakres UID się zmienił po remove + add ($start → $start2)"

  wg volumes export "$VOLUME_APP" data --out "$WORK/vol-out.tar" 2>/dev/null || die "volumes export nie przeszedł"
  expect=$start
  tar -tvf "$WORK/vol-out.tar" --numeric-owner \
    | awk -v want="$expect/$expect" '$2 == want && $NF ~ /(^|\/)f$/ { found = 1 } END { exit !found }' \
    || die "w eksporcie brak pliku f z właścicielem $expect (zakres $start): $(tar -tvf "$WORK/vol-out.tar" --numeric-owner | tr '\n' ';')"

  wg apps remove --purge-volumes "$VOLUME_APP" >/dev/null
  ! podman volume exists "$VOLUME_APP.data" || die "--purge-volumes zostawił wolumen"
  note "import obcego tara, dane i zakres $start przeżyły remove + add, eksport z uid $expect, purge czyści"
}

# `start = false` (issue #29): provisioning pins the image digest, creates the network, the uid range and the
# volume, but no container. A foreign tar can be imported before the first start; `apps start` then brings the
# app up (the data is already in the volume) and the export carries it back.
app_running() { # app
  [ "$(show_field "$1" .runtime)" = running ]
}

step_volume_no_start() {
  local start out
  wg apps remove --purge-volumes --ignore-missing "$NOSTART_APP" >/dev/null
  # `--no-start` is the flag form; volumes need `--spec`, and `start = false` in the file is the same field.
  cat >"$WORK/nostart-spec.toml" <<EOF
image = "$IMAGE"
port = 80
start = false
volumes = [{ name = "data", target = "/data" }]

[health]
attempts = 2
window_secs = ${HEALTH_WINDOW:-4}
EOF
  wg apps add "$NOSTART_APP" --spec "$WORK/nostart-spec.toml" >/dev/null
  [ "$(show_field "$NOSTART_APP" .runtime)" = not_started ] \
    || die "po provisioningu runtime to $(show_field "$NOSTART_APP" .runtime), oczekiwano not_started"
  ! podman container exists "$NOSTART_APP" || die "start = false utworzył kontener $NOSTART_APP"
  [ "$(wg --json volumes list "$NOSTART_APP" | jq -r '.volumes[0].exists')" = true ] \
    || die "wolumen nie istnieje po provisioningu (bez kontenera)"
  start=$(show_field "$NOSTART_APP" '.state.uid_range.start // empty')
  case $start in '' | *[!0-9]*) die "brak zakresu UID w stanie ($start)" ;; esac

  mkdir -p "$WORK/nostart-src"
  printf 'v1\n' >"$WORK/nostart-src/f"
  tar -cf "$WORK/nostart-in.tar" -C "$WORK/nostart-src" --owner=1000 --group=1000 --numeric-owner f
  wg volumes import "$NOSTART_APP" data --from "$WORK/nostart-in.tar" >/dev/null \
    || die "volumes import przed pierwszym startem nie przeszedł"
  [ "$(show_field "$NOSTART_APP" .runtime)" = not_started ] \
    || die "import uruchomił apkę z start = false (runtime=$(show_field "$NOSTART_APP" .runtime))"

  wg apps start "$NOSTART_APP" >/dev/null || die "apps start nie przeszedł"
  wait_for "apka $NOSTART_APP działa" "$DEPLOY_WAIT" app_running "$NOSTART_APP" \
    || die "$NOSTART_APP nie wstał po apps start w ${DEPLOY_WAIT}s"
  [ "$(show_field "$NOSTART_APP" '.state.uid_range.start')" = "$start" ] \
    || die "zakres UID zmienił się przy apps start ($start)"

  wg volumes export "$NOSTART_APP" data --out "$WORK/nostart-out.tar" 2>/dev/null \
    || die "volumes export nie przeszedł"
  # `tar -xOf` prints the file from the archive; no ownership changes (the archive carries the uid range).
  out=$(tar -xOf "$WORK/nostart-out.tar" ./f 2>/dev/null || tar -xOf "$WORK/nostart-out.tar" f 2>/dev/null || true)
  [ "$out" = v1 ] || die "w eksporcie brak zawartości pliku f (mam: ${out:-brak})"

  wg apps remove --purge-volumes "$NOSTART_APP" >/dev/null
  ! podman volume exists "$NOSTART_APP.data" || die "--purge-volumes zostawił wolumen"
  ! podman container exists "$NOSTART_APP" || die "--purge-volumes zostawił kontener"
  note "provisioning bez kontenera, import przed startem, apps start, dane w eksporcie, purge czyści"
}

step_cleanup() {
  local app out
  for app in "$WEBHOOK_APP" "$ROLLBACK_APP"; do
    wg apps remove --ignore-missing "$app" >/dev/null
  done
  podman rm -f "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
  # --purge-secrets (issue #80): the canary's webhook-hmac and any probe secret go with the app.
  wg apps remove --purge-secrets "$CANARY" >/dev/null || die "apps remove --purge-secrets $CANARY nie powiodło się"
  wg --json apps list | jq -e --arg n "$CANARY" '[.apps[].name] | index($n) | not' >/dev/null \
    || die "kanarek nadal na liście apek"
  # No orphaned canary secrets may remain: doctor warns about every secret scope whose instance is
  # gone, so the check must not mention $CANARY. `doctor` exits 1 on warnings and that is fine here.
  out=$(wg --json doctor) || true
  printf '%s' "$out" | jq -e '.checks' >/dev/null 2>&1 \
    || die "doctor po sprzątaniu nie zwrócił raportu: $out"
  printf '%s' "$out" | jq -e --arg n "$CANARY" \
    '[.checks[] | select(.id == "state.orphan_secrets" and (((.message // "") + " " + (.hint // "")) | contains($n)))] | length == 0' >/dev/null \
    || die "doctor nadal zgłasza osierocone sekrety kanarka ($CANARY) po --purge-secrets"
  if [ "$EDGE" = 1 ]; then
    # The canary's TLS server disappears with the app; then the test artifacts (certificate, ACME token) go.
    wait_for "zniknięcie serwera TLS" 30 \
      bash -c "! podman exec weglarka-nginx cat /etc/nginx/nginx.conf | grep -qF 'tls/$CANARY_DOMAIN.crt'" \
      || die "domena kanarka nadal ma serwer TLS w nginx.conf"
    remove_edge_canary_artifacts
    note "kanarek usunięty z sekretami (bez osieroconych wpisów), serwer TLS zniknął, certyfikat i token ACME usunięte"
  elif [ -n "$TRAEFIK_FILE" ] && [ -r "$TRAEFIK_FILE" ]; then
    wait_for "zniknięcie routera" 30 router_gone || die "domena kanarka nadal w $TRAEFIK_FILE"
    note "kanarek usunięty z sekretami (bez osieroconych wpisów), router zniknął z pliku Traefika"
  else
    note "kanarek usunięty z sekretami (plik Traefika niedostępny — routera nie sprawdzono)"
  fi
}

# ── Przebieg ─────────────────────────────────────────────────────────────────

human "Odbiór Węglarki: kanarek $CANARY_DOMAIN, obraz $IMAGE"
START=$(date +%s)

if [ "$SKIP_PREFLIGHT" = 1 ]; then
  printf '%s\tSKIP\t0\t%s\n' "doctor --preflight" "--skip-preflight" >>"$WORK/results.tsv"
  human "SKIP  doctor --preflight (--skip-preflight)"
else
  run_step preflight "doctor --preflight" step_preflight
fi
run_step doctor "doctor (przez API demona)" step_doctor
# Without a running daemon the following steps make no sense.
run_step canary "kanarek: apps add, deploy, bramka zdrowia, digest" step_canary doctor
if [ "$EDGE" = 1 ]; then
  run_step traffic "ruch: https://$CANARY_DOMAIN:$EDGE_HTTPS_PORT → 200, TLS, nagłówki" step_traffic canary
elif [ -z "$DIRECT" ]; then
  run_step traffic "ruch: https://$CANARY_DOMAIN → 200, cert, nagłówki" step_traffic canary
else
  run_step traffic "ruch: nginx bezpośrednio → 200, nagłówki" step_traffic canary
fi
run_step streaming "ingress: streaming = reload nginx bez odtworzenia kontenera" step_streaming canary traffic
run_step http_redirect "http → 301 na https (bez -L)" step_http_redirect canary traffic
# The ACME webroot exists only in edge mode, so behind keeps its step list unchanged.
if [ "$EDGE" = 1 ]; then
  run_step acme "ACME HTTP-01: token z webroota → 200 bez redirectu" step_acme canary
fi
run_step webhook_protocol "webhook: 202 / 401 / 204" step_webhook_protocol canary
run_step secrets "sekrety: set → list → remove → list" step_secrets webhook_protocol
if [ "$LOCAL_REGISTRY" = 1 ]; then
  run_step registry "lokalny rejestr testowy" step_registry doctor
  run_step webhook_deploy "webhook: deploy, duplikat dostarczenia" step_webhook_deploy registry
else
  skip_step "webhook: deploy, duplikat dostarczenia" "wymaga --with-local-registry"
fi
if [ "$SKIP_ROLLBACK" = 1 ]; then
  skip_step "rollback wymuszony (kod 6)" "--skip-rollback"
elif [ "$LOCAL_REGISTRY" != 1 ]; then
  skip_step "rollback wymuszony (kod 6)" "wymaga --with-local-registry (pełny test rollbacku jest w CI)"
else
  run_step rollback "rollback wymuszony (kod 6)" step_rollback registry canary
fi
if [ "$WITH_VOLUME" = 1 ]; then
  run_step volume "wolumen: import, dane i zakres UID, eksport, purge" step_volume doctor
  run_step volume_no_start "wolumen przy start = false: provisioning, import przed startem, apps start, eksport, purge" step_volume_no_start doctor
else
  skip_step "wolumen: import, dane i zakres UID, eksport, purge" "wymaga --with-volume"
  skip_step "wolumen przy start = false: provisioning, import przed startem, apps start, eksport, purge" "wymaga --with-volume"
fi
if [ "$KEEP" = 1 ]; then
  cleanup_helpers
  printf '%s\tSKIP\t0\t%s\n' "sprzątanie" "--keep: kanarek zostaje (usuń: weglarka apps remove $CANARY)" >>"$WORK/results.tsv"
  human "SKIP  sprzątanie (--keep: kanarek $CANARY zostaje)"
else
  run_step cleanup "sprzątanie: apps remove, router zniknął" step_cleanup doctor
fi

# ── Podsumowanie ─────────────────────────────────────────────────────────────

total=$(($(date +%s) - START))
count() { awk -F'\t' -v s="$1" '$2 == s' "$WORK/results.tsv" | wc -l | tr -d ' '; }
fails=$(count FAIL)
human ""
human "Podsumowanie: $(count PASS) PASS, $fails FAIL, $(count SKIP) SKIP (${total}s)"

if [ "$JSON" = 1 ]; then
  jq -R -s --argjson total "$total" --arg domain "$CANARY_DOMAIN" --arg image "$IMAGE" '
    [split("\n")[] | select(length > 0) | split("\t") |
      {step: .[0], status: .[1], seconds: (.[2] | tonumber), detail: .[3]}] as $steps
    | {canary_domain: $domain, canary_image: $image, total_seconds: $total,
       ok: ([$steps[] | select(.status == "FAIL")] | length == 0), steps: $steps}' \
    <"$WORK/results.tsv"
fi

[ "$fails" -eq 0 ] || exit 1
