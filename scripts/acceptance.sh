#!/usr/bin/env bash
# Skrypt odbioru Węglarki na prawdziwym hoście (docs/install.md, „Odbiór na hoście”).
#
# Uruchamiany jako użytkownik runtime'u (`weglarka`) z ustawionym XDG_RUNTIME_DIR; zależności:
# weglarka, curl, openssl, jq, podman. Dotyka wyłącznie instancji `wg-canary`, `wg-webhook`
# i `wg-rollback` oraz kontenera `wg-accept-registry` (lokalny rejestr testowy) — nigdy innych apek.
#
#   scripts/acceptance.sh --canary-domain wg-test.descriptortable.eu
#
# Kody wyjścia: 0 wszystko PASS, 1 przynajmniej jeden FAIL, 64 błędne wywołanie / brak zależności.
set -euo pipefail

# traefik/whoami v1.10.4 (index wieloarchitekturowy) — przypięty po digeście.
DEFAULT_CANARY_IMAGE='docker.io/traefik/whoami:v1.10.4@sha256:1699d99cb4b9acc17f74ca670b3d8d0b7ba27c948b3445f0593b58ebece92f04'
# docker.io/library/registry:2 — pomocniczy rejestr, w którym tagi da się przestawiać (webhook, rollback).
REGISTRY_IMAGE='docker.io/library/registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'

CANARY=wg-canary
WEBHOOK_APP=wg-webhook
ROLLBACK_APP=wg-rollback
REGISTRY_CONTAINER=wg-accept-registry

CONFIG=/etc/weglarka/weglarka.toml
CANARY_DOMAIN=
IMAGE=$DEFAULT_CANARY_IMAGE
WEBHOOK_BASE=
DIRECT=
KEEP=0
SKIP_ROLLBACK=0
SKIP_PREFLIGHT=0
STRICT=0
JSON=0
REGISTRY_PORT=15099
CERT_TIMEOUT=180
DEPLOY_WAIT=120
DUP_WAIT=25

usage() {
  cat <<'EOF'
Użycie: acceptance.sh --canary-domain DOMENA [opcje]

  --config PLIK          weglarka.toml (domyślnie /etc/weglarka/weglarka.toml)
  --canary-domain DOM    domena kanarka: w DNS i na allowliście walidatora (weglarka_allowed_domains)
  --canary-image REF     obraz kanarka (domyślnie traefik/whoami przypięty po digeście)
  --webhook-base URL     baza URL webhooków (domyślnie https://<webhook.domain> z configu)
  --direct URL           zamiast https://<domena>/ pytaj nginx Węglarki bezpośrednio (Host: <domena>),
                         bez Traefika i TLS — do testów lokalnych/CI, np. http://127.0.0.1:8088
  --keep                 nie usuwaj kanarka na końcu (instancje pomocnicze i tak znikają)
  --skip-rollback        pomiń test wymuszonego rollbacku
  --skip-preflight       pomiń `doctor --preflight` (np. gdy host to nie docelowy układ)
  --strict               ostrzeżenia `doctor` traktuj jak błąd
  --registry-port PORT   port lokalnego rejestru testowego na 127.0.0.1 (domyślnie 15099)
  --cert-timeout SEK     ile czekać na certyfikat Traefika (domyślnie 180)
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
    --keep) KEEP=1; shift ;;
    --skip-rollback) SKIP_ROLLBACK=1; shift ;;
    --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
    --strict) STRICT=1; shift ;;
    --registry-port) REGISTRY_PORT=${2:?--registry-port wymaga wartości}; shift 2 ;;
    --cert-timeout) CERT_TIMEOUT=${2:?--cert-timeout wymaga wartości}; shift 2 ;;
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

# Minimalny odczyt prostych wpisów `klucz = "wartość"` z weglarka.toml (bez pełnego parsera TOML).
toml_get() {
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$CONFIG" | head -n1
}

if [ -z "$WEBHOOK_BASE" ]; then
  webhook_domain=$(toml_get domain)
  [ -n "$webhook_domain" ] || die_usage "brak [webhook] domain w $CONFIG — podaj --webhook-base"
  WEBHOOK_BASE=https://$webhook_domain
fi
WEBHOOK_BASE=${WEBHOOK_BASE%/}
DIRECT=${DIRECT%/}
TRAEFIK_FILE=$(toml_get traefik_dynamic_file)

REG=127.0.0.1:$REGISTRY_PORT
WORK=$(mktemp -d)
: >"$WORK/results.tsv"
REGISTRIES_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/containers"
REGISTRIES_DROPIN="$REGISTRIES_DIR/registries.conf.d/zz-weglarka-acceptance.conf"
REGISTRIES_CONF="$REGISTRIES_DIR/registries.conf"

# Repo i tag kanarka (do payloadu webhooka): `repo:tag[@digest]` → `repo:tag`.
canary_ref=${IMAGE%%@*}
case ${canary_ref##*/} in
  *:*) ;;
  *) canary_ref=$canary_ref:latest ;;
esac
canary_repo=${canary_ref%:*}

wg() { weglarka --config "$CONFIG" "$@"; }

# ── Szkielet kroków ──────────────────────────────────────────────────────────

# Kroki biegną w podpowłoce (die = exit z kroku); stan między krokami przez pliki w $WORK.
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
  # `set -e` nie działa w kontekście `if`/`||`, więc krok biegnie w podpowłoce z własnym `set -e`.
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

# ── Sprzątanie (też przy przerwaniu) ─────────────────────────────────────────

cleanup_helpers() {
  local app
  for app in "$WEBHOOK_APP" "$ROLLBACK_APP"; do
    wg apps remove --ignore-missing "$app" >/dev/null 2>&1 || true
  done
  podman rm -f "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
  podman rmi -f "$REG/wg-accept/wh:t" "$REG/wg-accept/rb:t" >/dev/null 2>&1 || true
  rm -f "$REGISTRIES_DROPIN"
  # Plik zakładamy tylko wtedy, gdy go nie było (patrz step_registry); wtedy znamy jego treść.
  if [ -f "$WORK/registries_conf_created" ]; then rm -f "$REGISTRIES_CONF"; fi
}

on_exit() {
  local rc=$?
  trap - EXIT INT TERM
  cleanup_helpers
  if [ "$KEEP" != 1 ]; then
    wg apps remove --ignore-missing "$CANARY" >/dev/null 2>&1 || true
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

# Czeka (do $2 s), aż polecenie zwróci 0.
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

# Jedno żądanie do kanarka → kod HTTP ("000" przy błędzie transportu); ciało w $WORK/body.
canary_request() {
  local rc=0 code url=https://$CANARY_DOMAIN/
  local -a extra=()
  if [ -n "$DIRECT" ]; then
    url=$DIRECT/
    extra=(-H "Host: $CANARY_DOMAIN")
  fi
  code=$(curl -sS --max-time 10 -o "$WORK/body" -w '%{http_code}' ${extra[@]+"${extra[@]}"} "$url" 2>"$WORK/curl_err") || rc=$?
  put curl_rc "$rc"
  printf '%s' "$code"
}

# Predykaty dla wait_for (wołane pośrednio).
# shellcheck disable=SC2329
digest_changed_from() { [ "$(show_field "$WEBHOOK_APP" '.state.current // empty')" != "$1" ]; }
# shellcheck disable=SC2329
router_gone() { ! grep -qF "$CANARY_DOMAIN" "$TRAEFIK_FILE"; }

# Kanarek odpowiada 200 i widać nagłówek z nginxa/Traefika (X-Forwarded-Host = domena).
canary_ok() {
  [ "$(canary_request)" = 200 ] && grep -qi "^X-Forwarded-Host: $CANARY_DOMAIN\$" "$WORK/body" 2>/dev/null
}

hmac_hex() { # sekret plik → hex. Sekret jest jednorazowy i testowy (argv widoczny lokalnie przez chwilę).
  openssl dgst -sha256 -mac HMAC -macopt "key:$1" -r "$2" | cut -d' ' -f1
}

# Payload `registry_package` w formacie, który akceptuje adapter (docs/decisions/0004).
payload_file() { # plik repo:tag action
  local repo=${2%:*} tag=${2##*:} name
  name=${repo#*/}
  jq -nc --arg action "$3" --arg url "$2" --arg tag "$tag" --arg name "${name##*/}" --arg ns "$(dirname "$name")" \
    '{action:$action, registry_package:{name:$name, namespace:$ns, package_type:"CONTAINER",
      package_version:{package_url:$url, container_metadata:{tag:{name:$tag}}}}}' >"$1"
}

# send_webhook <instancja> <sekret> <event> <delivery> <plik-payloadu> → kod HTTP
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

# Krótka bramka zdrowia, żeby kroki nie czekały domyślnych 30 s.
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
  wg apps remove --ignore-missing "$CANARY" >/dev/null
  wg apps add "$CANARY" "$IMAGE" --domain "$CANARY_DOMAIN" --port 80 >/dev/null
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
  if [ -n "$TRAEFIK_FILE" ] && [ -r "$TRAEFIK_FILE" ]; then
    wait_for "router w pliku Traefika" 30 grep -qF "$CANARY_DOMAIN" "$TRAEFIK_FILE" \
      || die "domena kanarka nie pojawiła się w $TRAEFIK_FILE"
  else
    log "plik Traefika niedostępny — pomijam sprawdzenie routera"
  fi
  note "$outcome, $digest"
}

step_traffic() {
  local i=0 code
  while :; do
    code=$(canary_request)
    [ "$code" != 200 ] || break
    i=$((i + 5))
    if [ "$i" -gt "$CERT_TIMEOUT" ]; then
      die "brak 200 po ${CERT_TIMEOUT}s (ostatni: http=$code, curl=$(get curl_rc): $(tr '\n' ' ' <"$WORK/curl_err")) — DNS, allowlista walidatora, certyfikat Traefika (curl 60 = cert jeszcze niewystawiony)?"
    fi
    sleep 5
  done
  log "200 po ~${i}s"
  grep -qi "^X-Forwarded-Host: $CANARY_DOMAIN\$" "$WORK/body" \
    || { sed 's/^/  | /' "$WORK/body"; die "brak X-Forwarded-Host: $CANARY_DOMAIN w odpowiedzi whoami (nginx/Traefik nie przekazały nagłówka)"; }
  grep -qi '^X-Forwarded-For:' "$WORK/body" || die "brak X-Forwarded-For w odpowiedzi whoami"
  if [ -z "$DIRECT" ]; then
    grep -qi '^X-Forwarded-Proto: https' "$WORK/body" || die "brak X-Forwarded-Proto: https (nginx nie ufa Traefikowi?)"
    note "https://$CANARY_DOMAIN/ → 200, cert ważny, nagłówki forwardowane"
  else
    note "$DIRECT (Host: $CANARY_DOMAIN) → 200, nagłówki forwardowane; TLS nie sprawdzany"
  fi
}

step_registry() {
  podman rm -f "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
  podman run -d --name "$REGISTRY_CONTAINER" -p "127.0.0.1:$REGISTRY_PORT:5000" "$REGISTRY_IMAGE" >/dev/null
  # Demon ciągnie obrazy przez usługę Podmana tego usera — rejestr po http musi być jawnie „insecure”.
  # containers/image czyta `registries.conf.d` użytkownika tylko wtedy, gdy istnieje jego `registries.conf`.
  mkdir -p "$(dirname "$REGISTRIES_DROPIN")"
  if [ ! -e "$REGISTRIES_CONF" ]; then
    : >"$REGISTRIES_CONF"
    : >"$WORK/registries_conf_created"
  fi
  cat >"$REGISTRIES_DROPIN" <<EOF
[[registry]]
location = "$REG"
insecure = true
EOF
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

# Webhook, który naprawdę wdraża: apka śledzi tag w lokalnym rejestrze; przestawiamy tag i pukamy.
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
  wg --json deploy "$WEBHOOK_APP" >/dev/null || die "pierwszy deploy $WEBHOOK_APP nie przeszedł"
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

  # 2) ten sam X-GitHub-Delivery przy nowym obrazie → duplikat, bez deployu
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

# Wymuszony rollback: ten sam tag w lokalnym rejestrze zaczyna wskazywać obraz z healthcheckiem,
# który zawsze zawodzi; kontener działa, ale bramka zdrowia go odrzuca → wraca poprzedni digest.
step_rollback() {
  local spec ref good out rc=0 now
  ref=$REG/wg-accept/rb:t
  spec=$WORK/rb-spec.toml
  push_variant rb 1
  write_spec "$spec" "$ref"
  wg apps remove --ignore-missing "$ROLLBACK_APP" >/dev/null
  wg apps add "$ROLLBACK_APP" --spec "$spec" >/dev/null
  wg --json deploy "$ROLLBACK_APP" >/dev/null || die "deploy dobrej wersji nie przeszedł"
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

step_cleanup() {
  local app
  for app in "$WEBHOOK_APP" "$ROLLBACK_APP"; do
    wg apps remove --ignore-missing "$app" >/dev/null
  done
  podman rm -f "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
  rm -f "$REGISTRIES_DROPIN"
  if [ -f "$WORK/registries_conf_created" ]; then rm -f "$REGISTRIES_CONF"; fi
  wg apps remove "$CANARY" >/dev/null || die "apps remove $CANARY nie powiodło się"
  wg --json apps list | jq -e --arg n "$CANARY" '[.apps[].name] | index($n) | not' >/dev/null \
    || die "kanarek nadal na liście apek"
  if [ -n "$TRAEFIK_FILE" ] && [ -r "$TRAEFIK_FILE" ]; then
    wait_for "zniknięcie routera" 30 router_gone || die "domena kanarka nadal w $TRAEFIK_FILE"
    note "kanarek i pomocnicze usunięte, router zniknął z pliku Traefika"
  else
    note "kanarek i pomocnicze usunięte (plik Traefika niedostępny — routera nie sprawdzono)"
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
# Bez działającego demona dalsze kroki nie mają sensu.
run_step canary "kanarek: apps add, deploy, bramka zdrowia, digest" step_canary doctor
if [ -z "$DIRECT" ]; then
  run_step traffic "ruch: https://$CANARY_DOMAIN → 200, cert, nagłówki" step_traffic canary
else
  run_step traffic "ruch: nginx bezpośrednio → 200, nagłówki" step_traffic canary
fi
run_step registry "lokalny rejestr testowy" step_registry doctor
run_step webhook_protocol "webhook: 202 / 401 / 204" step_webhook_protocol canary
run_step webhook_deploy "webhook: deploy, duplikat dostarczenia" step_webhook_deploy registry
if [ "$SKIP_ROLLBACK" = 1 ]; then
  printf '%s\tSKIP\t0\t%s\n' "rollback wymuszony" "--skip-rollback" >>"$WORK/results.tsv"
  human "SKIP  rollback wymuszony (--skip-rollback)"
else
  run_step rollback "rollback wymuszony (kod 6)" step_rollback registry canary
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
