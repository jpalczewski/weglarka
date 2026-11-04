#!/usr/bin/env bash
# Static sites through the generated nginx.conf (ADR 0049), with plain Docker on a CI runner:
#
#   * `landing` (landing.example.eu) is served from <sites>/landing/current;
#   * `docs` (blog.example.eu/docs) is served from <sites>/docs/current next to the `blog` container app on the
#     same domain, with the prefix stripped;
#   * only GET and HEAD are allowed, a missing file is 404, `..` never leaves the site;
#   * repointing `current` (what a deploy does with one rename) changes what is served without an nginx reload.
#
#   test-static.sh <nginx-conf>
#
# The config comes from `cargo run -p weglarka-ingress --example dump -- nginx 127.0.0.11 172.16.0.0/12`.
# There is no upstream: the `blog` catch-all is only expected NOT to answer with a site's content.
set -euo pipefail

conf=$1
work=$(mktemp -d "${TMPDIR:-/tmp}/wg-static.XXXXXX")
fail=0
port=18098

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-static-nginx 2>&1 | tail -80 || true; echo "::endgroup::"
  fi
  docker rm -f wg-static-nginx >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-static-nginx >/dev/null 2>&1 || true

# The layout the daemon maintains: sites/<site>/releases/<id>/ and a relative symlink `current`.
site() { # site <name> <release> <index body>
  mkdir -p "$work/sites/$1/releases/$2/about"
  printf '%s' "$3" >"$work/sites/$1/releases/$2/index.html"
  printf '%s' "$1-$2-about" >"$work/sites/$1/releases/$2/about/index.html"
  printf '%s' "$1-$2-guide" >"$work/sites/$1/releases/$2/guide.html"
}
site landing r1 landing-r1
site landing r2 landing-r2
site docs r1 docs-r1
printf 'body{}' >"$work/sites/landing/releases/r1/style.css"
printf 'console.log(1)' >"$work/sites/landing/releases/r1/app.js"
ln -s releases/r1 "$work/sites/landing/current"
ln -s releases/r1 "$work/sites/docs/current"
echo secret >"$work/sites/secret.txt"

# `help` (#104, ADR 0069): every per-site option at once — a redirect, a custom 404 page, a feed and
# security headers (dump.rs's `APPS`). `style.css`/`app.js` are here too, so the security headers are
# exercised on the same request as issue #498's MIME table (a CSP/nosniff header must not change what
# content type a stylesheet or script comes back as).
site help r1 help-r1
printf 'body{}' >"$work/sites/help/releases/r1/style.css"
printf 'console.log(1)' >"$work/sites/help/releases/r1/app.js"
printf 'help-r1-not-found' >"$work/sites/help/releases/r1/404.html"
printf '<rss version="2.0"><channel><title>help</title></channel></rss>' >"$work/sites/help/releases/r1/feed.xml"
ln -s releases/r1 "$work/sites/help/current"
# mktemp -d is 0700; a container runtime that maps the mount through another user (Colima/virtiofs) needs more.
chmod -R a+rX "$work"

docker run -d --name wg-static-nginx -p "127.0.0.1:$port:8080" \
  --read-only --tmpfs /tmp:rw,size=16m -v /run/weglarka-probe \
  -v "$conf:/etc/nginx/nginx.conf:ro" -v "$work/sites:/etc/nginx/sites:ro" \
  docker.io/library/nginx:1-alpine >/dev/null

ready=0
for _ in $(seq 30); do
  if curl -fsS -o /dev/null -H 'Host: landing.example.eu' "http://127.0.0.1:$port/" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL: nginx did not start serving landing.example.eu"
  exit 1
fi

# request <method> <host> <path>: prints "<status> <body>".
request() {
  if [ "$1" = HEAD ]; then
    # `-X HEAD` would make curl wait for a body that never comes.
    curl -sS --path-as-is -I -H "Host: $2" -o /dev/null -w '%{http_code} ' "http://127.0.0.1:$port$3" || true
    return
  fi
  curl -sS --path-as-is -X "$1" -H "Host: $2" -o "$work/body" -w '%{http_code}' "http://127.0.0.1:$port$3" || true
  printf ' %s' "$(cat "$work/body" 2>/dev/null)"
}
expect() { # expect <description> <want> <method> <host> <path>
  local got
  got=$(request "$3" "$4" "$5")
  # A want without a space is a status code only (nginx's own error pages are not asserted).
  case "$2" in *" "*) ;; *) got=${got%% *} ;; esac
  if [ "$got" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: want '$2', got '$got'"
    fail=1
  fi
}

expect "landing / serves index.html" "200 landing-r1" GET landing.example.eu /
expect "landing /about/ serves the directory index" "200 landing-r1-about" GET landing.example.eu /about/
expect "landing /guide.html serves the file" "200 landing-r1-guide" GET landing.example.eu /guide.html
expect "landing /missing is 404" "404" GET landing.example.eu /missing.html
expect "landing HEAD is allowed" "200" HEAD landing.example.eu /
expect "landing POST is refused" "403" POST landing.example.eu /
expect "landing DELETE is refused" "403" DELETE landing.example.eu /
expect "docs /docs/ serves the site root" "200 docs-r1" GET blog.example.eu /docs/
expect "docs /docs/about/ serves a subdirectory" "200 docs-r1-about" GET blog.example.eu /docs/about/
expect "docs /docs/guide.html strips the prefix" "200 docs-r1-guide" GET blog.example.eu /docs/guide.html
expect "docs /docs (exact) serves the site root" "200 docs-r1" GET blog.example.eu /docs

# issue #498: the generated config carries its own MIME table (no `include mime.types`), so a stylesheet or
# script must not come back as `text/plain` — a browser then refuses to apply or execute it.
expect_content_type() { # expect_content_type <description> <want> <host> <path>
  local got
  got=$(curl -sS --path-as-is -I -H "Host: $3" "http://127.0.0.1:$port$4" \
    | tr -d '\r' | grep -i '^content-type:' | cut -d' ' -f2)
  if [ "$got" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: want '$2', got '$got'"
    fail=1
  fi
}
expect_content_type "landing /style.css has a css content type" "text/css" landing.example.eu /style.css
expect_content_type "landing /app.js has a javascript content type" "application/javascript" landing.example.eu /app.js

# expect_feed_content_type: a feed's `charset utf-8;` (#104) appends `; charset=utf-8` to the header,
# so this checks the media type alone — a separate helper from `expect_content_type` above, which stays
# a full-header match so it keeps catching a stray charset on a plain static file (issue #498).
expect_feed_content_type() { # expect_feed_content_type <description> <want> <host> <path>
  local got
  got=$(curl -sS --path-as-is -I -H "Host: $3" "http://127.0.0.1:$port$4" \
    | tr -d '\r' | grep -i '^content-type:' | cut -d' ' -f2 | cut -d';' -f1)
  if [ "$got" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: want '$2', got '$got'"
    fail=1
  fi
}

# expect_header <description> <host> <path> <header-name> <want-value>: case-insensitive header match.
expect_header() {
  local got
  got=$(curl -sS --path-as-is -I -H "Host: $2" "http://127.0.0.1:$port$3" \
    | tr -d '\r' | grep -i "^$4:" | cut -d' ' -f2-)
  if [ "$got" = "$5" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: want '$5', got '$got'"
    fail=1
  fi
}

# #104, ADR 0069: `help` has every per-site option set at once (dump.rs's `APPS`).
expect "help / serves index.html" "200 help-r1" GET help.example.eu /
expect "help custom 404 page serves its own content" "404 help-r1-not-found" GET help.example.eu /missing.html
expect_feed_content_type "help /feed.xml has an rss content type" "application/rss+xml" help.example.eu /feed.xml
# `absolute_redirect off` (first exercised by `redirects`): the Location of a redirect behind this
# proxy must be relative, never built from nginx's own internal scheme/host/port.
expect_header "help /old redirects with a relative Location" help.example.eu /old location /new
got=$(request GET help.example.eu /old)
case "$got" in
  301*) echo "ok   help /old answers 301" ;;
  *) echo "FAIL help /old did not answer 301: '$got'"; fail=1 ;;
esac
# Security headers must not break the MIME table of issue #498: `style.css`/`app.js` keep their real
# content type, and `nosniff`/CSP are present alongside it.
expect_content_type "help /style.css keeps a css content type with security headers on" "text/css" help.example.eu /style.css
expect_content_type "help /app.js keeps a javascript content type with security headers on" "application/javascript" help.example.eu /app.js
expect_header "help sets X-Content-Type-Options" help.example.eu /style.css x-content-type-options nosniff
expect_header "help sets Content-Security-Policy" help.example.eu /style.css content-security-policy "default-src 'self'"

# `..` must never leave the release (curl does not normalise with --path-as-is; nginx does).
got=$(request GET landing.example.eu /../secret.txt)
case "$got" in
  *secret*) echo "FAIL traversal reached secret.txt: '$got'"; fail=1 ;;
  *) echo "ok   traversal does not reach files outside the site ($got)" ;;
esac

# The blog catch-all has no upstream here: whatever it answers, it must not be a site's content.
got=$(request GET blog.example.eu /)
case "$got" in
  *docs-r1* | *landing-r1*) echo "FAIL blog / served static content: '$got'"; fail=1 ;;
  *) echo "ok   blog / is not served from a site ($got)" ;;
esac

# A deploy: build the new link next to the old one and rename it over `current` (one rename(2)).
ln -s releases/r2 "$work/sites/landing/current.tmp"
python3 -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' \
  "$work/sites/landing/current.tmp" "$work/sites/landing/current"
expect "landing serves the new release without a reload" "200 landing-r2" GET landing.example.eu /
expect "docs is untouched by another site's deploy" "200 docs-r1" GET blog.example.eu /docs/

exit "$fail"
