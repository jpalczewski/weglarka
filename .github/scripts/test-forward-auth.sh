#!/usr/bin/env bash
# Forward auth through the generated nginx.conf (#89, docs/decisions/0052), with plain Docker on a CI runner.
# A stub stands in for the identity provider (`authelia:9091`): the client's cookie decides its answer, so
# every outcome of the `auth_request` contract is exercised against real nginx.
#
#   test-forward-auth.sh <nginx-conf>
#
# The config comes from `cargo run -p weglarka-ingress --example dump -- nginx-forward 127.0.0.11 172.16.0.0/12`:
# `panel.example.eu` is protected with `/mcp/` exempt, `open.example.eu` has no auth, both are whoami
# upstreams on port 3000; the issuer is https://auth.example.eu. The published port's peer is the Docker
# bridge, which the config trusts, so `X-Forwarded-Proto: https` is honoured like behind Traefik.
set -euo pipefail

conf=$1
net=wg-auth-test
work=$(mktemp -d)
chmod 755 "$work" # the stub may run as another user than the runner
fail=0

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-auth-nginx 2>&1 | tail -60 || true; echo "::endgroup::"
    echo "::group::stub logs"; docker logs wg-auth-idp 2>&1 | tail -40 || true; echo "::endgroup::"
  fi
  docker rm -f wg-auth-idp wg-auth-app wg-auth-nginx >/dev/null 2>&1 || true
  docker volume rm wg-auth-probe >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-auth-idp wg-auth-app wg-auth-nginx >/dev/null 2>&1 || true
docker volume rm wg-auth-probe >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true

# The provider stub. Authelia's `/api/authz/auth-request` answers 200 + Remote-* for a session, 401 with a
# `Location` for none; the `nolocation` cookie is the header-strategy 401 that carries no `Location`.
cat >"$work/idp.py" <<'PY'
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        print("AUTHZ path=%s original-url=%s original-method=%s xff=%s cookie=%s" % (
            self.path, self.headers.get("X-Original-URL"), self.headers.get("X-Original-Method"),
            self.headers.get("X-Forwarded-For"), cookie), flush=True)
        if cookie == "session=alice":
            self.send_response(200)
            self.send_header("Remote-User", "alice")
            self.send_header("Remote-Groups", "admins,dev")
            self.send_header("Remote-Name", "Alice A")
            self.send_header("Remote-Email", "alice@example.org")
        elif cookie == "session=denied":
            self.send_response(403)
        elif cookie == "session=nolocation":
            self.send_response(401)
        else:
            self.send_response(401)
            self.send_header("Location", "https://auth.example.eu/?rd=" + (self.headers.get("X-Original-URL") or ""))
        self.send_header("Content-Length", "0")
        self.end_headers()

    log_message = lambda *a: None

http.server.ThreadingHTTPServer(("0.0.0.0", 9091), Handler).serve_forever()
PY

docker network create "$net" >/dev/null
docker run -d --name wg-auth-app --network "$net" --network-alias panel --network-alias open \
  docker.io/traefik/whoami:v1.10.4 --port 3000 >/dev/null
docker run -d --name wg-auth-idp --network "$net" --network-alias authelia -v "$work:/srv:ro" \
  docker.io/library/python:3-alpine python3 -u /srv/idp.py >/dev/null
docker volume create wg-auth-probe >/dev/null
docker run -d --name wg-auth-nginx --network "$net" -p 127.0.0.1:18097:8080 \
  -v wg-auth-probe:/run/weglarka-probe -v "$conf:/etc/nginx/nginx.conf:ro" docker.io/library/nginx:1-alpine >/dev/null

# `GET http://127.0.0.1:18097<path>` as <host>; extra curl args follow. Prints "<code> <redirect url>" then the body.
call() { # host path extra curl args...
  local host=$1 path=$2; shift 2
  curl -sS -w '\n%{http_code} %{redirect_url}' -H "Host: $host" -H 'X-Forwarded-Proto: https' \
    -H 'X-Forwarded-For: 203.0.113.9' "$@" "http://127.0.0.1:18097$path" | tr -d '\r'
}
status_line() { tail -n1 <<<"$1"; }

for _ in $(seq 30); do
  curl -fsS -o /dev/null -H 'Host: open.example.eu' http://127.0.0.1:18097/ 2>/dev/null && break
  sleep 1
done

expect() { # label text pattern
  if grep -qiF -- "$3" <<<"$2"; then echo "ok   $1: $3"; else echo "FAIL $1: missing $3"; fail=1; fi
}
reject() {
  if grep -qiF -- "$3" <<<"$2"; then echo "FAIL $1: unexpected $3"; fail=1; else echo "ok   $1: no $3"; fi
}

forged=(-H 'Remote-User: admin' -H 'Remote-Groups: root' -H 'Remote-Name: Mallory' -H 'Remote-Email: root@example.org')

# No session: a 302 to the login the provider named; the upstream is never contacted.
out=$(call panel.example.eu '/a?x=1' "${forged[@]}")
expect 'no session' "$(status_line "$out")" '302 https://auth.example.eu/?rd=https://panel.example.eu/a?x=1'
reject 'no session' "$out" 'Hostname'

# The provider saw the scheme the client used (not nginx's own `http`), the method and the client address.
idp=$(docker logs wg-auth-idp 2>&1)
expect 'authz request' "$idp" 'path=/api/authz/auth-request'
expect 'authz request' "$idp" 'original-url=https://panel.example.eu/a?x=1'
expect 'authz request' "$idp" 'original-method=GET'
expect 'authz request' "$idp" 'xff=203.0.113.9'

# A 401 without `Location` falls back to the portal, never an empty redirect.
out=$(call panel.example.eu / -H 'Cookie: session=nolocation')
expect 'no Location' "$(status_line "$out")" '302 https://auth.example.eu/'

# ACL deny stays a 403; a session gets through with the provider's identity, never the forged one.
out=$(call panel.example.eu / -H 'Cookie: session=denied')
expect 'denied' "$(status_line "$out")" '403 '
out=$(call panel.example.eu /whoami -H 'Cookie: session=alice' "${forged[@]}")
expect 'session' "$(status_line "$out")" '200 '
expect 'session' "$out" 'Remote-User: alice'
expect 'session' "$out" 'Remote-Groups: admins,dev'
expect 'session' "$out" 'Remote-Name: Alice A'
expect 'session' "$out" 'Remote-Email: alice@example.org'
reject 'session' "$out" 'Remote-User: admin'
reject 'session' "$out" 'root'
reject 'session' "$out" 'Mallory'
# The rest of the header set survives the protected location (it re-emits all of it).
expect 'session' "$out" 'X-Forwarded-Proto: https'
expect 'session' "$out" 'X-Forwarded-For: 203.0.113.9'
expect 'session' "$out" 'X-Real-Ip: 203.0.113.9'
expect 'session' "$out" 'Host: panel.example.eu'

# Exempt paths: no `auth_request` (200 without a session), the exact path and everything below, and still
# no identity header a client could inject. The sibling `/mcpx` is not exempt.
for path in /mcp /mcp/ /mcp/tools/list; do
  out=$(call panel.example.eu "$path" "${forged[@]}")
  expect "exempt $path" "$(status_line "$out")" '200 '
  reject "exempt $path" "$out" 'Remote-'
  expect "exempt $path" "$out" 'X-Forwarded-Proto: https'
  expect "exempt $path" "$out" 'X-Forwarded-For: 203.0.113.9'
done
# An upstream may read `;` or `\` as path syntax (`/mcp/..;/admin`) while nginx matched the exempt prefix.
for path in '/mcp/..;/admin' '/mcp/%3b/x' '/mcp/%5cx' '/mcp/%252e%252e/admin'; do
  expect "exempt $path refused" "$(status_line "$(call panel.example.eu "$path")")" '400 '
done
out=$(call panel.example.eu /mcpx)
expect 'sibling of an exempt path' "$(status_line "$out")" '302 '

# An app without forward auth never asks and never passes an injected identity on.
out=$(call open.example.eu / "${forged[@]}")
expect 'open app' "$(status_line "$out")" '200 '
reject 'open app' "$out" 'Remote-'
reject 'open app' "$out" 'Mallory'

# The daemon's probe socket: anonymous, answered by the authz location itself, so a protected `/` is
# reachable by `health.http` without a session. Python dials the unix socket (nginx:alpine has no curl).
before=$(docker logs wg-auth-idp 2>&1 | grep -c '^AUTHZ' || true)
probe=$(docker run --rm -v wg-auth-probe:/run/weglarka-probe docker.io/library/python:3-alpine python3 -c '
import http.client, socket
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect("/run/weglarka-probe/probe.sock")
c = C("probe"); c.request("GET", "/", headers={"Host": "panel.example.eu", **{"Remote-User": "admin"}})
r = c.getresponse(); print(r.status); print(r.read().decode())
' | tr -d '\r')
expect 'probe socket' "$probe" "200"
expect 'probe socket' "$probe" 'Hostname'
reject 'probe socket' "$probe" 'Remote-'
after=$(docker logs wg-auth-idp 2>&1 | grep -c '^AUTHZ' || true)
if [ "$before" = "$after" ]; then echo "ok   probe socket: the provider was not asked"; else echo "FAIL probe socket: provider asked"; fail=1; fi

# Fail closed: no provider, no access (500), while exempt paths and unprotected apps keep working.
docker rm -f wg-auth-idp >/dev/null
out=$(call panel.example.eu / -H 'Cookie: session=alice')
expect 'provider down' "$(status_line "$out")" '500 '
reject 'provider down' "$out" 'Hostname'
expect 'provider down, exempt' "$(status_line "$(call panel.example.eu /mcp/x)")" '200 '
expect 'provider down, open app' "$(status_line "$(call open.example.eu /)")" '200 '

echo "--- nginx access log (last run)"
docker logs wg-auth-nginx 2>&1 | tail -3
exit "$fail"
