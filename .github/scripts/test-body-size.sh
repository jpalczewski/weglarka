#!/usr/bin/env bash
# Per-app request body limit through the generated nginx.conf (ADR 0033), with plain Docker on a CI runner:
#
#   * `blog` keeps nginx's server-level default (64 MiB) -> 413 for a 70 MiB body (negative control);
#   * `upload` (`max_body_size = "256m"`, streaming) accepts 100 MiB and refuses 300 MiB;
#   * `capped` (`max_body_size = "8m"`, NOT streaming) shows the limit also holds below the default and
#     that a limit alone turns request buffering off;
#   * a slow upload that runs longer than nginx's 60 s defaults still completes, arrives at the upstream
#     while the client is still sending (nothing is spooled in nginx) and leaves /tmp/client_body empty —
#     the ingress container's root is read-only and /tmp is a small tmpfs, i.e. RAM.
#
#   test-body-size.sh <nginx-conf>
#
# The config comes from `cargo run -p weglarka-ingress --example dump -- nginx 127.0.0.11 172.16.0.0/12`.
# One upstream container answers on all three hostnames; the only difference between requests is the
# generated `location`. The slow-upload test deliberately takes ~80 s.
set -euo pipefail

conf=$1
net=wg-body-test
work=$(mktemp -d "${TMPDIR:-/tmp}/wg-body.XXXXXX")
fail=0
MIB=1048576

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-body-nginx 2>&1 | tail -80 || true; echo "::endgroup::"
    echo "::group::upstream logs"; docker logs wg-body-up 2>&1 | tail -20 || true; echo "::endgroup::"
  fi
  docker rm -f wg-body-up wg-body-nginx >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-body-up wg-body-nginx >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true

# The upstream reads and discards the request body (Content-Length or chunked — nginx sends either,
# depending on whether it buffered) and reports how many bytes it got and how long the body took to
# arrive. The latter is the proof that nginx streams: a buffered body reaches the upstream in one burst.
cat >"$work/upstream.py" <<'PY'
"""Body sink for the body-size test (ADR 0033): the byte count and the arrival time are the assertions."""

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_body(self):
        total = 0
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    return total
                remaining = size
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        return total
                    remaining -= len(chunk)
                    total += len(chunk)
                self.rfile.readline()
        remaining = int(self.headers.get("Content-Length", "0"))
        while remaining:
            chunk = self.rfile.read(min(remaining, 1 << 20))
            if not chunk:
                break
            remaining -= len(chunk)
            total += len(chunk)
        return total

    def do_GET(self):
        self.reply(200, "ok")

    def do_POST(self):
        started = time.monotonic()
        total = self.read_body()
        self.reply(200, f"bytes={total} secs={time.monotonic() - started:.1f}")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
PY

# mktemp -d is 0700; a container runtime that maps the mount through another user (Colima/virtiofs) needs more.
chmod 755 "$work"
docker network create "$net" >/dev/null
docker run -d --name wg-body-up --network "$net" \
  --network-alias blog --network-alias upload --network-alias capped \
  -v "$work:/srv:ro" docker.io/library/python:3-alpine python3 -u /srv/upstream.py >/dev/null
# Same hardening as the real ingress container: read-only root, a small writable /tmp.
docker run -d --name wg-body-nginx --network "$net" -p 127.0.0.1:18097:8080 \
  --read-only --tmpfs /tmp:rw,size=16m -v /run/weglarka-probe -v "$conf:/etc/nginx/nginx.conf:ro" \
  docker.io/library/nginx:1-alpine >/dev/null

ready=0
for _ in $(seq 30); do
  if curl -fsS -o /dev/null -H 'Host: blog.example.eu' http://127.0.0.1:18097/ 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL readiness: nginx on 127.0.0.1:18097 did not answer through the upstream within 30 s"
  exit 1
fi
echo "ok   readiness: nginx forwards to the upstream"

# Sparse-free zero files; the upstream only counts bytes.
mkfile() { head -c "$(($2 * MIB))" /dev/zero >"$work/$1"; }
mkfile b7 7
mkfile b9 9
mkfile b70 70
mkfile b100 100
mkfile b300 300

post() { # host file [extra curl args...] -> "<http code> <response body>"
  local host=$1 file=$2
  shift 2
  curl -sS -o "$work/resp" -w '%{http_code}' -H "Host: $host" --data-binary "@$work/$file" \
    -H 'Content-Type: application/octet-stream' "$@" http://127.0.0.1:18097/ 2>/dev/null || true
  printf ' %s' "$(cat "$work/resp" 2>/dev/null || true)"
}

expect() { # label host file expected-code [expected-bytes]
  local out code
  out=$(post "$2" "$3")
  code=${out%% *}
  if [ "$code" != "$4" ]; then
    echo "FAIL $1: got '$out', expected HTTP $4"
    fail=1
  elif [ -n "${5:-}" ] && ! grep -qF "bytes=$5 " <<<"$out "; then
    echo "FAIL $1: HTTP $code but the upstream did not receive $5 bytes ('$out')"
    fail=1
  else
    echo "ok   $1: HTTP $code"
  fi
}

expect "default limit (blog): 70 MiB is refused" blog.example.eu b70 413
expect "upload (256m): 100 MiB passes the default 64 MiB" upload.example.eu b100 200 $((100 * MIB))
expect "upload (256m): 300 MiB is refused" upload.example.eu b300 413
expect "capped (8m): 9 MiB is refused" capped.example.eu b9 413
expect "capped (8m): 7 MiB passes" capped.example.eu b7 200 $((7 * MIB))

# Slow upload, ~76 s: longer than nginx's 60 s defaults (client_body_timeout, proxy_send_timeout), so it
# only works if those are idle timeouts and the body keeps flowing. While it runs, nginx must not spool
# the body to its tmpfs, and the upstream must see the body arrive over (nearly) the whole duration.
mkfile slow 96
( curl -sS -o "$work/slow.out" -w '%{http_code}' -H 'Host: upload.example.eu' --limit-rate 1300k \
    --max-time 150 --data-binary "@$work/slow" -H 'Content-Type: application/octet-stream' \
    http://127.0.0.1:18097/ >"$work/slow.code" 2>"$work/slow.err" || true ) &
pid=$!
sleep 30
spooled=$(docker exec wg-body-nginx sh -c 'find /tmp/client_body -type f 2>/dev/null | wc -l' | tr -d ' ')
if [ "$spooled" = "0" ]; then
  echo "ok   slow upload: nothing spooled in /tmp/client_body after 30 s (proxy_request_buffering off)"
else
  echo "FAIL slow upload: $spooled file(s) in /tmp/client_body — nginx is buffering the request body"
  fail=1
fi
wait "$pid"
code=$(cat "$work/slow.code")
out=$(cat "$work/slow.out" 2>/dev/null || true)
secs=$(sed -n 's/.*secs=\([0-9.]*\).*/\1/p' <<<"$out")
if [ "$code" != "200" ]; then
  echo "FAIL slow upload: HTTP '$code' ($(cat "$work/slow.err")) — nginx cut a long but steady upload"
  fail=1
elif ! grep -qF "bytes=$((96 * MIB)) " <<<"$out "; then
  echo "FAIL slow upload: wrong byte count ('$out')"
  fail=1
elif [ "${secs%.*}" -lt 60 ]; then
  echo "FAIL slow upload: the upstream saw the body in ${secs}s — nginx buffered it first"
  fail=1
else
  echo "ok   slow upload: 96 MiB in ~${secs}s survived the 60 s defaults and streamed to the upstream"
fi

exit "$fail"
