#!/usr/bin/env bash
# Streaming responses through the generated nginx.conf (issue #64, docs/decisions/0018), with plain Docker
# on a CI runner: an app with `ingress.streaming = true` forwards a chunk as soon as the upstream writes
# it and an idle stream survives nginx's 60 s default `proxy_read_timeout`; an app without the option
# (the negative control) keeps buffering, so nginx itself delays the very same chunk.
#
#   test-streaming.sh <nginx-conf>
#
# The config comes from `cargo run -p weglarka-ingress --example dump -- nginx 127.0.0.11 172.16.0.0/12`:
# the sample has the app `sse` (streaming) and `blog` (buffered defaults), both on the upstream port
# 3000. One upstream container answers on both hostnames, so the only difference between the two
# requests is the generated `location`. The idle-stream test deliberately takes ~70 s.
set -euo pipefail

conf=$1
net=wg-stream-test
work=$(mktemp -d)
fail=0

# shellcheck disable=SC2329,SC2317 # invoked by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::nginx logs"; docker logs wg-stream-nginx 2>&1 | tail -80 || true; echo "::endgroup::"
    echo "::group::upstream logs"; docker logs wg-stream-sse 2>&1 | tail -20 || true; echo "::endgroup::"
  fi
  docker rm -f wg-stream-sse wg-stream-nginx >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
docker rm -f wg-stream-sse wg-stream-nginx >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true

# The upstream is kept in a file and mounted read-only instead of being inlined in `python3 -c`:
# `/plain` writes the first line immediately and the second one 2 s later (the buffering probe);
# `/sse` idles for 66 s, past nginx's 60 s default read timeout (the timeout probe).
cat >"$work/upstream.py" <<'PY'
"""Streaming upstream for the streaming test (issue #64): the timing of the bytes is the assertion.

`/plain` closes the body by closing the connection (no `Content-Length`, no chunked framing) — the shape
nginx buffers: with `proxy_buffering on` the first line is held until the response ends, with
`proxy_buffering off` it is forwarded at once. A chunked body would be forwarded chunk by chunk regardless
of buffering, so it cannot show the difference. `/sse` is a chunked SSE stream that idles for 66 s — past
nginx's 60 s default read timeout — before the last event.
"""

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IDLE_SECS = 66


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def headers_only(self, content_type, chunked):
        self.send_response_only(200)
        self.send_header("Content-Type", content_type)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Connection", "close")
        self.end_headers()

    def chunk(self, payload):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(payload), payload))
        self.wfile.flush()

    def plain(self, code, body):
        self.send_response_only(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Request headers (`Connection: close` from nginx, keep-alive, ...) are irrelevant; GET has no body.
        if self.path == "/healthz":
            self.plain(200, b"ok")
        elif self.path == "/plain":
            self.headers_only("text/plain", chunked=False)
            self.wfile.write(b"first\n")
            self.wfile.flush()
            time.sleep(2)
            self.wfile.write(b"second\n")
            self.wfile.flush()
            self.close_connection = True
        elif self.path == "/sse":
            self.headers_only("text/event-stream", chunked=True)
            self.chunk(b"data: start\n\n")
            time.sleep(IDLE_SECS)
            self.chunk(b"data: end\n\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        else:
            self.plain(404, b"not found")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
PY

docker network create "$net" >/dev/null
# One upstream, two names: `sse` and `blog` are the hostnames of the streaming and the buffered app.
# The whole temp directory is mounted (not the single file): a file created moments earlier can race
# with a virtiofs/Docker Desktop share, which then mounts an empty directory instead of the script.
docker run -d --name wg-stream-sse --network "$net" --network-alias sse --network-alias blog \
  -v "$work:/srv:ro" docker.io/library/python:3-alpine \
  python3 -u /srv/upstream.py >/dev/null
docker run -d --name wg-stream-nginx --network "$net" -p 127.0.0.1:18098:8080 \
  -v /run/weglarka-probe -v "$conf:/etc/nginx/nginx.conf:ro" docker.io/library/nginx:1-alpine >/dev/null

# Readiness through nginx, so the upstream DNS aliases are already resolving when the assertions run.
ready=0
for _ in $(seq 30); do
  if curl -fsS -o /dev/null -H 'Host: sse.example.eu' http://127.0.0.1:18098/healthz 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL readiness: nginx on 127.0.0.1:18098 did not answer through the upstream within 30 s"
  exit 1
fi
echo "ok   readiness: nginx forwards /healthz to the upstream"

# Test A (buffering, fast): the first line must reach the client immediately through the streaming app,
# while nginx holds the very same bytes for the buffered app until the whole response ends.
: >"$work/sse-plain.out"
curl -sN --max-time 10 -H 'Host: sse.example.eu' http://127.0.0.1:18098/plain -o "$work/sse-plain.out" &
pid=$!
sleep 1
if grep -qF 'first' "$work/sse-plain.out" 2>/dev/null; then
  echo "ok   streaming /plain: first line reached the client within 1 s (proxy_buffering off)"
else
  echo "FAIL streaming /plain: no data within 1 s — is 'proxy_buffering off;' missing in the sse location?"
  fail=1
fi
if wait "$pid"; then :; else echo "FAIL streaming /plain: curl failed"; fail=1; fi
if grep -qF 'first' "$work/sse-plain.out" && grep -qF 'second' "$work/sse-plain.out"; then
  echo "ok   streaming /plain: whole body arrived"
else
  echo "FAIL streaming /plain: incomplete body ($(tr '\n' ' ' <"$work/sse-plain.out"))"
  fail=1
fi

# Negative control: the same upstream and the same timing, only the location differs (`blog` has no
# `ingress.streaming`). nginx must delay the first line itself.
: >"$work/blog-plain.out"
curl -sN --max-time 10 -H 'Host: blog.example.eu' http://127.0.0.1:18098/plain -o "$work/blog-plain.out" &
pid=$!
sleep 1
if grep -qF 'first' "$work/blog-plain.out" 2>/dev/null; then
  echo "FAIL buffered /plain (blog): nginx forwarded the first line within 1 s (proxy_buffering should be on)"
  fail=1
else
  echo "ok   buffered /plain (blog): nginx held the first line the upstream wrote immediately"
fi
if wait "$pid"; then :; else echo "FAIL buffered /plain (blog): curl failed"; fail=1; fi
if grep -qF 'first' "$work/blog-plain.out" && grep -qF 'second' "$work/blog-plain.out"; then
  echo "ok   buffered /plain (blog): whole body arrived at the end"
else
  echo "FAIL buffered /plain (blog): incomplete body ($(tr '\n' ' ' <"$work/blog-plain.out"))"
  fail=1
fi

# Test B (idle stream, ~70 s — deliberately slow: it is the acceptance criterion from the issue).
# nginx's default `proxy_read_timeout` is 60 s and would cut the 66 s gap; `streaming` raises it to
# 180 s (the sample default), so `data: end` arrives.
start=$(date +%s)
rc=0
curl -sN --max-time 80 -H 'Host: sse.example.eu' http://127.0.0.1:18098/sse -o "$work/sse.out" || rc=$?
elapsed=$(( $(date +%s) - start ))
if [ "$rc" -ne 0 ]; then
  echo "FAIL idle stream: request failed after ${elapsed}s (curl exit $rc) — with the default 60 s read"
  echo "     timeout nginx cuts an idle stream and 'data: end' never arrives (nginx logs follow)"
  fail=1
elif ! grep -qF 'data: end' "$work/sse.out"; then
  echo "FAIL idle stream: no 'data: end' after ${elapsed}s (nginx cut the idle stream)"
  fail=1
elif [ "$elapsed" -lt 62 ]; then
  echo "FAIL idle stream: completed after ${elapsed}s, expected ~66 s (did the upstream really idle?)"
  fail=1
else
  echo "ok   idle stream: end received after ${elapsed}s (default read timeout is 60s)"
fi

exit "$fail"
