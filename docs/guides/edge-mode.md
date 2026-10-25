# Edge mode: nginx on 80/443 with TLS

In `edge` mode Węglarka no longer sits behind Traefik: its nginx **terminates TLS itself** and publishes two ports
on the host — `bind` (HTTP) and `https_bind` (TLS); inside the container it still listens on 8080/8443. Decision
and rejected alternatives: [ADR 0036](../decisions/0036-edge-mode.md). The `behind` mode does not change.

```toml
[ingress]
mode = "edge"
bind = "0.0.0.0:80"          # HTTP: only a 301 to https (except ACME) and a default server answering 444
https_bind = "0.0.0.0:443"   # TLS: one server per domain, certificate from <state>/nginx/tls
# traefik_dynamic_file and trusted_proxies are forbidden in edge — validation stops the daemon
```

- **Redirect:** every routed domain (apps and webhook) answers `301 https://$host$request_uri` on the HTTP port;
  the exception is the `/.well-known/acme-challenge/` prefix, served from the webroot. An unknown `Host` closes
  the connection (`444`).
- **TLS only with a certificate:** a TLS server is created **only** for a domain that has a pair of files
  (`<domain>.crt` and `<domain>.key`) or is covered by a wildcard pair `_wildcard.<apex>.crt|key`
  ([wildcard certificates](wildcard-certificates.md); an own pair wins). A domain without a pair still redirects
  to HTTPS but has no TLS server — the handshake is rejected (`ssl_reject_handshake`), so **nothing goes to the
  app in plaintext**. Certificates are issued by `[acme]` ([ACME certificates](acme.md)) or you put them there
  yourself (a self-signed one is enough in tests).

## Certificates and the ACME webroot

| path | mode | role |
|---|---|---|
| `<nginx_conf_dir>/tls/<domain>.crt` | `0644` | PEM chain, leaf first; read by the nginx master |
| `<nginx_conf_dir>/tls/<domain>.key` | `0600` | PEM key; read **only** by the nginx master |
| `<nginx_conf_dir>/tls/` (directory) | `0700` | created by the daemon on the first `apply` |
| `<nginx_conf_dir>/acme/<token>` | `0644` | HTTP-01 token, served as `/.well-known/acme-challenge/<token>` |
| `<nginx_conf_dir>/acme/` (directory) | `0755` | created by the daemon; files are read by the nginx worker |

`<nginx_conf_dir>` is `[ingress] nginx_conf_dir` or `<state dir>/nginx`. The ACME webroot accepts only
`GET`/`HEAD`; the token is **public**, so `0644` is not a leak — private keys never end up in the webroot. The
private key is read by the nginx master, which since [ADR 0036](../decisions/0036-edge-mode.md) runs as the runtime
user (a two-line uid map of the ingress container); that is why the files can stay `0600` and are **not**
readable by host users.

A test certificate (for the first deployment or for `scripts/acceptance.sh`):

```sh
install -d -m 0700 /var/lib/weglarka/nginx/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes -days 2 \
  -keyout /var/lib/weglarka/nginx/tls/ntfy.example.com.key \
  -out    /var/lib/weglarka/nginx/tls/ntfy.example.com.crt \
  -subj "/CN=ntfy.example.com" -addext "subjectAltName=DNS:ntfy.example.com"
chmod 0600 /var/lib/weglarka/nginx/tls/ntfy.example.com.key
```

Adding or renewing a certificate **needs no restart or recreation of nginx**: the daemon scans the `tls/`
directory on every pass, and its fingerprint (names, sizes, mtime) goes into `nginx.conf`, so the change takes the
usual `nginx -t` + SIGHUP path (and a rejected config is put back on disk with a message in `doctor`).
Verification:

```sh
podman exec weglarka-nginx grep -F 'ssl_certificate /etc/nginx/tls/' /etc/nginx/nginx.conf
head -2 /var/lib/weglarka/nginx/nginx.conf        # "# tls material: fingerprint …" changes after a renewal
curl -k --resolve ntfy.example.com:443:127.0.0.1 https://ntfy.example.com/   # -k only for self-signed
```

## Requirements and security

- Ports < 1024 need a sysctl and `[runtime] allow_privileged_host_ports = true`; `doctor --preflight` has the
  `ingress.privileged_ports` check for this, and `ingress.tls` warns about domains without a certificate pair.
  High ports (e.g. 18080/18443) need nothing — this is how CI and the local acceptance test run `edge`.
- **No trust in headers:** nginx terminates TLS, so it builds `X-Forwarded-For/Proto/Host` from
  `$remote_addr`/`$scheme`/`$host`; spoofed client values are overwritten ([ADR 0007](../decisions/0007-zaufane-proxy-i-reload-nginx.md)).
  `trusted_proxies` in `edge` is a validation error.
- **Ingress container:** the hardening profile ([ADR 0014](../decisions/0014-ingress-nginx-hardening.md), see
  [container hardening](container-hardening.md)) does not change (the same three capabilities, read-only root);
  the uid map does — the container root is the runtime user, the worker stays in the ingress range
  ([ADR 0036](../decisions/0036-edge-mode.md), [ADR 0009](../decisions/0009-volume-ownership.md)). Consequence:
  **nothing but `<nginx_conf_dir>` may be mounted into the nginx container** (no state directory, no
  `config_root`, no Traefik file).
- A custom `ingress.nginx_image` must have nginx >= 1.25.1 (`http2 on`, `ssl_reject_handshake`); the official
  `nginx:1-alpine` and the digest from [host configuration](../install.md#host-configuration) satisfy this, an
  older image fails `nginx -t`.
- **Acceptance test:** `scripts/acceptance.sh` detects the mode on its own and checks the redirect, TLS traffic,
  headers and ACME (see [acceptance test](../install.md#acceptance-test)). After installation: `weglarka doctor`
  (checks `ingress.apply`, `ingress.tls`, `ingress.nginx`).

## Rollback

Switching to `behind` is a return to the configuration from before ADR 0036: set `mode = "behind"`, remove
`https_bind`, restore `traefik_dynamic_file`, restart the daemon. The nginx container is recreated once (a
different `weglarka.ingress-hash`). `apps.toml`/`state.toml` did not change (no schema version bump), and you can
leave the files in `tls/`/`acme/` — `behind` does not read them. Before a downgrade to a release older than
ADR 0036, remove `https_bind` from `weglarka.toml` (an older daemon does not know that key).
