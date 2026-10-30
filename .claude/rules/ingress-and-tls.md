---
paths:
  - "crates/weglarka-ingress/**"
  - "crates/weglarka-acme/**"
  - "crates/weglarka-dns/**"
  - "crates/weglarka-daemon/src/{ingress,health_probe,acme,cdn,forwarder}.rs"
  - ".github/scripts/test-*.sh"
  - "docs/guides/{edge-mode,edge-cdn,acme,acme-behind-cdn,wildcard-certificates,path-routing,forward-auth,max-body-size,streaming,static-sites,access-log,host-ports}.md"
---

# Ingress, edge mode, TLS and ACME

## Invariants

- **Ingress:** every change to the generators passes snapshots, `nginx -t`, the `X-Forwarded-*` header test
  (`.github/scripts/test-forwarded-headers.sh`) and `scripts/acceptance.sh`. Remember both entrypoints (http and https).
- **`edge` mode (ADR 0036, #95):** Węglarka's nginx terminates TLS and publishes two ports — `bind` (HTTP: only a 301 to
  HTTPS + `/.well-known/acme-challenge/`) and `https_bind`; inside the container it is still 8080/8443, so the hardening
  profile (0014) does not change, and `health_probe` goes through the socket `<nginx_conf_dir>/probe/probe.sock`
  (ADR 0054). Certificates: `<nginx_conf_dir>/tls/<domain>.crt|key` (0600/0700), the ACME webroot
  `<nginx_conf_dir>/acme` (0644/0755); a TLS server is created **only** for a domain with a file pair (without a pair:
  redirect and a rejected handshake — fail closed). The daemon scans `tls/` on every `apply`, and the fingerprint of
  the material in `nginx.conf` causes a reload (`nginx -t` + SIGHUP) — **never** a recreate of the container; this is
  the path the ACME worker uses (`[acme]`, ADR 0038, `docs/guides/acme.md`). In edge **nobody is trusted** about
  `X-Forwarded-*` (0007), and the ingress uid map is two-line (uid 0 = runtime user, 1.. = ingress range) so that the
  master can read 0600 keys — therefore **only `<nginx_conf_dir>` may be mounted into nginx** (its subdirectories `run/`
  and `probe/` additionally, writable). Ports are published by the `weglarka-forwarder` container (daemon image, pasta,
  PROXY protocol over the socket `<nginx_conf_dir>/run`, `0700`; ADR 0043, #162), not by nginx — otherwise rootlessport
  loses the client address; `weglarka.ingress-hash` = v5 in both modes (mount of `probe/`, ADR 0054). Ports < 1024 need
  a sysctl and `[runtime] allow_privileged_host_ports`.

- **Admin relay carve-out (ADR 0060):** `Plan::build` sets `AppRoute::admin_relay` for an `[admin.http] clients` app served
  at `/`, and the nginx generator renders `RELAY_PREFIX` (`weglarka_model::admin_auth`) as unguarded, long-lived locations
  with the upload body limit. Derived from the host config, never from the spec (no `spec_hash`, no `apps.toml` field).

## Entry points

| Area | Files |
|---|---|
| ingress | `crates/weglarka-ingress/src/plan.rs` (`Plan::build` validates, including disjoint `paths` on a shared domain; `route_table()` for `doctor`) → `nginx.rs`/`traefik.rs` (render + snapshots); reload: `crates/weglarka-daemon/src/ingress.rs`; path prefixes: ADR 0031, `paths`/`ingress.strip_prefix` in `crates/weglarka-model/src/app.rs`, syntax `check_path_prefix`, `docs/guides/path-routing.md`; `edge` mode (two published ports, TLS, ACME webroot, ingress uid map): ADR 0036, `docs/guides/edge-mode.md` |
| ACME certificates (edge) | `crates/weglarka-acme/src/{manager,store,solver,instant,renewal}.rs` (engine, `FakeAcme` in `testing.rs`), `crates/weglarka-model/src/config.rs` (`AcmeConfig`, validation in `HostConfig::validate`), `crates/weglarka-model/src/events.rs` (`CertificateIssued`/`CertificateRenewalFailed`), `crates/weglarka-daemon/src/acme.rs` (worker, `AcmeStatus`) + wiring in `crates/weglarka-daemon/src/lib.rs`, checks `acme.*` in `crates/weglarka-daemon/src/doctor.rs`, `docs/guides/acme.md` (ADR 0038); wildcard via DNS-01: `[acme.dns]` (`AcmeDnsConfig`, `token_file` 0600 like ntfy), `DnsBackend` + a second `Manager` in `crates/weglarka-daemon/src/acme.rs`, `DnsSolver` in `crates/weglarka-acme/src/dns.rs`, adapters in `weglarka-dns`, checks `acme.dns`/`acme.wildcards`, `docs/guides/wildcard-certificates.md` (ADR 0039); serving wildcards: `crates/weglarka-model/src/config.rs` (`wildcard_covers`, `wildcard_cert_stem`), `crates/weglarka-ingress/src/nginx.rs` (`NginxOptions::certificate_stem`: an own pair wins, then the wildcard of the longest apex), scan of `_wildcard.<apex>` in `crates/weglarka-daemon/src/ingress.rs`, HTTP-01 skipped for covered domains in `AcmeWorker::specs` |
| health probe (`health.http`, probe socket) | `crates/weglarka-daemon/src/health_probe.rs` (`NginxProber` over `UnixStream`), `crates/weglarka-daemon/src/ingress.rs` (`PROBE_SUBDIR`, `probe_socket_path`, mount only into nginx, hash v5), `crates/weglarka-ingress/src/nginx/common.rs` (`listen_probe`), `NginxOptions::probe_socket`, ADR 0054 |
