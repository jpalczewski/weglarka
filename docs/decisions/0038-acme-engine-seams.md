# 0038 — ACME engine: crate layout and seams

Status: accepted (2026-10-25, issue #96)

## Problem

Edge mode (ADR 0036) serves a webroot for `/.well-known/acme-challenge/` and builds a TLS server for every
domain with `tls/<id>.crt|key`, but nothing issues or renews those files. #96 adds HTTP-01 issuance and
renewal; #97 adds DNS-01 (wildcard certificates). The first design decides whether #97 is an addition or a
rewrite, and a private key that leaks into a log or a mismatched cert/key pair that reaches nginx are the
failure modes that matter most.

## Decision

**A new crate `weglarka-acme` (depends on `weglarka-core` only) holds the engine; the daemon wires it.**
The crate is split into seams, each small enough to test on its own:

- **`CertSpec` / `CertId`: a certificate is a list of names.** The file stem on disk comes from the id
  (`[a-z0-9._-]`, no leading dot), never from a name, so a wildcard cannot put `*` or a path separator in a
  file name. A single-domain certificate uses the domain as its id (the layout the ingress already scans);
  #97 uses `_wildcard.<apex>`.
- **`ChallengeSolver`: `present` / `cleanup` per challenge.** `Http01Solver` writes `<webroot>/<token>`
  (`0644`); the token comes from the CA and is validated as base64url before it becomes a file name.
  Cleanup is idempotent and also runs when the order fails. DNS-01 is another implementation (#97).
- **`AcmeClient` (order one certificate, driving a solver) and `CertInspector` (read `notAfter`)** are
  traits with native `async fn` (ADR 0001). `InstantAcme` implements both over `instant-acme` with
  `default-features = false` and the `ring` provider (the default `aws-lc-rs` needs a C toolchain). Its HTTP
  client is built by us (hyper + `hyper-rustls`, `ring`, bundled `webpki-roots`, HTTP/1.1; the crate's
  platform verifier would find no CA store in the `scratch` image, ADR 0021). The account credentials
  (they contain the account private key) live in a `0600` JSON file that is refused when group/other
  accessible; the account is created on first use only when the terms are explicitly accepted.
  `testing::FakeAcme` implements both traits for tests.
- **`CertStore` writes the key first, then the certificate**, atomically (`state::write_atomic`: key `0600`,
  chain `0644`, `tls/` `0700`). The ingress fingerprint needs both files; this order means it never sees a
  new certificate without its key, and a crash in between leaves a pair `nginx -t` rejects, so the ingress
  keeps the last good config and the next pass repairs it.
- **`renewal::decide` is a pure function** (renew when 30 days or less are left; expired is reported
  separately), and `Manager::pass` is one reconcile pass without a clock, loop or events. Scheduling,
  backoff, `Event`s and `IngressManager::request_apply` stay with the daemon.
- **`PrivateKeyPem` has a redacted `Debug`, no `Display` and no `Clone`.** Errors and logs carry names and
  paths only.

State that outlives a pass goes into its own tolerant file (like `self-update.toml`), not into `state.toml`,
so it needs no `SCHEMA_VERSION` bump.

## Consequences

`[acme]` (`accept_terms`, `email`, `directory_url`, `enabled`, `renew_before_days`, `check_interval_secs`) is a
new `weglarka.toml` section: it requires `edge` ingress (unless `enabled = false`), and it breaks rollback to
an older daemon because of `deny_unknown_fields` ([the ACME guide](../guides/acme.md)). It does not touch `apps.toml`,
`state.toml`, `spec_hash` or `SCHEMA_VERSION`.

The daemon runs one worker (`weglarka-daemon/src/acme.rs`): the first pass 30 s after start (nginx must be
listening), then every `check_interval_secs`, or after 30 minutes when the last pass had failures (the CA
allows 5 failed validations per hostname per hour). One single-name certificate per routed domain; a name that
cannot be a public DNS name is skipped with a warning. After a pass that wrote files it calls
`IngressManager::request_apply`, so nginx reloads through the existing fingerprint path. It emits
`CertificateIssued` and `CertificateRenewalFailed`; the latter is critical when fewer than 7 days are left or
there is no certificate at all. `doctor` gets `acme.config`, `acme.account` and `acme.certs`.

`testing::FakeAcme` plus `Manager` and worker tests cover issue, renew, skip, failure and cleanup without a
CA. An opt-in staging test (`WEGLARKA_ACME_STAGING_DOMAIN` / `_WEBROOT`) needs a public port 80 and is not part
of default CI.

## Rejected alternatives

- **A module in `weglarka-daemon`.** Keeps one crate fewer, but the daemon is the widest crate and #97 would
  have to edit it in parallel; a separate crate gives the DNS work a stable seam to depend on.
- **Naming files after the domain.** Simplest for #96, but forces a rename (or a `*` in a file name) for
  wildcard certificates.
- **A solver that knows the ACME client's types.** Would make the DNS-01 adapter depend on `instant-acme`;
  `Challenge` is a plain struct for that reason.
