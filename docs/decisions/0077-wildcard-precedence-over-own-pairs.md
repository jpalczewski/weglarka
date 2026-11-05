# 0077 — Opt-in wildcard precedence over a domain's own certificate pair

Status: proposed (2026-11-05, issue #210)

## Problem

In `edge` mode a routed domain is served with its own pair (`tls/<domain>.crt|key`) when one exists, and only
otherwise with the wildcard of the longest covering apex (ADR 0039, rollout step 4). The ACME worker keeps renewing
an own pair over HTTP-01, because nginx prefers it and an expired one must not be served.

That is right for a pair the operator placed deliberately, but it leaves no path off per-domain certificates after
a migration. A host moved from another proxy carries its old per-domain pairs into `tls/`, and pairs issued over
HTTP-01 before `[acme.dns]` was configured stay there too. With a working wildcard those domains still depend on
per-host HTTP-01 renewals (behind a CDN that means the zone-rule or `acme.cdn` path) until someone deletes the
files by hand, and nothing tells the operator that this is happening.

Constraints, in priority order (CLAUDE.md): security → elegant, extensible code → RAM economy. Whatever we choose
must keep `edge` fail closed (no TLS server without a usable pair) and must not change existing hosts unasked.

## Decision

**A new opt-in setting `[acme.dns] prefer_wildcard` (default `false`) flips the precedence for covered domains,
and `doctor` reports own pairs that shadow a valid wildcard. The daemon never deletes or moves a pair.**

```toml
[acme.dns]
provider = "cloudflare"
token_file = "/etc/weglarka/cloudflare.token"
wildcards = ["example.com"]
prefer_wildcard = true
```

1. **One selection rule in one place.** The rule is written once in `weglarka-model`
   (`config::choose_certificate`) and used by the nginx generator (`NginxOptions::certificate_stem`), the ACME
   worker (`Worker::specs`) and the certificate reader behind `GET /v1/certificates` and `doctor`
   (`certificates::collect_with`), so they cannot disagree:
   `prefer_wildcard` and a covering valid wildcard → the wildcard; else an own pair → the own pair; else a covering
   valid wildcard → the wildcard; else no TLS server.
2. **With `prefer_wildcard = true`** a covered domain is served with the wildcard even when it has its own pair,
   and the worker stops renewing that pair. The pair stays on disk, unrenewed, as a fallback. The ingress counts a
   wildcard as covering in this mode only while its chain is unexpired (it reads the `.crt`, never the key). A failed
   or expired wildcard therefore falls back: the worker orders the domain's own certificate over HTTP-01 again,
   the write changes the TLS fingerprint, and the next apply serves the own pair.
3. **With the default** nothing changes in what is served or renewed (the `edge` snapshots stay byte for byte).
   `doctor` adds an `Info` check, `acme.shadowed`, listing each domain whose own pair shadows a valid covering
   wildcard, with the two ways out (set `prefer_wildcard`, or delete `tls/<domain>.crt|key`).
4. **No API change.** A domain served by a wildcard is already reported as `covered` by `GET /v1/certificates`;
   with the preference that also applies to a domain that has a stale own pair. The shadowing list is internal to
   `doctor`. The config read view exposes `prefer_wildcard`.

Invariants: the default does not change output or renewals; a domain without a usable pair still gets no TLS
server; the daemon never removes or rewrites operator-supplied files in `tls/`.

## Consequences

- Operators migrating a host set `prefer_wildcard = true` once; the old pairs stop mattering without a manual
  cleanup and can be deleted at leisure.
- `weglarka.toml` gains a field in a `deny_unknown_fields` section: an older daemon refuses to start until the line
  is removed. `apps.toml` and `state.toml` are untouched, so `state::SCHEMA_VERSION` does not change. The
  [wildcard guide](../guides/wildcard-certificates.md) documents the setting, the fallback and the downgrade step.
- Rollout: the shared helper and the generator option (no configuration yet), the `acme.shadowed` check, then the
  setting with the worker, the ingress scan and the guide.
- Tests: the helper's precedence table, an `edge` snapshot with the preference, worker tests (own pair not renewed
  with the preference, per-domain issuance again after a failed wildcard), `collect_with` and `doctor` rows.

## Rejected alternatives

- **Retire covered own pairs automatically** (move them to `tls/retired/`). The daemon cannot tell a pair carried
  over by accident from one the operator placed on purpose (a certificate from another CA, an EV certificate), and
  moving files in `tls/` behind the operator's back is a destructive, surprising action that a downgrade cannot undo.
- **Only stop renewing covered own pairs.** nginx would keep preferring the own pair until it expires and then serve
  an expired certificate; the precedence has to change together with renewals.
- **Make the wildcard win by default.** It silently changes what existing hosts serve on upgrade, including hosts
  whose own pairs are deliberate.
