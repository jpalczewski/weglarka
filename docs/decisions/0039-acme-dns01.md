# 0039 — ACME DNS-01 through a DNS-provider adapter (wildcard certificates)

Status: proposed (2026-10-25, issue #97). The adapter crate and the `DnsSolver` are implemented; the
configuration, wildcard handling in the manager and the ingress mapping follow (see “Rollout”).

## Problem

HTTP-01 (#96) proves control of one host name at a time and needs port 80 reachable. Two things it cannot do:

* **wildcard certificates** (`*.example.eu`): only DNS-01 can issue them. A wildcard keeps individual
  subdomains out of the Certificate Transparency logs, and it is what PR preview instances (#105) need —
  a new host name per pull request must not wait for an issuance;
* **hosts without a reachable port 80** (the ACME server cannot reach the webroot).

DNS-01 means writing a TXT record `_acme-challenge.<name>` at the domain's DNS host. Węglarka does not run
DNS, so the record is written through the provider's API with a credential that can change the zone — the
most sensitive secret the daemon would hold. Constraints, in the project's order: security (that token),
then an extensible shape (more providers later), then RAM (no big HTTP stack).

## Decision

**One trait, one crate, no ACME dependency.** `weglarka-dns` depends on `weglarka-core` only and exposes

```rust
trait DnsProvider: Send + Sync {
    async fn set_txt(&self, name: &str, value: &str) -> Result<RecordHandle, DnsError>;
    async fn remove_txt(&self, handle: &RecordHandle) -> Result<(), DnsError>;
}
```

(native `async fn`, generics instead of `dyn`, ADR 0001). The provider is picked by configuration and used
through a generic parameter, so the trait stays dyn-free. The ACME solver (`weglarka-acme`, #96) drives it;
DNS-01 is a second `ChallengeSolver` next to HTTP-01.

* `set_txt` **adds** a record and never replaces: an order for `*.example.eu` + `example.eu` publishes two
  values on the same name, so the name is not a key. The returned `RecordHandle` is the only way to delete
  exactly that record.
* `remove_txt` is **idempotent** (a missing record is success): cleanup also runs after a failed order and
  may run twice.
* The zone is the provider's business, not the caller's: the adapter finds it from the name.
* `FakeDns` (feature `testing`) keeps the live records and a call log, with failure injection, for the ACME
  manager and daemon tests — the same pattern as `FakePodman` and `FakeRegistry`.

**Cloudflare first.** API v4 over a small HTTP/1.1 + rustls client (`ring`, bundled `webpki-roots`; the daemon
image is `scratch`), like `weglarka-registry` and `weglarka-notify`: one request per connection, bounded
response head and body, no redirects, plain `http://` only for a loopback host (the tests) so the token can
never travel unencrypted to a remote machine. A third copy of this client is a conscious cost: each crate
keeps its own audited ~300 lines instead of a shared dependency or `reqwest`; folding them into one
internal crate is a follow-up, not part of this decision.

* **Zone discovery** walks the name's suffixes (longest first, at least two labels) against
  `GET /zones?name=`. A token lists only the zones it may see, so a name outside them is
  `ZoneNotFound` — never a write into someone else's zone. Found zone ids are cached per run.
* **Everything that reaches a URL is checked first**: record names must be lower-case FQDN labels
  (`[a-z0-9_-]`, underscore for `_acme-challenge`), TXT values printable ASCII without quotes or
  backslashes, and ids from the API (zone, record, handle) 32 lower-case hex characters. A hostile or
  broken answer cannot inject a path segment.
* **Records have TTL 60** (the lowest value Cloudflare accepts outside Enterprise): challenge records live
  for seconds.
* **Errors carry the provider's own error text** (`code: message`, capped) and never the request, so the
  token cannot appear in an error, a log line or a notification.

**The token is a secret by name.** It lives in `secrets.toml` under a reserved name and reaches the adapter
as a `SecretValue` (redacting `Debug`), is trimmed and validated once (printable ASCII), and is never
rendered anywhere else. The operator creates a Cloudflare token with `Zone:Read` and `DNS:Edit`
**scoped to the zones Węglarka may certify** — never the global API key. Compromise of this token lets an
attacker rewrite every record of those zones (including pointing the domain elsewhere), which is the
reason for the scope rule and for a dedicated token per installation; the doctor will warn when the token
can see zones the configuration does not mention (planned with the configuration).

**Wildcard only.** `challenge = "dns-01"` issues the wildcard certificate (`*.<apex>`, optionally with the
apex in the same order); per-domain certificates stay with HTTP-01. DNS-01 per domain would only trade
the port-80 requirement for the zone-write token and hide nothing in CT logs (the exact name is in the
certificate), so there is no case where it is the better choice. The certificate files follow the #96
convention `tls/_wildcard.<apex>.crt|key`.

## Rollout

1. **First step (done):** the ADR and `weglarka-dns` (trait, `FakeDns`, Cloudflare adapter, tests). Nothing is
   wired into the daemon yet, so there is no behavioural change.
2. **`DnsSolver`** in `weglarka-acme` (done, on the #96 skeleton): `kind() == Dns01`, publishes
   `_acme-challenge.<name>` = `Challenge::dns01_txt_value()` and remembers one handle per `(name, value)`, so
   a wildcard order's two challenges on the same name are two records removed independently. `present` and
   `cleanup` are idempotent, a failed delete keeps its handle for a retry, and the provider's error text is
   the only thing that reaches `AcmeError::Challenge`.
3. After the `instant-acme` client and `[acme]` of #96 land: the additions `challenge` and `[acme.dns]` (the
   provider and the *name* of the token secret), building the solver from them, and the wildcard
   `CertSpec` (`_wildcard.<apex>`: `*.<apex>` + `<apex>`) in the daemon's certificate list.
4. A separate change for ingress: map a routed domain to its certificate (exact `<domain>.crt` first, then
   a one-label wildcard `*.<apex>`; the apex itself is not covered), which touches the certificate scan in
   the daemon and the `edge` generator and its snapshots; `behind` stays byte-for-byte unchanged.
5. Doctor checks (`acme.dns.*`, CAA), `docs/install.md` and the operator documentation.

## Consequences

- **No state or schema change in this step**; later steps add optional `[acme]` keys, which break rollback to
  an older daemon the same way `[acme]` does (`deny_unknown_fields`), and are documented with it.
- **New secret to manage**: the DNS token. `secrets list` shows its fingerprint only; rotation is a
  `secrets set` and takes effect on the next challenge (the adapter reads it at construction, so the daemon
  rebuilds it with the configuration).
- **Tests**: unit tests run against a loopback mock of the API (request lines, the bearer header, bodies,
  zone walking and caching, idempotent delete, malformed and hostile answers, input validation, token
  redaction). The live check is **opt-in**: it runs only when a token and a zone are provided through the
  environment (the names are fixed with the solver), against a dedicated development zone, and skips with
  a message otherwise — the same pattern as `WEGLARKA_PODMAN_SOCKET`. CI never talks to Cloudflare.
- **CT and DNS exposure**: a wildcard hides individual subdomains, but the apex and the zone's existing
  records stay public; the operator documentation says so.
- **Propagation**: the ACME server queries the authoritative servers itself, so no resolver is needed in the
  daemon; the solver only retries within the ACME order's own limits.

## Rejected alternatives

- **A module inside `weglarka-acme`.** Cloudflare needs none of the ACME code, and the crate did not exist
  when this work started: a separate crate could land and be tested without waiting on #96 or touching its
  files. The cost is one more crate in the map and the release configuration.
- **`reqwest`/`hyper-rustls` for the API.** It pulls a large dependency tree and a second TLS stack choice
  into a `scratch` binary (priority: RAM), for roughly ten requests a quarter.
- **Replacing the TXT record instead of adding one.** A wildcard order publishes two values on one name;
  replacing would invalidate the first challenge.
- **Deleting by name.** It could remove records the operator created; the handle deletes exactly what we
  made.
- **A global API key, or a token without zone scope.** The blast radius would be the whole account.
- **A `dyn` provider registry.** One provider is configured per installation; a closed `enum` or a generic
  chosen at start-up is enough and keeps the trait dyn-free (ADR 0001).
- **Creating the A/CNAME records too.** Certificates are the daemon's job; address records stay with
  whatever manages the zone today, so the token needs no more than TXT edits.
