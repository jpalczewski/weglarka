# 0080 — Host credentials behind one secret abstraction

Status: proposed (2026-11-06, issue #199)

## Problem

Host-level credentials reach the daemon through separate, ad-hoc paths: app secrets live in `secrets.toml` behind
`SecretStore` (ADR 0024), while the ntfy token (`[notify.ntfy] token_file`, ADR 0021) and the Cloudflare token
(`[acme.dns] token_file`, ADR 0039) are 0600 files read once at startup, each with its own reader, its own
permission check and its own (or no) `doctor` check. The two readers are near copies (trim CR/LF, reject empty,
printable ASCII only), and the "group/other may not read it" check exists four times. A forge token for webhook
registration (#187) would add a fifth copy.

What goes wrong without a decision: every new credential repeats the copy, a fix to one reader misses the others
(header injection is the failure that matters), rotation means a daemon restart, and a future vault process (#200)
has no single seam to replace.

## Decision

**One read seam, `CredentialSource`, with two adapters.** A synchronous, dyn-compatible trait in `weglarka-model`
(like `SecretStore`: local I/O on small files, `dyn` because the source is chosen by configuration):

```rust
pub trait CredentialSource: Send + Sync {
    /// Reads the current value; called on every use, never cached by the caller.
    fn read(&self) -> Result<SecretValue, CredentialError>;
}
```

- `FileCredential { path }` — the existing `token_file`: 0600 check, trailing newline dropped.
- `StoreCredential { store, name }` — a named entry in the host secret store (below).

Both validate the value as a header token (`HeaderToken`: non-empty, printable ASCII, no CR/LF) through one
function; the 0600 check is one function (`fsutil::check_private`) shared with `FileSecretStore`. Errors name the
source (path or secret name), never the value.

**Read on use.** The ntfy channel and the DNS provider hold an `Arc<dyn CredentialSource>` instead of the token and
read it per publication / per DNS-01 order. Rotation is "replace the file or `secrets set --host`", for either
adapter, without a restart or `SIGHUP`. A source that fails at use is reported like a failed delivery or order. At
startup both consumers read once: a broken source (permissions, shape, unreadable file) stays a startup error (ADR
0039: opt-in, but never a silent skip), while a host secret that is **not set yet** only warns — it can be set only
through the running daemon, so making it fatal would lock the operator out. `doctor` reports it as a failure.

**Host secrets live in their own file, `host-secrets.toml` (0600)**, served by the same `FileSecretStore` code
parametrised by scope (`SecretScope::App` keeps `<instance>.<name>`; `SecretScope::Host` takes a bare `<name>`
with the `valid_secret_name` rules). A separate file, not a `_host.` prefix in `secrets.toml`: an older daemon
validates every key of `secrets.toml` and would treat the whole store as corrupt after a rollback, taking the app
secrets down with it. `SecretOps` (value-free operations, #213) works over the host store unchanged.

**Configuration.** `[notify.ntfy]` and `[acme.dns]` gain `token_secret = "<name>"`, exclusive with `token_file`
(exactly one for `[acme.dns]`, at most one for ntfy). `token_file` stays supported as the file adapter; it is
documented as the older form, not removed (`deny_unknown_fields` makes removal a breaking change).

**Operator surface.** `weglarka secrets host set|list|remove <name>` (`--host` is the global remote flag) over
`/v1/host/secrets`: writes need the admin scope, the list the read scope like app secrets; the list view is an
allowlist projection (name, fingerprint, `updated_at`). `doctor` gets one `host.credentials` check that walks the
configured sources (file permission or store presence and shape), replacing the token part of `acme.dns`.

**Reserved names.** The reserved app secrets (`registry-auth`, `webhook-hmac`, the OIDC pair) move into one table
that `is_daemon_managed` and `doctor` read; `forge-token` is reserved there for #187.

Invariants:

- No `apps.toml`/`state.toml` change: `SCHEMA_VERSION` stays. `secrets.toml` keeps its format and key rules.
- A value never reaches logs, `Debug`, an error message or a read view.
- A host secret is never bound into a container: host names are not resolvable from an `AppSpec`.

## Consequences

- Operators may move a token from a file into `host-secrets.toml` and back; both forms rotate without a restart.
- Rollback: a `weglarka.toml` that uses `token_secret` does not parse on an older daemon — switch back to
  `token_file` first (`docs/guides/verify-and-rollback.md`). `host-secrets.toml` is ignored by an older daemon.
- Code: the two `read_token` copies, the `NotifySettingsError::Token*` variants and the doctor's own permission
  check go away. New API endpoints change `weglarka-api` (released together with CLI and daemon).
- Tests: header-token validation (CR/LF, empty, non-ASCII), both adapters (permissions, rotation visible on the
  next read), exclusivity of `token_file`/`token_secret`, the redacted `Debug`/error texts, the allowlist view.

## Rejected alternatives

- **`_host.<name>` keys in `secrets.toml`** — one file, but a rollback makes the whole app secret store unreadable.
- **Read once, reload on `SIGHUP`** — a new signal path and a stale-token window for no gain: the files are small and
  a publication or DNS-01 order is rare.
- **Extending `SecretOps` with a value-returning read** — `SecretOps` is value-free by design (the vault seam of
  #200); the read seam belongs in its own trait, so a vault can implement one without the other.
- **Removing `token_file`** — breaks every existing `weglarka.toml` under `deny_unknown_fields`.
