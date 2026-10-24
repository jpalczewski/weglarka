# 0027 — Self-update: a host-side switcher, a pinned cosign key and a schema gate

Status: accepted (2026-10-24, issue #99) · part of #47; automatic fallback is #100.

## Problem

Updating Węglarka meant `weglarka-daemon platform install --image …@<digest>` plus a restart — a manual step on
every release. The daemon cannot do it from inside its container:

- the image is `scratch`: no `systemctl`, no `/etc/passwd`, no D-Bus, so `Platform::install_service` and
  `systemctl --user daemon-reload` are unavailable;
- the quadlet directory is not mounted into the container and should not be: write access to its own unit would
  let a compromised daemon persist itself;
- with `Restart=always` a running container restarts, but systemd re-runs the *loaded* unit — a rewritten quadlet
  only takes effect after a reload. Without `daemon-reload` a "pin and exit" would therefore switch through the
  local tag, not through the service definition, and would leave the quadlet describing something else.

Pulling and running a new image is remote code execution on the host, so it needs a verifiable trust anchor: a
signature, not just TLS to the registry. A failed update must also be recoverable by hand — #100 (automatic
fallback) is deliberately later.

## Decision

**The switch runs on the host, as Węglarka itself.** A new subcommand, `weglarka-daemon self-update`, is installed
by `platform install` together with a user timer:

* `weglarka-self-update.service` — oneshot, `ExecStart=<binary> --config <config> self-update`;
* `weglarka-self-update.timer` — `OnBootSec=5min`, `OnUnitActiveSec=10min`, `Persistent=true`.

`[self_update] interval_secs` (default 3600) decides whether a wake-up really checks the registry, so the cadence
is configuration, not a unit edit, and a broken release is not retried every ten minutes.

One run, in this order — each step is a pure function over a trait (`PodmanClient`, `Registry`, `Platform`), so the
tests drive all of it without Podman, a registry or systemd:

1. **Pull** `[self_update] image` (a tag; a digest is refused in configuration) and take the digest Podman
   resolved (`PullEvent::Complete`).
2. **Verify** the cosign signature of *that digest* against the pinned public key: `cosign.pub` in the repository,
   embedded in the binary with `include_str!`; `[self_update] public_key_file` overrides it for rotation. The
   signature object is the standard `.sig` tag (`sha256-<hex>.sig`), the simple-signing payload layer with the
   `dev.cosignproject.cosign/signature` annotation; the key is ECDSA P-256/SHA-256 and the check uses `ring`
   (`ECDSA_P256_SHA256_ASN1`), which the binary already links for rustls. Verification checks the payload type, the
   image digest and the repository identity, then the signature over the exact payload bytes. Keyless layers
   (carrying a certificate annotation) are skipped.
3. **Schema gate** (the version marker from ADR 0023): compare the image's OCI label
   `io.weglarka.state-schema` with the `schema_version` of `state.toml` (a file without the marker is v1). A
   downgrade across a bump is refused (unless `--force`), because the older image cannot read migrated state —
   and a state this binary cannot read at all (`SchemaTooNew`) stops the switcher before it pulls anything.
4. **Pin**: render the same `ServiceSpec` `platform install` renders, with `image = repo@sha256:<digest>`, write the
   quadlet and run `daemon-reload`. The definition now names exactly what runs.
5. **Record and restart**: write `pending = <digest>` to `<state dir>/self-update.toml` **before** restarting, then
   `systemctl --user restart weglarka.service`. The daemon's graceful stop drains an in-flight deploy
   (`TimeoutStopSec=70`); a killed one is converged by the startup reconcile.

The daemon confirms the outcome on its next start: it reads the digest of its own container
(`container_inspect("weglarka")` → `image_inspect`) and resolves `pending`:

* `pending == running` → `current = pending`, `previous` = the old `current` (the rollback target), emit
  `SelfUpdated`;
* `pending != running` → `SelfUpdatePending` (warning) and `doctor` keeps showing the pending digest with its age —
  a failed switch is reported, never silently assumed.

`weglarka-daemon self-update --rollback` pins `previous` again and restarts — the manual fallback until #100. It
does not re-fetch or re-verify the signature: returning to the image that was running a moment ago is not an
untrusted operation, and a rollback must work when the registry does not.

The signing key is a **long-lived cosign key pair**: `cosign.pub` is committed, the private half is only in the
repository secrets (`COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`). The release workflow signs every image twice — keyless
(for people, `cosign verify --certificate-identity-regexp …`) and with the static key
(`--tlog-upload=false`, so verification needs neither Rekor nor the network beyond the registry). Self-update is
opt-in: no `[self_update]` section means the switcher does nothing (the timer still exists, and returns
immediately).

**Invariants.**

* The switcher verifies the digest it pins — no pull-then-verify-something-else window.
* Nothing is pinned or restarted unless the signature and the schema check passed; a refusal is recorded in
  `self-update.toml` (`doctor`, the journal) and the same digest is not retried until the tag moves.
* The image label mirrors `state::SCHEMA_VERSION` (the `ARG STATE_SCHEMA` in the `Containerfile`), and a test in
  `weglarka-core` fails when the two drift apart; the switcher never guesses a version from the image name.
* `self-update.toml` is tolerant (`serde(default)`, unknown fields ignored, 0600): it is bookkeeping, and neither an
  older nor a newer daemon may be stopped by it. The strict, schema-versioned files stay `state.toml`/`apps.toml`.
* The container never gets write access to the quadlet directory; the switch is always a host operation.
* `[self_update]` is a new section of `weglarka.toml`, which uses `deny_unknown_fields`: an older daemon refuses to
  start with it. Documented in [install.md](../install.md) (6i and 7).

## Consequences

* New operator surface: `weglarka-daemon self-update [--check|--force|--rollback|--image <ref>]`,
  `platform install` now also writes and enables the timer (re-run it once on an existing host), `platform remove`
  disables and deletes it. `doctor` gains a `self_update` check; `weglarka.toml` gains `[self_update]`;
  `docs/examples/self-update.toml` is a validated excerpt; the `Containerfile` gains the
  `io.weglarka.state-schema` label fed from an `ARG STATE_SCHEMA` tied by a test to `state::SCHEMA_VERSION`.
* New state: `<state dir>/self-update.toml` (tolerant, 0600) — the schema marker itself is ADR 0023's
  `schema_version`, not a second file. Neither the marker nor `self-update.toml` is written eagerly, so a
  rollback of the image is unaffected by the state files themselves.
* Notifications: `SelfUpdated` (info) and `SelfUpdatePending` (warning) go through the existing pipeline; they name
  Węglarka itself, so they carry no click-through link.
* The release pipeline now needs the two secrets; without them a tag build fails and `main` builds warn, because
  an unsigned image cannot be self-updated. Rotation: replace `cosign.pub` and the secrets, or point
  `public_key_file` at the new key.
* Tests: payload/key/verification vectors and an HTTP server per case in `weglarka-registry`; the whole switcher
  (no-op, applied, refused, schema downgrade, `--check`, `--rollback`, not-due) on fakes in
  `weglarka-daemon`; the startup confirmation and both `doctor` checks through the real admin socket.
* **Not covered:** automatic fallback when the new daemon does not become healthy (#100 — its home is the same
  timer: wait for health, then `--rollback`); keyless Sigstore verification in the daemon; private registries
  (pulls are anonymous); a webhook-triggered check (the timer covers "or tag").

## Rejected alternatives

* **Pull and exit in the container** (`Restart=always` restarts from the local tag). Works without host changes, but
  the service definition keeps `:latest` — the switch is not pinned anywhere and a rewritten quadlet would only
  take effect at the next reload. It also gives the daemon the power to change what runs next.
* **Mount the quadlet directory into the container and rewrite it there.** Same reload problem, plus a container
  that can edit its own service definition — a persistence primitive gained for no benefit.
* **Keyless verification in the daemon (`sigstore` crate).** Semantically the nicest (identity = the release
  workflow), but the crate pulls ~250 dependencies including TUF, Rekor, an OCI client and a second crypto backend,
  and it wants a CA bundle file that a `scratch` image does not have. Too much weight and moving trust material for
  a 5 MB static binary.
* **Hand-rolled keyless verification** (Fulcio chain at Rekor time, SET canonicalization, Merkle inclusion, OIDC
  identity). Six subtle traps, all of them security-critical; not written by hand here.
* **The `cosign` binary in the image** (static Go, ~140 MB): a third-party binary to pin and verify, needs a CA
  bundle and `TMPDIR`, and contradicts the packaging decision (0006). It stays the oracle for manual checks.
* **Podman `policy.json` with `sigstoreSigned`.** Would enforce on every pull, but it is global host configuration
  (not per service) and its Fulcio path matches e-mail identities only, which GitHub Actions certificates do not
  carry.
* **`AutoUpdate=registry` in the quadlet.** Out of scope in 0006 and it bypasses any signature check.
* **Polling the registry API for the tag digest** instead of `podman pull`. Duplicates what Podman already does,
  including credentials and platform resolution, and adds a second source of truth for "the digest of this tag".
* **A webhook as the only trigger.** It needs an extra secret and inbound access to react faster than an hour;
  the timer covers the same need, and `self-update --force` is the manual lever.
