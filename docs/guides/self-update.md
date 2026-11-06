# Self-update (self_update)

Węglarka updates its own image without a manual `platform install`: it pulls the tag, **verifies the cosign signature** with a pinned key, checks state-schema compatibility, pins the digest in the service definition (quadlet) and restarts the service. Decisions and rejected alternatives: [ADR 0027](../decisions/0027-self-update.md); state file schema: [ADR 0023](../decisions/0023-state-schema-version.md). Configuration snippet: [`self-update.toml`](../examples/self-update.toml).

The swap happens **on the host**, not in the container: the image is `scratch` (no `systemctl`, no `/etc/passwd`, no D-Bus), and the container has no write access to its own unit. `platform install` therefore installs two user timers: `weglarka-self-update.timer` (runs `weglarka-daemon self-update` every 10 minutes; `interval_secs` decides whether a run actually queries the registry) and `weglarka-watchdog.timer` (runs `weglarka-daemon supervise` every minute, which checks that the switched daemon answered `/v1/health`; see step 4). Both do nothing without a configured `[self_update]` section. Decision on the automatic fallback: [ADR 0034](../decisions/0034-automatic-fallback.md).

**1. Signing key (once).** The release signs the image with **two** signatures: keyless (for humans, `cosign verify`) and a static key, which the daemon verifies. The public key lives in the repo (`cosign.pub`) and is compiled into the binary; the private key exists only in repo secrets (`COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`):

```sh
cosign generate-key-pair                       # cosign.key (encrypted) + cosign.pub
gh secret set COSIGN_PRIVATE_KEY < cosign.key
gh secret set COSIGN_PASSWORD
```

Key rotation: replace `cosign.pub` in the repo and the secrets (a new image), or point to a new key in `[self_update] public_key_file` (no rebuild).

**2. Section in `weglarka.toml` and a one-time reinstall of the units** (so that both timers get created):

```toml
[self_update]
image = "ghcr.io/jpalczewski/weglarka:latest"   # a tag, not a digest: Węglarka pins the digest itself
# fallback = true                                # automatic fallback (step 4); false = manual --rollback only
# fallback_timeout_secs = 180                    # seconds the new daemon has to answer /v1/health (30..=3600)
```

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml platform install --dry-run   # preview: quadlet + timer units
weglarka-daemon --config /etc/weglarka/weglarka.toml platform install             # write, daemon-reload, enable the timers
systemctl --user list-timers weglarka-self-update.timer weglarka-watchdog.timer
```

**3. Manually, without waiting for the timer:**

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml self-update --check   # pull + signature + schema; changes nothing
weglarka-daemon --config /etc/weglarka/weglarka.toml self-update           # same as the timer does
weglarka-daemon --config /etc/weglarka/weglarka.toml self-update --force   # skip the interval / retry a failed digest
```

**4. Automatic fallback (#100) and manual rollback.** The `self-update.toml` state file (0600, in the state directory) carries `current`, `previous`, `pending`, and since #100 also a record of the switch in progress (`switch_from`/`switch_to`/`switch_at`, `switch_attempts`) and the last automatic fallback (`fallback_*`). `weglarka-watchdog.timer` runs `weglarka-daemon supervise` every minute: it probes `GET /v1/health` on the admin socket (an answer means all startup conditions are met), and when the new image does not answer within `fallback_timeout_secs`, it pins `switch_from` in the quadlet (`systemctl --user reset-failed weglarka.service`, because the restart loop exhausts the start limit, then a restart) and records the fallback in the state file. After the restart the daemon confirms it and emits the `SelfUpdateFellBack` event (a notification); the broken digest goes into `error`, so later runs do not pin it again until the tag moves (`--force` is a deliberate override). The budget is **one** automatic attempt per switch: a fallback that itself fails to come up ends in a report (the watchdog unit "failed", `doctor`), not a restart loop. The watchdog and the switcher share a lock (`self-update.lock`), so they do not overlap.

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml supervise                # manually: same as the timer does (with a report)
weglarka-daemon --config /etc/weglarka/weglarka.toml self-update --rollback   # manual return to `previous`
weglarka doctor | grep self_update    # running / previous / pending / automatic fallback and the last error
```

If the new image does not start at all, a manual pin also works:
`weglarka-daemon platform install --image ghcr.io/jpalczewski/weglarka@sha256:<previous>` + `systemctl --user restart weglarka`.

**5. Limitations and diagnostics.**

- **What the automatic fallback does not cover:** an image that started and answers `/v1/health` but is functionally broken; a fallback across a state-schema bump (image label `io.weglarka.state-schema` older than `state.toml` gives a report instead of a pin); an image that is no longer in the local store (retention, [ADR 0020](../decisions/0020-image-retention.md)); an exhausted attempt budget. In these cases `weglarka-watchdog.service` ends in failure, `doctor` shows the state, and the decision is the operator's.
- **State schema:** a newer image may write a newer `schema_version`; Węglarka then compares the image label `io.weglarka.state-schema` with the version in `state.toml` **before** the swap and refuses a downgrade ("the image writes state schema …"; the `--force` override requires a deliberate decision about the state backup). See [state schema version](state-schema.md) and [ADR 0023](../decisions/0023-state-schema-version.md).
- **An unsigned image** (for example a build from before the key was added) is rejected with "no key-based cosign signature …"; nothing is pinned and the previous version keeps running. The registry must be public: the pull is anonymous.
- Log: `journalctl --user -u weglarka-self-update.service -u weglarka-watchdog.service -n 50`; state: `weglarka doctor` (the `self_update` check).

### Switcher stopped after an upgrade that raised the state schema

A self-update replaces the **image**; the `weglarka-daemon` binary the timers run is host-side and is not replaced with it (that handoff is [ADR 0067](../decisions/0067-managed-images-and-platform-updates.md) work, issue #203).

**Host binaries from this release on keep updating across schema bumps:** the switcher and the watchdog read only the `schema_version` header of `state.toml` and compare it with the image label (issue #616), so a state written by a newer daemon is an ordinary update as long as the new image writes at least that schema; the journal then logs "the state is newer than this host binary; comparing only its schema header". The gate itself is unchanged: an image below the state's schema is still refused as a downgrade. The rest of this section is for hosts whose host binaries **predate** that change — they need one manual refresh, after which this does not recur.

When the new image raises `state::SCHEMA_VERSION`, such older host binaries cannot read `state.toml` any more and stop:

- `weglarka-self-update.service` fails; the journal shows "self-update stopped: the state is newer than the host binaries" and the run's result "refused: the state files are at schema N, but the host binaries support only schema M …" (a host binary from before this reporting prints "schema version N is newer than this daemon supports (M)" instead);
- `self-update.toml` records the stop with `host_tools_stale = true` — "the state files are at schema N, but the host binaries support only schema M …";
- `weglarka doctor` reports the `self_update` check as **fail** with that message and the fix, instead of the misleading "the switcher has not run recently".

A host binary older than this reporting records nothing, so there the journal message is the only trace. Apps keep running either way; only the automatic update is stopped (a stopped switcher must not replace the image while it cannot tell what the state needs — [ADR 0023](../decisions/0023-state-schema-version.md)). Recovery:

1. install the host binaries (`weglarka-daemon`, `weglarka`) from the **same release as the running image** — from the release tarball or by extracting them from the image, see [installation](../install.md#host-binaries) and [verifying the image and binaries](../install.md#verifying-the-image-and-binaries);
2. make the timers use them: `platform install` on a daemon-only setup;
3. check: `weglarka-daemon --config /etc/weglarka/weglarka.toml self-update --check` and `weglarka doctor | grep self_update`.

The first run that can read the state again clears the recorded stop, also when the image is already the running one, so `doctor` returns to `ok` right after step 3 (without `--check`, the next timer run does it once the interval has passed).

**A new `weglarka.toml` key.** A similar stop happens without a schema bump, also with host binaries that compare only the schema header, when you add a key to `weglarka.toml` that only the running (newer) daemon knows, for example a new `[logs]` option. `weglarka.toml` is parsed strictly (`deny_unknown_fields`, an unknown key is never ignored), so the older host binaries fail before they do anything:

- both `weglarka-self-update.service` and `weglarka-watchdog.service` fail; their journal shows `invalid …/weglarka.toml: TOML parse error at line N …` followed by `unknown field` and the key's name;
- `self-update.toml` records the stop with `host_tools_stale = true` — "the host binaries cannot parse weglarka.toml (TOML parse error at line N …: unknown field …)" (the key's name and position, never a config value) — once, not on every watchdog wake-up (issue #617; host binaries older than that record nothing, so only the journal shows it);
- `weglarka doctor` reports the `self_update` check as **fail**, with the hint that the host binaries are older than the running daemon.

The recovery is the same three steps as above. If the key is not new but mistyped, fix `weglarka.toml` instead. Either way, the first switcher or watchdog run that works again clears the record.

**Launcher setup.** There the timers run the active **generation** from the generation store, not `/usr/local/bin`, so installing new binaries changes nothing, and `platform bootstrap` refuses a host that is already bootstrapped with another generation. An in-place refresh of the generation is not implemented yet (ADR 0067, issue #203). The existing commands allow a detour that has not been verified end to end: `platform downgrade` (back to the daemon-only setup, see [platform updates](platform-updates.md); on OpenRC this leaves no daemon running until the next step), then `platform bootstrap --generation sha256:<digest of the running image> --dry-run` with the new binaries, and the same without `--dry-run` once the plan looks right.

**6. Trial on the host (optional).** CI has no user systemd, so the watchdog behavior is checked by hand:

1. **a broken image:** `self-update --image <tag> --force` with an image that does not start; after `fallback_timeout_secs` the quadlet returns to the previous digest, `doctor` shows the automatic fallback, and `journalctl --user -u weglarka-watchdog.service` shows the course and the reason;
2. **a reboot with `pending`:** reboot the host in the middle of a swap (before confirmation); after boot, within a minute, the watchdog either confirms the new image (healthy) or restores the previous one (`OnBootSec=1min`);
3. **an offline registry:** after pinning, cut off the registry (or stop `podman system service`); the automatic fallback does not contact the registry, it takes the image from the local store, so it still works.

## Rollback

`[self_update]` is a new section in `weglarka.toml` (`deny_unknown_fields`): **an older daemon will not start with it**. Before a downgrade, remove the section (together with `fallback`/`fallback_timeout_secs`) and disable both timers (`weglarka-self-update.timer`, `weglarka-watchdog.timer`).
