# 0064 — Generated config a consumer watches by itself

Status: accepted (2026-10-31, issue #366, epic #331). Amends ADR 0055 (generated config pipeline): it adds what ADR 0055
rejected as "an `ApplyMode` per generator", for one reason that ADR did not cover. Builds on ADR 0061 (metrics listener)
and #364 (per-app metrics networks).

## Problem

A managed Prometheus (`[metrics] scraper`) needs a list of scrape targets that follows `apps.toml`: one target per app
with `metrics_port`, plus the daemon's own listener. The generated config pipeline (ADR 0055) already renders, validates
and swaps files atomically, so the targets should go through it. But its apply step reloads a running consumer — its
`reload_signal`, otherwise a **restart** — and then runs the health gate. For Prometheus that is wrong both ways:

- **A restart on every `apps.toml` change** drops in-flight scrapes, replays the WAL and loses the gap; with the 2 s
  debounce it still happens on every deploy that touches an opted-in app.
- **A signal does nothing.** On SIGHUP Prometheus re-reads its main config and keeps every service discovery provider
  whose config did not change (`discovery.Manager.ApplyConfig` compares the configs and keeps equal ones running); the
  `file_sd_configs` entry is the same, so the provider is not restarted and the file is not re-read because of the
  signal. Requiring `reload_signal = "SIGHUP"` would be a check that always passes and proves nothing.

Prometheus does not need either: `file_sd` re-reads its files by itself. Constraints, in order: security (no secret or
free text in the file), then extensible code (the pipeline must not learn about Prometheus), then RAM.

## Decision

1. **The generator says how its consumer learns about a new version.** `ConfigGenerator::apply_mode()` returns
   `ApplyMode::Reload` (the default, ADR 0055 unchanged) or `ApplyMode::ConsumerWatches`. For the latter the pipeline
   skips step 5: no signal, no restart, no health gate, and therefore no rollback. Everything before it stays: render →
   equal? stop → write the version → validate → swap `current` → record. `GeneratedOutcome::Applied` reports
   `reloaded: false`. Only the Prometheus targets generator returns `ConsumerWatches`; the identity generator keeps
   `Reload`, because Authelia reads its config only at start.
2. **Validation is the only guard, so it must be real.** `promtool` has no standalone check for a `file_sd` file:
   `check config` reads one only through a config whose `file_sd_configs` references it, and a referenced file that does
   not exist is a warning with exit code 0. The generator therefore renders a second file into the same version,
   `promtool-check.yml`, a minimal config whose only job lists `targets.yml` by a **relative** path, and validates with
   `promtool check config <version>/promtool-check.yml` in a one-off container of the scraper. The relative path resolves
   to the version being validated (Prometheus resolves `file_sd` paths against the config's directory), and both files
   are written together, so the "missing file" warning cannot hide a check that did not happen. `check config` parses
   the file strictly and builds every target from it (`scrape.TargetsFromGroup`), the same code path the server uses.
3. **Pick-up is Prometheus' own `refresh_interval`.** The scraper reads `/weglarka/generated/current/targets.yml`.
   `file_sd` watches the file's directory with inotify, but `current` is a symlink, so the watch is on the version
   directory it pointed at; the swap renames the link in the parent and raises no event in that directory. The
   periodic re-read (default 5 minutes) then picks up the new file, re-resolving the link. The guide recommends
   `refresh_interval: 30s`: reading a file of a few hundred bytes every 30 seconds costs nothing, and a target that
   appears half a minute after its deploy loses at most that much data of a brand-new app.
4. **Atomic, and visible through the mount.** Nothing about the layout changes: the version is built in `<version>.tmp`
   and renamed, `current` changes by one `rename`, and the scraper mounts the consumer's **directory**
   (`<state dir>/generated/<scraper>` at `/weglarka/generated`, read-only), not a single file. A single-file bind mount
   would keep pointing at the replaced inode after a rename; a directory bind sees the new entries at once. A reader that
   opens the file mid-swap gets either the whole old or the whole new version.
5. **What the file contains.** One target group per app with `metrics_port`, sorted by instance name: target
   `<app>:<metrics_port>` (the instance name is the alias on `metrics-<app>`, #364), labels `app` and `__metrics_path__`
   (`metrics_path`, or `/metrics`). Then the daemon: `weglarka:<[metrics] listen port>` with `__metrics_path__` only —
   no `app` label, because the daemon's own series carry `app` and a target label of the same name would rename theirs
   to `exported_app`. Label values are validated instance names and validated paths (ADR 0061, decision 8), quoted and
   escaped anyway. No secret, digest, image reference or timestamp: same input, same bytes.
6. **Triggers need nothing new.** The worker already runs on every desired-state change (`Daemon::changed()`), and the
   render depends only on `metrics_port` and `metrics_path` of each app, so opting in or out, removing an app, and
   changing the port or the path each change the fingerprint. A path-only change recreates no container
   (`metrics_path` is outside `spec_hash`) and still rewrites the file.

Invariants: a `ConsumerWatches` generator must return a validator from `validate_argv` — the pipeline enforces it and
fails the pass, before the swap, when one returns none (the bootstrap before the consumer's first deploy stays
unchecked, as in ADR 0055); the pipeline still never touches `current` except by `rename`; the default stays `Reload`,
so an existing generator behaves exactly as before.

## Consequences

- New optional `scraper` key in `[metrics]` (`weglarka.toml`, `deny_unknown_fields`): an older daemon refuses a file that
  has it. `GET /v1/config` shows it (`MetricsView.scraper`, additive). No `apps.toml`/`state.toml` field, no
  `SCHEMA_VERSION` bump.
- The scraper is a generated-config consumer: it gains the `/weglarka/generated` mount, so a running scraper is
  recreated **once** when `scraper` is first set. Every other app keeps its hash.
- The scraper's image must contain `promtool` (the official Prometheus image does). With another scraper every render
  is rejected as invalid and `doctor`'s `generated.metrics-targets` says why.
- A bad render never reaches Prometheus; if one did, `file_sd` keeps the previous targets and logs the error, so there
  is nothing to roll back to that Prometheus has not kept already.
- `doctor` gets `generated.metrics-targets`; the events are the existing `GeneratedConfig*` ones.
- Joining the scraper to `metrics` and to every `metrics-<app>` network is #365, not this decision.
- A validator that times out or is cancelled is recorded as `Invalid` like a rejection (ADR 0055), so that render is
  not retried until it changes and the scraper keeps the previous targets. The guide says how to clear the record.
- Tests: a real-Podman test (`podman-tests` job) runs the official image's `promtool` on the generator's actual output:
  the render passes, a malformed file, an empty label name, an invalid address and a file of the wrong shape fail,
  and the check config without `targets.yml` passes with a warning (the reason both files are written together).
  The first CI run corrected one assumption: Prometheus 3 validates label names as UTF-8, so a name such as
  `bad-label` is accepted; only an empty name is rejected. The generator emits only `app` and `__metrics_path__`,
  so its output is unaffected;
  a snapshot of the rendered file and of the check config, determinism, a fingerprint change for every trigger,
  an engine test that a `ConsumerWatches` consumer is validated but never stopped or signalled, and a daemon test that a
  path-only change rewrites the file without recreating the app or restarting the scraper.

## Rejected alternatives

- **Require a `reload_signal` on the scraper.** SIGHUP does not re-read an unchanged `file_sd` provider (decision 1), so
  the requirement would be satisfied and useless.
- **Keep restarting it.** One Prometheus restart per deploy of any opted-in app is the failure the issue names.
- **Skip the apply step inside the pipeline for any consumer without `reload_signal`.** That would silently stop
  restarting every other consumer that relies on the restart (Authelia).
- **`promtool check service-discovery`.** It runs the discovery for a job of a full config and reports the targets; it
  needs the same companion config and adds nothing that `check config` does not already check.
- **Validate with a shell in the scraper's image (`sh -c` writing a temporary config).** Depends on a shell and a
  writable path inside the image, and puts quoting between the render and the check.
- **Write `targets.yml` in place in a fixed directory, so inotify fires.** A reader could see a half-written file, and
  ADR 0055's one-`rename` invariant would have an exception.
- **An `http_sd_configs` endpoint on the metrics listener.** Pull-based and always fresh, but it adds a second route to a
  listener that ADR 0061 keeps to exactly one, and the targets would be computed per request instead of once per change.
