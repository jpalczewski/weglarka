# 0040 — One-off containers (`weglarka run`)

Status: accepted (2026-10-25, issue #106)

## Problem

Migrations, admin commands and "what does this image do with these args" need the app's image with the
app's env, secrets, volumes, configs and networks — but not the app itself. Without a first-class command
the operator reaches for `podman run` by hand, which skips the uid-range guard (a changed range makes
existing files unreadable, ADR 0009), the secret materialisation and the config-mount containment, and can
publish the app's ports a second time. The failure modes that matter: a stray container that answers to the
app's DNS name or steals its ingress route, a run that writes volumes under the wrong uid range, a process
that outlives its caller, and a container that survives a daemon crash.

## Decision

**`POST /v1/apps/{name}/run` creates a container from the app's pinned image, streams its output and
removes it afterwards.** The pieces:

- **Same preparation as a deploy, different container.** `prepare_instance` (config mounts, networks, the
  uid-range guard, volumes) is the part of a launch that does not touch the app's container; `launch` and a
  run share it, so a run cannot skip a guard. The image is the digest in `state.toml`; a missing local
  image is pulled by digest only, never by tag, so a run never follows the tag to something newer. A
  provisioned app (`start = false`) can run, which is what a migration before the first start needs.
- **It is not the app.** The container carries `weglarka.run=true` and `weglarka.run-for=<instance>` and
  **no** `weglarka.instance`, so reconcile, the crash watcher and ingress never see it. It is named
  `wg-run.<instance>.<token>` (`.` cannot occur in an instance name, as for the import helper), joins the
  app's networks **without** the extra DNS aliases, publishes nothing (`host_ports` are never applied) and
  has no restart policy and no healthcheck. Resources and the hardening profile are the app's.
- **Request fields.** `command` (arguments to the image's entrypoint, ADR 0019), `entrypoint` (replaces
  it; `ContainerSpec.entrypoint`, only ever set here), `env` (on top of the app's), `timeout_secs`
  (default and maximum 24 h). At least a command or an entrypoint is required. Output is not recorded.
- **Two phases so errors stay HTTP errors.** `Reconciler::prepare_run` validates, takes a slot and creates
  the container under the engine lock; only then does the response start. Everything that can be refused
  (unknown app 404, no deployed image 409, too many runs 409, invalid request 400, an unresolvable config
  mount 400) is an ordinary JSON `ApiError`. The lock is held for the preparation only, never for the run,
  so a long run does not block deploys. At most 4 runs live at once, across apps.
- **Framed stream, not JSON lines.** The body is `application/vnd.weglarka.run-stream`: frames of
  `kind (u8) | length (u32 BE) | payload` — stdout, stderr, exit (i32), timed out, error. Process output is
  arbitrary bytes; JSON would have to re-encode it and could split a multi-byte character across lines.
  The last frame says how the run ended; a stream that stops without one is an error to the CLI.
- **Cleanup is unconditional.** The run lives in its own task. A client that hangs up drops the response
  body, the pump drops the output channel, the engine's `out.closed()` fires, and the container is killed
  (`SIGKILL`) and removed — the same path as a timeout and as a normal exit. A daemon that dies mid-run
  leaves a container with `weglarka.run=true`; the engine removes every such container at start, when no
  run of the new process can exist yet (`remove_stale_runs`). Graceful shutdown does not wait for runs
  past the existing server-stop timeout; they are swept at the next start.
- **Podman contract (additive).** `container_logs(name, follow)` returns a stream of stdout/stderr chunks
  (libpod's multiplexed log format, demultiplexed in `weglarka-podman`), `container_wait` the exit code
  (both bare-number and `{"StatusCode"}` answers are accepted), and `ContainerSpec.entrypoint` maps to
  `SpecGenerator.entrypoint`. `FakePodman` scripts a run (`script_next_run`: output, exit code, hang).
- **CLI.** `weglarka run <app> [-e K=V]… [--entrypoint PATH] [--timeout 10m] -- <command…>`. stdout and
  stderr stay separate, the exit code is the command's own (`& 0xff`; a timeout is 124 like `timeout(1)`),
  Ctrl-C ends the process and thereby the run. `--json` prints one JSON object per line.

**Invariants:** no `spec_hash` change, no `AppSpec`/`apps.toml`/`state.toml` field, no schema bump — a run
leaves no state. The app's container, its secrets in the store and its volumes' ownership are never
modified by a run (volumes are mounted read-write: that is the point of a migration).

## Consequences

- New API route `POST /v1/apps/{name}/run`, new CLI command `run`, new `PodmanClient` methods and one new
  `ContainerSpec` field (every literal gained `entrypoint: None`). Documented in [the one-off commands guide](../guides/one-off-commands.md).
- Rollback to an older daemon needs nothing: no state was written. An older CLI simply has no `run`.
- **Volumes are shared with the live app.** A migration against a running app can write the same files
  (a SQLite database in WAL mode, for one). The operator decides whether to `apps stop` first; Węglarka does
  not, and says so in the docs.
- Secrets reach the process as the app's do (env or file) and can be printed by the command; output is not
  stored by Węglarka, but it is on the caller's terminal.
- The exit-code space is shared with the CLI's own codes (3 = not found, 4 = conflict…). `--json` and the
  stderr message tell them apart; documented in the help.
- Tests: engine scenarios on `FakePodman` (no `publish`, labels, cleanup on exit/timeout/cancel, the slot
  limit, the sweep), daemon tests over the real admin socket (frames, JSON errors, hang-up), wire and demux
  unit tests, CLI parsing and stream tests, and an opt-in integration test on real Podman.

## Rejected alternatives

- **Interactive console (stdin, TTY).** Needs a hijacked `attach` (HTTP upgrade) on both hops and terminal
  handling; a separate piece of work, to be tracked under #49 after this.
- **`podman exec` into the running app.** Needs the app running, shares its process limits and cannot run
  before the first start; it also cannot swap the entrypoint.
- **JSON-lines output.** Not binary-safe (see above).
- **Holding the engine lock for the whole run.** Would block every deploy and webhook for the length of a
  migration.
- **Reusing `Reconciler::deploy`'s container name and labels.** The run would be mistaken for the app by
  reconcile (which would remove it as a duplicate) and by ingress.
- **Pulling the tag.** A one-off command must run what the app runs, not what the tag points at today.
