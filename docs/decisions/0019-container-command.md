# 0019 — Per-app container command (arguments to the image's entrypoint)

Status: accepted (2026-10-24, issue #79).

## Problem

Some images are a single binary with subcommands: `docker.io/binwiederhier/ntfy` declares
`ENTRYPOINT ["ntfy"]` and **no** `CMD`, because it is meant to be run as `ntfy serve`, `ntfy publish` or
`ntfy access`. Started with no arguments it prints its help, exits with status **0**, and the deploy gate
reports:

    container not running (Stopped, exit code 0)

Exit code 0 is the trap in that message: nothing crashed. The container did exactly what its image config
asks — ran the binary without arguments and finished successfully — so there is nothing to retry and no
image defect to pin down; the gate can only report that the container is not running. Every image that
splits its behaviour into subcommands has the same shape; ntfy is the motivating case, not a special
one.

Węglarka created containers from the image's own config and nothing else: `AppSpec` has `image`, `env`,
volumes, `port`, `health` and so on, but no field reaches the process argv. `health.command` is a
**probe**, not the main process, so it cannot help. The only workarounds were outside the spec: bake a
wrapper image, or accept that such an app cannot be deployed. Both move the fix from the declarative file
into image maintenance; the spec needs to be able to say what the container runs.

## Decision

**A new optional field on `AppSpec`: `command`, a list of strings** — in `apps.toml` inside the app
table, in a `--spec` file at the top level:

```toml
[apps.ntfy]
image = "docker.io/binwiederhier/ntfy:latest"
domains = ["ntfy.example.com"]
port = 80
command = ["serve"]          # argv: ["ntfy", "serve"]
```

**Exec form, no shell.** Every list element is exactly one argv element; nothing is quoted, split,
globbed or expanded. `command = ["serve", "-v"]` is two arguments, `command = ["serve -v"]` is one
argument containing a space, and `$VAR`, `*`, `;`, `&&` are literals that the container receives as data.
That is the OCI argv model: there is no shell to interpret anything, and an image without one
(`scratch`, distroless) works just as well as a full distribution.

**It maps to `Cmd`, not to the entrypoint.** The field becomes libpod's `SpecGenerator.command` (the OCI
`Config.Cmd`): the arguments appended to the image's `ENTRYPOINT`. For ntfy the argv becomes
`["ntfy", "serve"]` — the image's entrypoint keeps working, only its argument list is supplied.
Overriding the entrypoint itself is a different concern and deliberately out of scope: it is a separate
field (`entrypoint`) with separate semantics (replace `["ntfy"]` instead of adding to it), and an image
with a wrong entrypoint is a different problem from an image that expects a subcommand. Smuggling both
into one field would make it impossible to tell which one a spec means.

**Omitted or empty means the image's own `CMD`; set means that `CMD` is replaced, not extended.** The
field is the container's whole command, exactly like `docker run <image> <command>`: an image declaring
`CMD ["serve"]` with a spec setting `command = ["worker"]` runs `worker`, not `serve worker`, and an image
without an `ENTRYPOINT` (so its `CMD` is the whole argv) gets that whole argv from `command`. Appending
instead would make the field an unexplained tweak to image defaults and would leave no way to choose
among them. An empty list is the same as an absent field: there is nothing "no arguments at all" could
express that the image's own `CMD` does not already say.

**Part of `spec_hash`, only when set.** `HashInput` gets `command` appended **last** and skipped while
empty (`skip_serializing_if`), the same way `host_ports` and `shared_volumes` were added before it, so
the hash format version stays `v1` and an app that does not use the field hashes byte-for-byte as
before — **upgrading Węglarka recreates nothing**. An app that does set it is hashed including the
argument order, because order is meaning (`["serve", "-v"]` is not `["-v", "serve"]`): changing `command`
changes `spec-hash`, and the next reconcile recreates the container from the **pinned digest** — a
spec change, no pull, no new image.

**Validation: every argument must be a non-empty string.** `command = [""]` has no meaning as argv and
would only ever be a typo, so the daemon rejects the spec with HTTP 400 and the message
`command argument <i> must not be empty` instead of letting it reach libpod and produce a container whose
argv nobody can read. The empty *list* is not an error — it is "not set" and means the image's `CMD`.

**CLI: `--command ARG`, repeatable, replacing the whole vector.** `weglarka apps add <app> <image>
--command serve` and `weglarka apps update <app> --command serve`; one occurrence is one argv element, so
`--command serve --command=-v` is `["serve", "-v"]` — the `=` form being what a dash-leading argument
needs, because `--command -v` would be read as a flag. The flags replace the stored `command`; they never
append to it. `--command none` clears the field back to the image's `CMD` (case-insensitive, the same
convention as `--depends-on none`), which on an ENTRYPOINT-only image returns it to its useless default —
clearing is "image default", not "make it work". Like the other spec flags, `--command` conflicts with
`--spec`, and `--dry-run` prints the diff without sending anything.

**A failed gate rolls back the digest, not the spec — the operational caveat.** When a deploy fails the
health gate, rollback restores the previous container from the previous **digest** with the **current**
spec, including the `command` that just failed. A wrong `command` therefore fails the deploy (new digest,
wrong args) *and* the rollback (old digest, same wrong args): the app stays down until the spec is fixed
with `apps update <app> --command ...`. That is the opposite of the usual rollback promise, and the
reason the symptom has to be recognised for what it is: a gate failure with **exit code 0** and help
output means a missing or wrong `command`, not a bad image. The fix is a spec change, so the next
reconcile recreates the container from the pinned digest — without pulling anything.

## Consequences

- **ENTRYPOINT-only images became deployable.** The motivating case is documented end to end: ntfy with
  `command = ["serve"]` passes the gate, and the same field covers every other subcommand-style image
  (a worker entry `["worker"]`, a one-shot subcommand, a daemon with flags).
- **The command is data in the declarative file.** It is set in `apps.toml`, in a `--spec` file, with
  `--command`, and appears in `--dry-run` diffs like every other spec field; no wrapper image, no
  Dockerfile, no entrypoint override is needed.
- **No recreation on upgrade.** An app without the field hashes exactly as before, and the serialized
  form omits an empty `command` — an existing `apps.toml` is unchanged by the upgrade and no container is
  recreated by it.
- **Changing the command is a container replacement.** It is a container setting, so the next reconcile
  stops and recreates the container from the pinned digest (brief downtime for that app, no image pull).
  The argument order counts as part of the setting.
- **Only the main process, not the probe.** `command` and `health.command` are different things with the
  same exec-form shape: one configures the container's argv, the other a health probe. The names keep
  them apart; neither implies the other.
- **The rollback caveat is permanent user-facing behaviour.** It is documented in `docs/install.md` (6f
  and section 7) because it is the failure mode most likely to be misread: the deploy "succeeds" at
  rolling back and the app is still down, while nothing in the image was wrong.
- **Backward compatibility in both directions needs a note.** An older `apps.toml` parses fine with the
  new daemon (the field is optional). The reverse is not true: `apps.toml` has `deny_unknown_fields`, so
  **downgrading Węglarka requires removing `command` first** (`apps update <app> --command none` or
  editing the file), otherwise the older daemon refuses to start with a parse error. Documented in
  `docs/install.md` (section 7).
- **Verification.** The wire mapping is pinned by a snapshot of the libpod create body and by an
  integration test against a real rootless Podman (`weglarka-podman/tests/podman.rs`): the `pause`
  image, started with `command = ["-v"]`, receives the argument after its `ENTRYPOINT` and exits 0
  (with no argument it runs forever, so the zero exit code is the proof). Unit tests cover the hash
  (unset and empty hash as before, order matters), the argument validation and the CLI flags.
  End-to-end acceptance, as in the issue, is a deploy of the motivating image —
  `weglarka apps add ntfy docker.io/binwiederhier/ntfy:<tag> --command serve …` passing the health
  gate — documented in `docs/install.md` (6f).

## Rejected alternatives

- **An `entrypoint` field.** It solves a different problem: it replaces the image's `ENTRYPOINT`
  (`["ntfy"]`), while the issue is about supplying its arguments. An entrypoint override would work for
  ntfy only by accident (the binary must then also be re-added as the first argument), it invites
  wrapper-image hacks into the spec, and an image with a broken entrypoint is a different bug. Adding it
  later as its own field stays possible; conflating the two now does not.
- **A single shell string (`command = "serve -v"`, run as `/bin/sh -c ...`).** It turns the spec into a
  quoting puzzle (what happens to a space, a `$VAR`, a `;`?), requires a shell in the image (distroless
  and `scratch` images do not have one), and makes every argument a potential injection through the
  spec file. OCI and libpod are argv-based; a string would have to be re-split by rules the user cannot
  see, so the same spec could mean different things in Węglarka and in `docker run`.
- **Naming it `args` or `cmd`.** `args` reads like "extra arguments appended to the image's command",
  which is exactly what the field does *not* do, and it comes from Kubernetes, where `command` means the
  *entrypoint* and `args` means this field — so a spec in which `command` maps to `Cmd` would also be
  actively misleading to a Kubernetes user. `cmd` is the opaque OCI/internal spelling and reads like
  `health.command`, the probe. `command` names the thing the user is choosing (what the container
  runs) and pairs with `health.command` without implying the same target.
- **A global default in `weglarka.toml`.** The argv an image needs is a property of the image
  (`serve`, `worker`, `run`, `-v`), not of the host, so a single default would be wrong for almost every
  app and would **replace** the `CMD` of images that are fine today — one app's need must not change
  every other app's process. If a host-wide need ever appears, a default can be added additively; the
  per-app field is the smallest unit that matches reality (the same argument as for per-app streaming,
  0018).
- **Appending to the image's `CMD` instead of replacing it.** `docker run <image> <command>` replaces,
  OCI/libpod replace, and append semantics would silently combine a spec's argument with an image's
  default subcommand (`serve` + `worker`), with no way to remove or reorder the image's half. It would
  also be untestable without knowing every image's `CMD`; ntfy works under either rule, which makes
  append a rule chosen for one image rather than for the model.
