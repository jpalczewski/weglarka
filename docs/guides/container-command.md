# Container command (command)

An image may define only `ENTRYPOINT` and expect a subcommand as an argument: `docker.io/binwiederhier/ntfy` has `ENTRYPOINT ["ntfy"]` and no `CMD`, so the container starts without arguments, prints help and exits with code 0, and the health gate reports "container not running (Stopped, exit code 0)". That is not an image failure or a missing healthcheck: the `serve` argument is missing. The optional `command` field supplies the container's argv. Decision and rejected alternatives: [ADR 0019](../decisions/0019-container-command.md).

```toml
# apps.toml / --spec: ntfy runs as `ntfy serve`
[apps.ntfy]
image = "docker.io/binwiederhier/ntfy:latest"
domains = ["ntfy.example.com"]
port = 80
command = ["serve"]             # container argv: ["ntfy", "serve"]
```

Apply it with `weglarka apps add ntfy docker.io/binwiederhier/ntfy:latest --command serve` for a new app, or `weglarka apps update ntfy --command serve` for an existing one; in a `--spec` file `command` is a top-level field (like `image`). A ready-made file: [`docs/examples/command.toml`](../examples/command.toml).

- **Exec form, no shell:** each list element is exactly one argv argument; nothing is quoted, split or expanded. `command = ["serve", "-v"]` is two arguments, `command = ["serve -v"]` is one argument containing a space, and `$VAR`, `*`, `;` and `&&` are data, not shell syntax (an image without a shell, e.g. `scratch`, behaves the same).
- **This is not an entrypoint override:** the field goes to `Cmd` / `SpecGenerator.command` in libpod, so it is appended to the image's `ENTRYPOINT` (for ntfy: `["ntfy", "serve"]`). A separate `entrypoint` field is out of scope here; it is a different decision with a different meaning (replacing `["ntfy"]`, not adding an argument).
- **Empty = the image's `CMD`; set = replaces `CMD`** (does not append): an image with `CMD ["serve"]` and `command = ["worker"]` runs `worker`, not `serve worker`; an image without `ENTRYPOINT` gets the whole argv from `command`. An empty `command` means the same as no field ("no arguments" is exactly the default `CMD`).
- **`spec-hash`:** `command` enters the hash **only when set** (appended at the end of the input, format v1 unchanged), so a Węglarka upgrade does not recreate any existing container. Changing `command`, including the order of arguments, changes the `spec-hash`, and the next reconcile recreates the container from the **pinned digest** (no pull).
- **CLI:** `--command ARG` is repeatable, and one occurrence is one argv element; an argument starting with a dash needs the `=` form: `apps update ntfy --command serve --command=-v`. The flags **replace the whole vector** (they do not append), and `--command none` (case-insensitive) clears the field back to the image's `CMD`; on an `ENTRYPOINT`-only image that is a return to the broken default behaviour. Like the other spec flags, `--command` is mutually exclusive with `--spec`; `--dry-run` shows the diff and sends nothing.
- **Validation:** every argument must be non-empty; an empty string ends with HTTP 400 and the message `command argument <i> must not be empty`. An empty **list** is not an error: it means "not set", i.e. the image's `CMD`.
- **Operational note (rollback):** after a failed deploy the health gate restores only the previous **digest**, not the spec. A wrong `command` therefore fails the deploy *and* the rollback (old digest, same bad arguments), and the app stays stopped until the spec is fixed: `weglarka apps update <app> --command ...` (the next reconcile recreates the container from the pinned digest, without a pull). How to recognise the symptom: the deploy fails at the gate with exit code 0 and the image's help output; that is a missing or wrong `command`, not a bad image.

## Rollback

**Downgrade:** `apps.toml` has `deny_unknown_fields`, so an **older daemon** cannot read `command`. Before going back to an earlier Węglarka version, remove the field from the apps (`apps update <app> --command none` or by hand); see [verify and rollback](verify-and-rollback.md).
