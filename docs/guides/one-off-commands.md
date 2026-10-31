# One-off commands (weglarka run)

`weglarka run <app> -- <command>` runs a new container **once** with the app's image, env, secrets, volumes,
configs and networks — e.g. a database migration or an admin command — streams its output as it happens and
removes the container when it finishes. Decision: [ADR 0040](../decisions/0040-one-off-containers.md).

```sh
weglarka run gitea -- gitea admin user list
weglarka run ntfy --env LOG_LEVEL=debug --timeout 10m -- ntfy user list
weglarka run gitea --entrypoint /bin/sh -- -c 'ls -l /data'
```

- **What the container gets:** the app's pinned image digest (never a newer one from the tag), its `env` (the
  `--env`/`-e` flag adds to and overrides it for this one run), secrets, volumes (private and shared, writable),
  host configs (read-only), the app's network and the shared network. Resource limits and hardening as in the app.
- **A secret for this run only:** `--secret SECRET=VARIABLE` (repeatable) exposes a stored secret of the app
  (`weglarka secrets set`) as that environment variable of the one-off container. It does not need to be bound in the
  spec, nothing is written to `apps.toml` and the app is not recreated, so a one-off admin command can read S3
  credentials without a binding that restarts production. The value is read by the daemon and handed over as a Podman
  secret: it is never on a command line, in the request, in a log or in `Debug` (only the secret *name* is sent). It
  wins over `--env` (giving both for one variable is an error) and over a binding of the app on that variable. A secret
  that is not stored is refused before the command starts, and so are the ones Węglarka manages itself
  (`registry-auth`, `webhook-hmac`, `oidc-client-*`). The Podman secret stays in the store like the app's own.
- **What it does not get:** `host_ports`, ingress routing or the app's DNS aliases — it does not answer under the
  app's name. Reconcile and `doctor` do not see it (label `weglarka.run`, no `weglarka.instance`).
- **Arguments:** everything after `--` is arguments to the image entrypoint (like `command`, see
  [container command](container-command.md)), unless you pass `--entrypoint PATH` — then they are its arguments.
  With neither a command nor an entrypoint: an error.
- **Output and exit code:** stdout and stderr go to the corresponding CLI streams; the CLI exit code is the
  command's exit code. Note that it shares the space with the CLI's own codes (3 = no such app, 4 = conflict…);
  errors before the command starts are printed to stderr, and `--json` prints one JSON object per line
  (`stream`/`data`, `exit_code` at the end). `--timeout` (default and maximum 24 h) ends the command with
  `SIGKILL`; exit code 124.
- **Ctrl-C / a dropped connection** kills the command and removes the container. A daemon that died mid-run
  leaves a container labelled `weglarka.run=true` — the next daemon start removes such orphans.
- **Limits:** at most 4 concurrent runs (409 above that); the app must have a pinned image (after `deploy` or
  after `apps add` with `start = false`, which pulls it) — it does not have to be running, so a migration can be
  done **before** the first start.
- **Mind the data:** volumes are shared with the running app. A migration on a live database (e.g. SQLite in WAL
  mode) may write to the same files — stop the app (`apps stop`) before a migration that requires it.
- **Not available (yet):** stdin or a TTY (an interactive console) — a separate task under #49.

## Rollback

Nothing to do — `run` does not write state (`apps.toml`/`state.toml` unchanged, no schema version bump). An older
daemon has no `/v1/apps/{name}/run` route, and an older CLI has no such command.
