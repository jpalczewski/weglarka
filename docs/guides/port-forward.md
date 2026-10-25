# Temporary port forward (weglarka forward)

`weglarka forward <app> <port>` exposes a port of an app on your machine for a while — a database console, an
admin UI that is not behind the ingress, a metrics endpoint — without changing the app's spec and without
`host_ports`. The daemon starts a short-lived relay container on the app's network, published **only on the
host's loopback** (random port), and the CLI connects it to your laptop with `ssh -L`. When the command ends the
relay is removed. Decision: [ADR 0041](../decisions/0041-temporary-port-forward.md).

```sh
weglarka forward gitea 3000                       # localhost:3000 -> port 3000 of the app gitea
weglarka forward db 5432 --local-port 15432 --timeout 2h
```

- **SSH destination** (`host`, `user@host` or an alias from `~/.ssh/config`): the `--ssh` flag, then the
  `WEGLARKA_SSH` variable, then the user-wide file `$XDG_CONFIG_HOME/weglarka/cli.toml` (default
  `~/.config/weglarka/cli.toml`):

  ```toml
  ssh_host = "deploy@host.example.eu"
  ```

  The file is optional and has only this key (unknown keys are an error). Without a destination (for example when
  the CLI runs on the host itself) nothing is tunnelled: the CLI prints the relay's loopback address on the host
  and keeps the relay until you press Ctrl-C.
- **Local port:** the same as the app's port by default; `--local-port` changes it. A port that is already taken
  ends the command with an error (`ExitOnForwardFailure`).
- **Lifetime:** until Ctrl-C, a dropped connection, `ssh` exiting or `--timeout` (default and maximum 24 h). A
  daemon that died mid-forward leaves a container labelled `weglarka.forward=true`; the next daemon start removes
  such leftovers. At most 4 forwards at once (409 above that), separate from the `run` limit.
- **Requirements:** the app must be running (409 otherwise); the port is any port 1–65535 inside the app's
  container. The relay is the `ingress.nginx_image` image (with the `stream` module) under the ingress hardening
  profile; it gets no DNS alias of the app, no `host_ports` and no routing, and reconcile and `doctor` do not see
  it.
- **Security:** the relay's loopback port has no authentication — while the forward lives, anyone with an account
  on the host can connect to it. The relay resolves the app's name once, when it starts; if the app gets a new
  address (a restart), end the forward and start it again.
- **`--json`:** after the start prints one line `{"ready":true,"app":…,"port":…,"host_port":…,"local_port":…}`.

**Rollback:** nothing to do — a forward writes no state (`apps.toml` and `state.toml` are unchanged, no schema
version bump). An older daemon has no `/v1/apps/{name}/forward` route; an older CLI has neither the command nor
`cli.toml` (it ignores the file).
