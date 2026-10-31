# Operating a host with the CLI (for people and coding agents)

This guide is the short, safe way to drive a Węglarka host with `weglarka`. It is written so that a coding agent can
follow it, and the [agent plugin](#install-the-agent-skill) points at it, but nothing here is specific to an agent: it
is what you would want any operator to know before touching a live host.

## Pick where the commands go

First match wins; an explicit `--host` still beats `WEGLARKA_SOCKET` (and `--socket` beats `WEGLARKA_HOST`):

1. `--socket` (or `WEGLARKA_SOCKET`): the local daemon, on the host itself.
2. `--host https://panel.example.com` (or `WEGLARKA_HOST`): a remote host through its admin panel. Sign in first with
   `weglarka login` ([remote CLI](remote-cli.md)); a person has to approve the code, so an agent should start the
   command, show the code and the address, and wait.
3. `host = "https://panel.example.com"` in `cli.toml` (`~/.config/weglarka/`): the same as `--host`, kept as the default.
4. The `admin.socket` of the local `weglarka.toml`.

`weglarka whoami` tells you whether the session is alive and for how long; it refreshes the token when it is about to
expire. `--host` and `--socket` together are refused.

## Start with reads

These change nothing and are safe to run freely (a token with the `read` scope is enough for most of them):

| Command | Tells you |
|---|---|
| `weglarka status` | daemon version and the apps with their state |
| `weglarka apps list`, `apps show <app>` | the declared spec and the runtime state (with `read`, free text such as `env` values is blanked) |
| `weglarka doctor` | the host's self-diagnosis; exit code 1 means a warning, 2 a failure |
| `weglarka secrets list <app>` | secret names and fingerprints, never values |
| `weglarka volumes list`, `networks list`, `sites list` | what exists |
| `weglarka images prune --dry-run` | which old images a prune would remove |

Prefer `--json` when a program reads the output: the types come from `weglarka-api`, errors are
`{"error":{"code","message","hint","exit_code"}}`, and the exit codes are stable (`weglarka --help` lists them: 3 not
found, 4 conflict, 5 rejected by the daemon, 6 rolled back, 64 bad invocation, 69 unreachable, 70 internal).

## Before any write

- **Ask the owner first.** Anything that is not in the table above changes a live host. Name the app and the effect,
  and wait for a clear yes. One approval covers that action only.
- **Use `--dry-run`** (`apps add/update`, `secrets set`, `push`, `volumes`, …): it validates and prints the request
  without sending it.
- **Test writes on a throwaway app**, never on a real one. For example
  `weglarka apps add relay-test docker.io/library/busybox:1.37 --command sleep --command infinity --no-auto-update --memory 64M`,
  try what you need, then `weglarka apps remove relay-test`.
- **If the host is managed declaratively** (a playbook, a git repo), change the declared state there. The CLI is for
  reads, diagnosis and operations that are not part of the declaration (`run`, `forward`, a one-off `push`).
- **Secrets never go in arguments.** `weglarka secrets set <app> <name>` reads the value from stdin or `--from-file`;
  an argument would end up in the shell history and the process list. Do not print a secret back.

## The heavier commands

| Command | What it does | Care |
|---|---|---|
| `deploy <app>` | pull, swap the container, health gate, rollback on failure | a real deploy of a live app |
| `push <app> [archive]` | deploy an image archive built elsewhere (`podman save … \| weglarka push app -`) or another tag of the app's repository | up to 8 GiB over the relay; leaves the loaded image in the host's image store, which `images prune` does not remove (it is not an app's current or previous image) |
| `run <app> -- <cmd>` | a one-off container with the app's image, env, secrets and volumes | it can write to the app's volumes; the exit code of the container is yours |
| `forward <app> <port>` | a short-lived relay container; with `--ssh` a tunnel to this machine | removed when the command ends (Ctrl-C); without an SSH destination nothing is tunnelled |

`push` and `run` stream, so a long call is normal; the daemon stops a stream when the token expires, so sign in again
for anything that takes longer than the token lives.

## Things that are easy to get wrong

- `weglarka apps remove` removes the app, its volumes and its secrets. There is no undo.
- A `read` token can see an app's shape but not its secrets or `env` values; `apps show` prints `redacted: true` for
  it and the CLI refuses to write such a spec back.
- The relay forwards your bearer token; it decides nothing. A 403 means your account is not in a group with that scope,
  not that the panel is down.
- A remote command with an expired session fails with a hint to run `weglarka login`; run `whoami` to see why.

## Install the agent skill

The repository is also a Claude Code plugin marketplace with one plugin, `weglarka-cli`, that carries a skill pointing
to this guide. Add the marketplace once and install the plugin at user scope; the exact commands are in
[the plugin's README](../../plugins/weglarka-cli/README.md). Other agents can read this guide directly, or use the same
`SKILL.md` from their own skills directory.
