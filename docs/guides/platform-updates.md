# Platform updates: downgrade and remove

`platform bootstrap` installs the launcher-based setup (coordinated platform updates): periodic launcher jobs, and on
OpenRC the launcher-run `weglarka` and `weglarka-podman` init scripts. Two commands take it apart again. Both run on the
host with `weglarka-daemon`, never inside the container, and with the same privileges as `platform install`
(see [installation](../install.md)): the runtime user on systemd, root on OpenRC, whose init scripts are root-owned:

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml platform downgrade
weglarka-daemon --config /etc/weglarka/weglarka.toml platform remove
```

Both are idempotent: pieces that are already gone are skipped. Unrelated entries (other lines in the runtime user's
crontab) are never touched, and a crontab without the managed block is not rewritten at all. If the block's start marker
has no end marker, the command stops with an error naming the file and changes nothing: remove the block by hand and
run it again.

## Bootstrap: check first

`platform bootstrap` decides everything before it changes anything: it reads the host, runs the checks and only then
executes the steps. A host that is already bootstrapped with another `--generation`, a legacy self-update runner that
still holds `self-update.lock`, an unreadable `self-update.toml`, a launcher or tool that is not a regular file, a
generation directory whose files differ from the tools being installed, or (on systemd) a tool that fails
`host-preflight` is refused with nothing installed, retired or imported. `--dry-run` runs the same checks and prints the
numbered steps without applying them:

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml platform bootstrap --generation sha256:<digest> --dry-run
```

A dry run needs the same privileges as the real run and writes nothing that outlives it. The preflight of the tools
runs on a verified private copy in a `.weglarka-bootstrap-plan-*` directory (mode 0700) next to the host-only
directory, whose parent directory must therefore exist; it is removed when the run ends, and leftovers of a killed run
are removed by the next one. An existing generation directory is verified read-only (the `.verified` cache record is
not rewritten). On OpenRC the preflight also needs the runtime user's Podman socket and the cron service, which
bootstrap itself provisions, so there it still runs after those steps, as the last check before the bootstrap-complete
marker is written. Two things are deliberately looked at again while applying: the legacy lock once the legacy timers
are off, and `self-update.toml`, which is read, imported and retired only then, so a legacy timer firing during a long
preflight cannot make bootstrap import a stale copy. The launcher and tool sources are validated again when they are read.

## Downgrade

`platform downgrade` goes back to the daemon-only setup. It refuses while a platform update transaction is not
finished, and it deletes the launcher selection (`platform-service.toml`), `host-tools.toml` and the bootstrap marker.

| Platform | Removed | Left in place |
|---|---|---|
| systemd | the launcher job timers and services (`weglarka-platform-update.*`, `weglarka-platform-watchdog.*`) | the quadlet; the legacy `weglarka-self-update.*` and `weglarka-watchdog.*` units are written again |
| OpenRC | the managed cron block, and the `weglarka` and `weglarka-podman` init scripts (stopped and removed from the `default` runlevel) | `crond`, other crontab lines |

OpenRC never had a daemon-only setup: its `weglarka` init script always runs the launcher. There is therefore nothing to
restore, and an OpenRC host has no daemon after `downgrade` (also after a reboot) until you run `platform bootstrap`
again. The platform update contract describes the reverse command as removing the launcher units and restoring the
legacy daemon-only units, and the cron block as the only crontab content that uninstall removes.

On OpenRC nothing supervises a daemon after `downgrade`: the init script is gone, and a container that was running keeps
running unsupervised until it exits or the host reboots.

## Remove

`platform remove` deletes the service and everything the launcher setup installed.

| Platform | Removed |
|---|---|
| systemd | the quadlet, the launcher job timers and services, and the self-update and watchdog timers and services |
| OpenRC | the managed cron block, and the `weglarka` and `weglarka-podman` init scripts (stopped and removed from the `default` runlevel) |

On OpenRC a crontab that held only the managed block is deleted; lines you added yourself stay. `crond` stays enabled,
because other jobs may use it.

## Rollback

Both commands only remove host-side service definitions; they do not touch `apps.toml`, `state.toml` or the apps'
containers and volumes. To get the setup back, run `platform install` (systemd) or `platform bootstrap` (either
platform) again.
