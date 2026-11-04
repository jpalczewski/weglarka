# Platform updates: downgrade and remove

`platform bootstrap` installs the launcher-based setup (coordinated platform updates): periodic launcher jobs, and on
OpenRC the launcher-run `weglarka` and `weglarka-podman` init scripts. Two commands take it apart again. Both run on the
host as the runtime user's installer, like `platform install`:

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml platform downgrade
weglarka-daemon --config /etc/weglarka/weglarka.toml platform remove
```

Both are idempotent: pieces that are already gone are skipped. Unrelated entries (other lines in the runtime user's
crontab) are never touched.

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

A running daemon container is not stopped by `downgrade`; the init script that supervised it is.

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
