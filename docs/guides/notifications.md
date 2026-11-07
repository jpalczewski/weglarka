# Notifications (ntfy)

Failed deploys, rollbacks and events from the reconcile loop reach your phone through ntfy. ntfy is itself run by Węglarka (the `ntfy` app), so notifications have to survive a deploy of ntfy. For the decision and the rejected alternatives see [ADR 0021](../decisions/0021-notifications.md). Configuration snippet: [`notify.toml`](../examples/notify.toml).

What you receive: `deployed <app>`, `deploy failed: <app>`, `rolled back <app>`, `ROLLBACK FAILED: <app>` (critical), `provisioned <app>`, `recreated <app>` and `waiting for secrets: <app>` (info). If you raise `min_severity` to `debug`, you also get `removed container <name>`, `waiting for dependencies: <app>` and `duplicate webhook <id>`. Restart loops and failing healthchecks are described in [crash detection](crash-detection.md) and [ADR 0022](../decisions/0022-crash-loop-detection.md); a mail fallback is tracked in #113.

**1. Topic and token in ntfy.** Create a topic (for example `weglarka`) and, if the server is not public, an access token in the ntfy panel. **The token never goes into `weglarka.toml`.** Recommended: a host secret — a bare name in `host-secrets.toml` (0600, next to `secrets.toml`; see [host secrets](host-secrets.md)):

```sh
weglarka secrets host set ntfy-token < ntfy-token.txt   # value from stdin, never from an argument
```

Older form, still supported: a 0600 file next to the configuration:

```sh
umask 077 && printf '%s\n' 'tk_…' | sudo -u weglarka tee /var/lib/weglarka/ntfy-token >/dev/null
sudo -u weglarka chmod 600 /var/lib/weglarka/ntfy-token
```

**2. Section in `weglarka.toml`** (the host configuration file, not `apps.toml`):

```toml
[notify]
dedup_window_secs = 300          # window for merging repeats; 0 = no merging

[notify.ntfy]
url = "https://ntfy.example.com" # must be reachable FROM THE WĘGLARKA CONTAINER (see below)
topic = "weglarka"
token_secret = "ntfy-token"                   # recommended: a host secret; omit for a public topic
# token_file = "/var/lib/weglarka/ntfy-token" # the older form — set at most one of the two
min_severity = "info"            # debug | info | warning | critical
```

- **Address:** if the Węglarka container cannot reach the host's public domain (hairpin NAT / DNS inside the container), use the internal route through the ingress: `url = "http://weglarka-nginx:8080"` together with `host = "ntfy.example.com"` (the `Host` header; nginx routes by `Host`). `host` is only accepted together with an `http://` URL; for `https://` put the real name in `url`. The internal route is plain HTTP on the Podman network, so the token never leaves the host. **This route works in `behind` only.** In `edge` that port answers every routed domain with a `301` to HTTPS, which the notifier does not follow, so use the public `https://` URL there; `health.http` no longer depends on this port (it uses the [probe socket](edge-mode.md)), but notifications do not use the socket yet.
- **One token form:** `token_file` and `token_secret` are exclusive — setting both is a startup error (`[notify.ntfy] set at most one of token_file / token_secret`); with neither the topic is public. `token_secret` must be a valid host secret name (`[A-Za-z0-9_-]{1,64}`, no dot).
- **Rotation without a restart:** the token is read on every use (each publication), so replacing the host secret (`weglarka secrets host set ntfy-token < …`) or rewriting the token file takes effect with the next message, in either form. There is no `SIGHUP` and no restart to remember. A source that breaks later is not silently ignored either: a failed read is reported like a failed delivery.
- **Validation at startup:** a bad URL, a bad topic, or a broken token source — a missing or unreadable file, permissions looser than 0600, contents that cannot go into an HTTP header — **stops the daemon** (`notifications: …` in the log). Once enabled, notifications must not silently stop working. One exception: a host secret that is **not set yet** only logs a warning, because it can be set only through the running daemon; `doctor` reports it as a failure (`host.credentials`).
- **Test:** after a restart (`systemctl --user restart weglarka`):

```sh
weglarka notify test      # "test notification delivered" = URL, DNS, ingress and token all work
weglarka notify status    # channels, queue, dropped counter, last error and last delivery time
```

`notify test` goes **around the queue** (immediately, no dedup) and exits with code 7 when the channel refuses it.

**3. What happens when ntfy does not respond.** Every notification first goes to the durable queue `/var/lib/weglarka/notifications.toml` (0600) and only then is sent. A failed attempt stays in the queue and is retried with backoff 30 s → 1 min → … → 30 min, at most 12 times (about 3.5 h); the queue is also capped at 200 entries and 7 days (the oldest fall out, and the `dropped` counter shows in `notify status`). So a deploy of ntfy, which is exactly when notifications matter most, does not lose them. The queue survives a daemon restart; the dedup windows (below) are in memory only.

**4. Repeats (flapping).** The first event of a given kind for a given app is sent immediately; later ones within `dedup_window_secs` are counted, and when the window closes a single summary arrives (for example `3 more: deploy failed: ntfy`). A success does not reset the failure window, so an app that alternates between starting and crashing still produces one report per window.

## Upgrading from 0.0.3

A `[notify.ntfy]` with `host` **and** an `https://` `url` is rejected at startup (the daemon stops with `notifications: …`). Earlier releases accepted it and verified the certificate against `host`. Fix: put the real name in `url` (`url = "https://ntfy.example.com"`, no `host`), or use the plain-HTTP internal route (`url = "http://weglarka-nginx:8080"` with `host`; in `behind` mode only, since in `edge` that port answers with a redirect). Rolling back to 0.0.3 needs no change.

## Rollback

`weglarka.toml` has `deny_unknown_fields`, so **an older daemon will not start** with a `[notify]` section. Before a downgrade, remove the section from the configuration (or keep it in a backup) and restart the service. Notifications are not part of app state, so there is nothing else to clean up.

A `[notify.ntfy]` that uses `token_secret` does not parse on a daemon older than ADR 0080: switch it back to `token_file` before downgrading (the host secret itself can stay in `host-secrets.toml`, which an older daemon ignores). The field is in the table in [verification and rollback](verify-and-rollback.md).
