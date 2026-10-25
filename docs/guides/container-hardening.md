# Container hardening

How Węglarka restricts containers: the opt-in `security` block for apps, and the always-hardened `weglarka-nginx` ingress container ([ADR 0014](../decisions/0014-ingress-nginx-hardening.md)).

## Hardening an app (security)

By default an app container has only UID isolation (a separate range per instance, or the group's shared range for a shared volume, see [shared-volumes.md](shared-volumes.md)) and optional limits. For apps with secrets (API keys, tokens) and private data, enable hardening. It is the same thing Coolify gave services with `read_only` / `cap_drop` / `no-new-privileges`:

```toml
# apps.toml / --spec
security = { read_only = true, tmpfs = ["/cache"], cap_drop = ["ALL"], no_new_privileges = true }
```

With flags: `--hardened` (= `read_only`, `cap_drop = ["ALL"]`, `no_new_privileges`), plus `--tmpfs /path` for writable directories outside volumes and `--cap-add NAME` if the app needs a capability (for example `NET_BIND_SERVICE` for a port below 1024 inside the container). Individually: `--read-only true|false`, `--no-new-privileges true|false`, `--cap-drop`, `--cap-add`, `--tmpfs` (`none` clears the list).

- With `read_only`, Podman mounts writable tmpfs on `/tmp`, `/var/tmp` and `/run`; volumes and secrets work as usual. An app that writes elsewhere outside a volume (a cache, a pid file in the application directory) needs `--tmpfs`.
- Changing `security` recreates the container. Apps without hardening hash as before (updating Węglarka recreates nothing).
- Check after a deploy: `podman inspect <container> --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'`.

## The ingress container (weglarka-nginx)

The nginx container is **always** hardened ([ADR 0014](../decisions/0014-ingress-nginx-hardening.md)): it is the only container exposed to the outside, and its profile is chosen by Węglarka, not by an app spec. It runs with `read_only`, `no_new_privileges`, `cap_drop = ["ALL"]` and only three capabilities added back (`CHOWN`, `SETGID`, `SETUID`): nginx changes the owner of its temporary directories to the image's worker user and drops privileges to it, and it will not start without them. Everything nginx writes at runtime (the pid file and the `*_temp_path` directories) lives in `/tmp`, which Podman mounts as writable tmpfs under `read_only` (together with `/var/tmp` and `/run`). That is why the profile needs no `tmpfs` entry of its own.

- The profile is part of `weglarka.ingress-hash`, so **updating Węglarka recreates nginx once** (a short traffic interruption; the image is already on the host if `nginx_image` did not change). Rolling back to an older Węglarka recreates it too, this time without the hardening. No TOML field changed, so `deny_unknown_fields` does not get in the way of a rollback in either direction.
- A custom `ingress.nginx_image` must work with a read-only root and with exactly these capabilities (the official `nginx:*-alpine` does).
- Check: `podman inspect weglarka-nginx --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'` (expected `true` and `[CAP_CHOWN CAP_SETGID CAP_SETUID]`) and `podman exec weglarka-nginx nginx -t -c /etc/nginx/nginx.conf`.
