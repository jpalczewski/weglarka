# Webhooks: GitHub and Forgejo

Węglarka updates an app when its registry publishes a new image: the registry's host sends a webhook, the daemon
verifies its HMAC and deploys. This guide covers the GitHub webhook (GHCR), how redelivery is handled across
restarts, and the Forgejo adapter for private images. Decisions:
[ADR 0004](../decisions/0004-webhook-github.md), [ADR 0025](../decisions/0025-webhook-forgejo.md),
[ADR 0035](../decisions/0035-webhook-delivery-persistence.md). The webhook domain is `[webhook] domain` in
`weglarka.toml` ([Host configuration](../install.md#host-configuration)).

## GitHub webhook (auto-update)

The HMAC is per app ([ADR 0004](../decisions/0004-webhook-github.md)). The same string goes to Węglarka and to GitHub:

```sh
openssl rand -hex 32 > hmac.txt
weglarka secrets set ntfy webhook-hmac --from-file hmac.txt
cat hmac.txt          # paste into the Secret field on GitHub, then: rm hmac.txt
```

Repository `jpalczewski/ntfy.zig` → Settings → Webhooks → Add webhook:

| Field | Value |
|---|---|
| Payload URL | `https://weglarka.example.com/webhook/github/ntfy` (`<webhook.domain>/webhook/github/<instance>`) |
| Content type | `application/json` |
| Secret | the contents of `hmac.txt` |
| Events | *Let me select individual events* → only **Registry packages** (`registry_package`/`package`, action `published`) |

After the first push check *Recent Deliveries*: `latest` → **202**, `sha-…` → 204 (the app tracks `:latest`); 401 =
wrong secret, 204 for `latest` = mismatched image name. The payload field names are not yet confirmed on a real push
([ADR 0004](../decisions/0004-webhook-github.md)) — the first delivery is a test as well.

### Redelivery after a restart

Delivery ids (`X-GitHub-Delivery`, and `X-Forgejo-Delivery` for Forgejo) are stored in
`<state dir>/webhook-deliveries.toml` (0600, at most 256 entries, the oldest drop out), so a repeat of the same event
after a restart, a self-update or a host reboot ends with **202** and does no pull or deploy. The file is only
bookkeeping: it can be safely deleted (dedup starts from zero), it is not versioned, and an older daemon ignores
it — a rollback needs no migration
([ADR 0035](../decisions/0035-webhook-delivery-persistence.md)).

## Forgejo webhook (private images)

The Forgejo adapter ([ADR 0025](../decisions/0025-webhook-forgejo.md)) handles the `package` event (`created`) for
images in Forgejo's container registry. Route: `<webhook.domain>/webhook/forgejo/<instance>`; the secret is as above
(`webhook-hmac`, per app).

1. **Registry from the config.** The payload does not contain the registry host, so give it in `weglarka.toml`:

   ```toml
   [webhook.forgejo]
   registry = "git.example.com"   # host[:port] only, no scheme or path
   ```

   Without this section the route answers 404. An older daemon will not start with this section
   (`deny_unknown_fields`) — remove it before a downgrade, just like `[notify]`.
2. **The app's image** is `<registry>/<org>/<name>:<tag>` (lowercase), e.g. `git.example.com/acme/shop:main`.
3. **The webhook in Forgejo** (repo or organization → Settings → Webhooks → Forgejo): URL as above, content type
   `application/json`, Secret = the `webhook-hmac` value, event **Package**.
4. **Pulling from the private registry** goes through the Podman user's `auth.json` (option (a) of
   [ADR 0025](../decisions/0025-webhook-forgejo.md)). Log in once as the user running Podman, with a service account
   whose token can only read packages:

   ```sh
   podman login git.example.com     # service account login + a read:package token
   ```

   The token lives in `auth.json` on the host, outside Węglarka's secret store. Alternatively, store the credentials
   as the app's `registry-auth` secret ([Your first app](first-app.md)). When the registry rejects the pull
   (401/403), the deploy ends with a registry-auth error naming the instance and image
   (`registry requires credentials to pull <image>; set them with weglarka secrets set <instance> registry-auth
   (value <username>:<password>) or podman login as the podman user`; when a `registry-auth` secret was sent:
   `registry rejected the credentials in secret <instance>.registry-auth for <image>; …`), not "image not found".
5. **Deliveries:** pushing `main` + `sha-<commit>` gives 202 for `main` and 204 for `sha-…` (the app tracks `:main`).
   The payload field names, and whether re-pushing a moving tag sends `package.created`, are not yet confirmed on a
   real instance — if it does not, #83 is needed.
