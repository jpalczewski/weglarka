# Secrets: removal and cleanup

Secrets are stored per instance, in the scope `<app>.<name>` in `secrets.toml` (0600). Nothing used to remove them: `apps remove` deleted the app, but its secrets, including `webhook-hmac`, stayed behind. The file kept growing, and **a new app under an old name inherited the old values** (for example an old `webhook-hmac` that no longer matches the webhook in GitHub). Decision and rejected alternatives: [ADR 0024](../decisions/0024-secret-removal-and-purge.md).

## Removing a single secret

```sh
weglarka secrets list ntfy                     # names, fingerprint, date; no values
weglarka secrets remove ntfy config            # 409 while the app spec still binds this secret
weglarka secrets remove ntfy config --force    # removes despite the binding; the app waits for a secret
weglarka secrets remove ntfy config --dry-run  # shows what it would remove
```

- **409 by default:** while the app spec binds the secret (`--secret-env`/`--secret-mount`), removal is rejected, because an app without the value would never start. Unbind it first (`weglarka apps update ntfy --unbind-secret config`) or use `--force`.
- **`--force`:** the value disappears, and on the next reconcile the app goes into the waiting-for-a-secret state (status `waiting-for-secret`; see [first app](first-app.md)). This is not an error: the deploy waits for `secrets set`. A running container keeps the materialized value until its next recreation; the removal itself does **not** trigger a deploy.
- **404** when there is no such secret; **400** for an invalid app or secret name.
- **The app does not have to exist in `apps.toml`.** That is the point of this endpoint: it cleans up leftovers of a removed app and **of an instance rename** (the old scope `<old-name>.*` stays in the file until you remove it).

## Removing an app's whole scope

```sh
weglarka apps remove ntfy --purge-secrets                  # the app + all its secrets
weglarka apps remove ntfy --purge-secrets --purge-volumes  # + volumes (data)
```

- Removes the **whole** scope `<app>.*`, including `webhook-hmac`. `--purge-secrets` and `--purge-volumes` are independent: by default data survives `remove` + `add`, and credentials need not be kept just because the data stays.
- The purge happens **before** `apps.toml` is written: if it fails, the app stays registered and you can retry.
- Works only for an app that is present in `apps.toml`; afterwards use `secrets remove` (above).
- Does not touch **materialized Podman secrets**: those are created from the store on every deploy and remain after the app is removed until a separate cleanup (a known gap, described in ADR 0024).

## Leftovers: the doctor warning

The `state.orphan_secrets` check reports a `warn` with the list of secrets whose instance is no longer in `apps.toml`, with a hint (`weglarka secrets remove <app> <name>`; for the next removal, `apps remove --purge-secrets`). When everything is clean, the check is absent. The warning blocks nothing: leftover secrets do not break anything, they are a hygiene and security problem.

## Compatibility

The format of `secrets.toml`/`apps.toml`/`state.toml` is unchanged, so upgrading and rolling back the daemon are safe, and removing a secret changes neither the spec nor the `spec_hash` (only the value changes, not the binding). The file is still written atomically with 0600 permissions. A new CLI against **an older daemon** silently ignores `--purge-secrets` (the app is removed, the secrets stay) and gets 404 on `secrets remove`, so update the daemon first.

## Reserved names

`oidc-client-secret` and `oidc-client-digest` are minted as a pair by Węglarka (OIDC client credentials,
issue #213) and cannot be set or removed with `weglarka secrets set` / `secrets remove`; the API answers 400 and
points to `weglarka oidc rotate` (arrives with the identity rollout). `apps remove --purge-secrets` still clears
both, because it removes the whole `<app>.*` scope. `secrets list` shows them like any other secret (metadata only).
