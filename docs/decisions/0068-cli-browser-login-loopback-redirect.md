# 0068 — `weglarka login --browser`: authorization code flow on a loopback redirect

Status: accepted (2026-11-04, issue #338, #294). Completes ADR 0060, decision 6.

## Problem

ADR 0060 ships `weglarka login` with the device grant and defers a browser flow for workstations: the authorization code
flow with PKCE and an RFC 8252 loopback redirect. It rejected that flow first because the provider must accept a redirect
URI whose port is chosen at run time, "unverified against Authelia (#294)". Registering the wrong shape would make every
`--browser` login fail with `invalid_request`, and the answer decides what the client registration looks like.

## Finding: how Authelia matches a loopback redirect URI

The pinned image (`AUTHELIA_IMAGE` in `.github/workflows/ci.yml`) is Authelia 4.39.22. Its `go.mod` requires
`authelia.com/provider/oauth2 v0.3.0` ([go.mod](https://github.com/authelia/authelia/blob/v4.39.22/go.mod)), which does the
redirect matching. In that module `IsMatchingRedirectURI` falls back to `isMatchingLoopbackURI`
([uri.go at v0.3.0](https://github.com/authelia/oauth2-provider/blob/v0.3.0/uri.go)): when the requested and the registered
URI both use scheme `http` and a loopback IP literal, the host literals are equal (`127.0.0.1` is not `[::1]`), and path and
query are equal, **the port is ignored**. This is RFC 8252 section 7.3. `localhost` is not a loopback IP literal for this
rule, so it only matches exactly. Authelia's client documentation
([clients](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/)) says nothing about loopback
or ports, so the behaviour rests on the library source of the pinned version, not on documented configuration. A
`public = true` client with PKCE is what the library treats as a native client.

Branch (a) is therefore chosen: register `http://127.0.0.1/callback`, bind `127.0.0.1:0`, send the bound port in the
request's `redirect_uri`. A test in the `identity-config` CI job validates that Authelia's own validator accepts such a
registration; an end-to-end login against Authelia is not covered (as for #294, which stays open for the panel).

## Decision

1. **Model.** `redirect_uris` may hold `http://127.0.0.1[:port]/...` or `http://[::1][:port]/...` only for a
   `public = true` client. `localhost` (RFC 8252 section 8.3) and any other `http://` stay refused; length, fragment and
   userinfo rules are unchanged. The field exists, so `SCHEMA_VERSION` and `spec_hash` do not change, and the rendered
   file of every existing client is byte-identical (snapshot test). Loopback entries are exempt from "host is one of the
   app's domains" because they never name a host.
2. **`weglarka login --browser`.** After `resolve_target` and the discovery (as for the device flow), the CLI binds
   `127.0.0.1:0`, builds the authorization URL (PKCE S256, `state`, `nonce`) with `weglarka_oidc::begin_code_flow`, opens it
   with `open`/`xdg-open` (best effort, always prints the URL on stderr), waits for the callback, exchanges the code with
   `ClientAuth::Public` and stores the session as the device flow does. The access token stays opaque to the CLI
   (ADR 0060); `nonce` is sent but the id token is not verified.
3. **Listener.** A hyper http1 server bound to `127.0.0.1` only, serving `GET /callback` (everything else is 404 and the
   wait goes on). Every callback is compared with `state` first, including one carrying `error`. A mismatch answers 400,
   prints a note and **keeps waiting**: any local process can hit the port, so a counter or an abort would let it kill the
   login; the whole wait ends after 5 minutes. Only a matching `state` ends it: `error` is reported as "denied" without
   echoing `error_description`, `code` goes to the exchange. The response is a static page with `Cache-Control: no-store`
   that echoes nothing, and the listener closes right after.
4. **Provider refusal.** `invalid_request` from the provider now hints at a missing loopback `redirect_uri` in the client
   registration as well as `device_flow`.

## Consequences

- Operators add `http://127.0.0.1/callback` to the CLI client's `redirect_uris` (`docs/guides/remote-cli.md`,
  `docs/guides/identity-provider.md`). Without it `--browser` fails with the hint; the device flow is unaffected.
- A local process that wins the race for the port cannot complete the login: it lacks `state` and the PKCE verifier, and
  the code it could steal is useless without the verifier. It can only delay until the timeout.
- Other providers may require an exact port match; they would need a fixed port list, which this ADR does not add.
- Tests: `state` mismatch keeps waiting, `error` with a wrong `state` does not abort, timeout, 404 for other paths,
  loopback-only bind, a correct callback leads to the exchange with the right `redirect_uri` and `code_verifier`, model
  accept/refuse cases, unchanged render snapshot.

## Rejected alternatives

- **A fixed list of registered ports (the exact-match fallback):** needed only if the provider matches exactly; Authelia
  does not, and a fixed port can be occupied by anything.
- **`localhost` redirect:** RFC 8252 section 8.3 discourages it (name resolution, other listeners on `::1`).
- **Counting wrong-`state` attempts:** lets a local process abort the login.
- **A browser-opening crate (`open`, `webbrowser`):** a dependency for two `Command` calls.
