# Decyzje implementacyjne (ADR)

Każda decyzja opisuje problem, wybór, konsekwencje i odrzucone alternatywy. Nowe wpisy numerujemy kolejno
(po `0011` następny jest `0012`); szkielet: [`0000-template.md`](0000-template.md).

| # | Temat |
|---|---|
| [0001](0001-async-traits.md) | Async w traitach: natywne `async fn` + generyki, bez `async-trait` |
| [0002](0002-podman-in-ci.md) | Podman 6.1 w testach integracyjnych: instalacja z OBS, job `integration-podman` |
| [0003](0003-state-toml.md) | Stan runtime w osobnym `state.toml` (atomowy zapis, walidacja) |
| [0004](0004-webhook-github.md) | Webhooki GitHub: zdarzenia, HMAC per apka, `202` od razu, dedup dostarczeń |
| [0005](0005-ingress-i-platforma.md) | Ingress w demonie: przeładowanie nginxa, plik Traefika, quadlet |
| [0006](0006-pakowanie-obrazy-i-release.md) | Pakowanie: obraz na `scratch`, oficjalny nginx, release na GHCR |
| [0007](0007-zaufane-proxy-i-reload-nginx.md) | Trusted proxies za rootless Podmanem, reload zamiast recreate |
| [0008](0008-ci-speed-prebuilt-binaries.md) | CI speed: prebuilt binarki, profil `ci`, bez stosu regex |
| [0009](0009-volume-ownership.md) | Własność plików w wolumenach: zakresy UID per instancja |
| [0010](0010-health-http-probe.md) | `health.http` przez nginx, limity zasobów, `health.command` |
| [0011](0011-start-false-provisioning.md) | `start = false`: provisioning bez startu, import przed pierwszym startem |
