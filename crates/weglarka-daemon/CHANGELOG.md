# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/v0.0.4...v0.0.5) - 2026-10-29

### Added

- *(daemon)* certificates and host config view ([#286](https://github.com/jpalczewski/weglarka/pull/286))
- *(daemon)* app logs stream ([#287](https://github.com/jpalczewski/weglarka/pull/287))
- *(daemon)* recent events ([#256](https://github.com/jpalczewski/weglarka/pull/256))
- *(api)* redacted app view and runtime detail ([#252](https://github.com/jpalczewski/weglarka/pull/252))

### Fixed

- *(daemon)* logs stream review follow-ups ([#304](https://github.com/jpalczewski/weglarka/pull/304))
- *(daemon)* read view as an exhaustive projection ([#280](https://github.com/jpalczewski/weglarka/pull/280))
- *(daemon)* redact argv and failure text for read tokens

### Other

- *(model)* split JWT verification from access-token claims ([#261](https://github.com/jpalczewski/weglarka/pull/261))

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/v0.0.3...v0.0.4) - 2026-10-29

### Added

- *(daemon)* token admin API with read/admin scopes (ADR 0056) ([#246](https://github.com/jpalczewski/weglarka/pull/246))
- *(identity)* enforce forward-auth policy and groups with generated access rules ([#245](https://github.com/jpalczewski/weglarka/pull/245))
- *(identity)* wire OIDC clients and the provider into the daemon ([#239](https://github.com/jpalczewski/weglarka/pull/239))
- *(engine)* generated config pipeline (render, validate, apply) ([#238](https://github.com/jpalczewski/weglarka/pull/238))
- *(ingress)* forward auth via nginx auth_request in both modes ([#236](https://github.com/jpalczewski/weglarka/pull/236))
- *(model)* SecretOps and OIDC client credentials ([#229](https://github.com/jpalczewski/weglarka/pull/229))

### Fixed

- *(ingress)* health probe over a unix probe socket in both modes ([#231](https://github.com/jpalczewski/weglarka/pull/231))

### Other

- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))
- speed up dev builds and slim the dependency graph ([#218](https://github.com/jpalczewski/weglarka/pull/218))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/v0.0.2...v0.0.3) - 2026-10-26

### Added

- *(core)* sites with environments and promotion ([#206](https://github.com/jpalczewski/weglarka/pull/206))
- *(core)* serve static sites from unpacked OCI releases (#48, #101, #102) ([#184](https://github.com/jpalczewski/weglarka/pull/184))
- *(core)* allowlisted host mounts and group_add for log collectors ([#185](https://github.com/jpalczewski/weglarka/pull/185))
- *(daemon)* refresh the Cloudflare ranges from the API ([#172](https://github.com/jpalczewski/weglarka/pull/172))
- *(ingress)* trust the CDN's client address in edge mode ([ingress.cdn]) ([#171](https://github.com/jpalczewski/weglarka/pull/171))
- *(ingress)* keep the real client address in edge mode ([#166](https://github.com/jpalczewski/weglarka/pull/166))
- *(cli)* deploy a locally built image with weglarka push ([#163](https://github.com/jpalczewski/weglarka/pull/163))
- *(cli)* weglarka forward, a temporary port forward ([#165](https://github.com/jpalczewski/weglarka/pull/165))
- *(ingress)* serve wildcard certificates for the domains they cover ([#161](https://github.com/jpalczewski/weglarka/pull/161))
- *(daemon)* wildcard certificates over DNS-01 ([acme.dns]) ([#160](https://github.com/jpalczewski/weglarka/pull/160))
- one-off containers with `weglarka run` ([#157](https://github.com/jpalczewski/weglarka/pull/157))
- *(daemon)* run an ACME worker for edge certificates ([#154](https://github.com/jpalczewski/weglarka/pull/154))
- *(ingress)* edge mode with nginx owning 80/443 ([#146](https://github.com/jpalczewski/weglarka/pull/146))
- *(core)* persist webhook delivery dedup across restarts ([#145](https://github.com/jpalczewski/weglarka/pull/145))

### Fixed

- *(acme)* wait for DNS-01 records before asking the CA to validate ([#202](https://github.com/jpalczewski/weglarka/pull/202))
- *(daemon)* keep the edge forwarder across self-updates and log why nginx is recreated ([#194](https://github.com/jpalczewski/weglarka/pull/194))

### Other

- *(acme)* HTTP-01 behind the Cloudflare proxy and a doctor hint (acme.cdn) ([#175](https://github.com/jpalczewski/weglarka/pull/175))
- speed up cargo test with mold, nextest and a shorter dependency gate in tests ([#170](https://github.com/jpalczewski/weglarka/pull/170))
- translate the install guide to English and split it into topic guides ([#164](https://github.com/jpalczewski/weglarka/pull/164))
- *(daemon)* share the integration test harness and unflake the shared-network test ([#151](https://github.com/jpalczewski/weglarka/pull/151))

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/v0.0.1...v0.0.2) - 2026-10-24

### Added

- *(daemon)* automatic fallback to the previous daemon image ([#144](https://github.com/jpalczewski/weglarka/pull/144))
- *(ingress)* per-app request body limit (ingress.max_body_size) ([#141](https://github.com/jpalczewski/weglarka/pull/141))
- *(ingress)* path-prefix routing (several instances behind one domain)
- *(core)* shared networks between instances ([#137](https://github.com/jpalczewski/weglarka/pull/137))
- *(core)* more than one shared volume per app via volume groups ([#135](https://github.com/jpalczewski/weglarka/pull/135))
- config_root mounts and apps reload ([#121](https://github.com/jpalczewski/weglarka/pull/121))
- self-update Węglarka's own image with a verified digest ([#133](https://github.com/jpalczewski/weglarka/pull/133))
- *(podman)* send per-app registry credentials as X-Registry-Auth on pull ([#134](https://github.com/jpalczewski/weglarka/pull/134))
- *(daemon)* add a Forgejo webhook adapter ([#132](https://github.com/jpalczewski/weglarka/pull/132))
- *(cli)* secrets remove and apps remove --purge-secrets ([#122](https://github.com/jpalczewski/weglarka/pull/122))
- *(core)* version the state files and refuse a newer schema at startup ([#127](https://github.com/jpalczewski/weglarka/pull/127))
- *(core)* detect crash-looping and unhealthy apps ([#120](https://github.com/jpalczewski/weglarka/pull/120))
- notify deploys and rollbacks through ntfy ([#115](https://github.com/jpalczewski/weglarka/pull/115))
- *(core)* keep only the current and previous image per app ([#116](https://github.com/jpalczewski/weglarka/pull/116))
- *(core)* per-app container command (arguments to the image entrypoint) ([#84](https://github.com/jpalczewski/weglarka/pull/84))
- *(ingress)* per-app streaming support (proxy_buffering off, longer read timeout) ([#72](https://github.com/jpalczewski/weglarka/pull/72))
- share volumes between instances ([#66](https://github.com/jpalczewski/weglarka/pull/66))
- *(core)* order app starts with depends_on and gate on healthy dependencies ([#65](https://github.com/jpalczewski/weglarka/pull/65))

### Fixed

- *(ingress)* trust nginx's own addresses as the port forwarder's source ([#140](https://github.com/jpalczewski/weglarka/pull/140))
- *(daemon)* read the Forgejo event name from X-Forgejo-Event-Type ([#139](https://github.com/jpalczewski/weglarka/pull/139))
- *(core)* keep the uid-range guard when the container is gone ([#126](https://github.com/jpalczewski/weglarka/pull/126))
- *(core)* parse image repositories with one shared helper ([#124](https://github.com/jpalczewski/weglarka/pull/124))

### Other

- version and changelog each crate independently with release-plz ([#68](https://github.com/jpalczewski/weglarka/pull/68))
