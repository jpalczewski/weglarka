# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/jpalczewski/weglarka/compare/weglarka-cli-v0.1.0...weglarka-cli-v0.1.1) - 2026-10-31

### Added

- *(cli)* show container resource usage with weglarka stats ([#431](https://github.com/jpalczewski/weglarka/pull/431))
- *(engine)* connect the metrics scraper to the metrics networks ([#397](https://github.com/jpalczewski/weglarka/pull/397))
- *(cli)* expose a stored secret to one run with run --secret ([#396](https://github.com/jpalczewski/weglarka/pull/396))
- *(cli)* apps update/start/stop --wait for the reconcile ([#395](https://github.com/jpalczewski/weglarka/pull/395))
- *(cli)* secrets set --env-file for many secrets at once ([#386](https://github.com/jpalczewski/weglarka/pull/386))
- *(cli)* apps diff and env-removal markers for apps update --spec ([#377](https://github.com/jpalczewski/weglarka/pull/377))
- *(cli)* document and test apps update --spec - (stdin), share the spec reader with apps add ([#374](https://github.com/jpalczewski/weglarka/pull/374))
- *(engine)* metrics_port and a per-app metrics network ([#383](https://github.com/jpalczewski/weglarka/pull/383))
- *(daemon)* host metrics from the daemon without mounts ([#362](https://github.com/jpalczewski/weglarka/pull/362))
- *(daemon)* stream an app's access log ([#355](https://github.com/jpalczewski/weglarka/pull/355))
- *(cli)* stream logs of one or many apps ([#346](https://github.com/jpalczewski/weglarka/pull/346))

### Fixed

- *(cli)* let an explicit --host beat WEGLARKA_SOCKET ([#380](https://github.com/jpalczewski/weglarka/pull/380))
- *(cli)* let apps update --spec run against a redacted view ([#372](https://github.com/jpalczewski/weglarka/pull/372))
- *(cli)* rename the access domain filter so it stops shadowing --host ([#361](https://github.com/jpalczewski/weglarka/pull/361))
- *(cli)* keep log history across a token renewal ([#359](https://github.com/jpalczewski/weglarka/pull/359))
- *(cli)* verify cgroup delegation instead of assuming it ([#347](https://github.com/jpalczewski/weglarka/pull/347))

### Other

- *(api)* share the unsafe-character set for untrusted stream text ([#429](https://github.com/jpalczewski/weglarka/pull/429))
- *(cli)* reuse the model's secret-name and mount-target rules ([#426](https://github.com/jpalczewski/weglarka/pull/426))
- *(api)* add DoctorCheck constructors ([#423](https://github.com/jpalczewski/weglarka/pull/423))
- *(model)* move human_bytes to weglarka-model ([#422](https://github.com/jpalczewski/weglarka/pull/422))

## [0.0.6](https://github.com/jpalczewski/weglarka/compare/weglarka-cli-v0.0.5...weglarka-cli-v0.0.6) - 2026-10-30

### Other

- updated the following local packages: weglarka-api

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-cli-v0.0.4...weglarka-cli-v0.0.5) - 2026-10-29

### Added

- *(daemon)* app logs stream ([#287](https://github.com/jpalczewski/weglarka/pull/287))
- *(api)* redacted app view and runtime detail ([#252](https://github.com/jpalczewski/weglarka/pull/252))

### Fixed

- *(daemon)* read view as an exhaustive projection ([#280](https://github.com/jpalczewski/weglarka/pull/280))

### Other

- *(cli)* extract the unix-socket HTTP client ([#250](https://github.com/jpalczewski/weglarka/pull/250))

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-cli-v0.0.3...weglarka-cli-v0.0.4) - 2026-10-29

### Added

- *(daemon)* token admin API with read/admin scopes (ADR 0056) ([#246](https://github.com/jpalczewski/weglarka/pull/246))
- *(identity)* wire OIDC clients and the provider into the daemon ([#239](https://github.com/jpalczewski/weglarka/pull/239))
- *(core)* identity provider types behind a disabled gate ([#226](https://github.com/jpalczewski/weglarka/pull/226))

### Other

- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-cli-v0.0.2...weglarka-cli-v0.0.3) - 2026-10-26

### Added

- *(core)* sites with environments and promotion ([#206](https://github.com/jpalczewski/weglarka/pull/206))
- *(core)* serve static sites from unpacked OCI releases (#48, #101, #102) ([#184](https://github.com/jpalczewski/weglarka/pull/184))
- *(ingress)* per-app streaming_paths with a long read timeout ([#180](https://github.com/jpalczewski/weglarka/pull/180)) ([#188](https://github.com/jpalczewski/weglarka/pull/188))
- *(ingress)* access_log_skip_paths for noisy poll endpoints ([#189](https://github.com/jpalczewski/weglarka/pull/189))
- *(core)* [**breaking**] blue-green deploys for stateless apps ([#186](https://github.com/jpalczewski/weglarka/pull/186))
- *(core)* allowlisted host mounts and group_add for log collectors ([#185](https://github.com/jpalczewski/weglarka/pull/185))
- *(cli)* deploy a locally built image with weglarka push ([#163](https://github.com/jpalczewski/weglarka/pull/163))
- *(cli)* weglarka forward, a temporary port forward ([#165](https://github.com/jpalczewski/weglarka/pull/165))
- *(ingress)* serve wildcard certificates for the domains they cover ([#161](https://github.com/jpalczewski/weglarka/pull/161))
- one-off containers with `weglarka run` ([#157](https://github.com/jpalczewski/weglarka/pull/157))
- *(daemon)* run an ACME worker for edge certificates ([#154](https://github.com/jpalczewski/weglarka/pull/154))
- *(core)* uid/gid for mounted secrets ([#150](https://github.com/jpalczewski/weglarka/pull/150))
- *(cli)* detach private and shared volumes from an app spec ([#149](https://github.com/jpalczewski/weglarka/pull/149))
- *(ingress)* edge mode with nginx owning 80/443 ([#146](https://github.com/jpalczewski/weglarka/pull/146))

### Other

- translate the install guide to English and split it into topic guides ([#164](https://github.com/jpalczewski/weglarka/pull/164))

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/weglarka-cli-v0.0.1...weglarka-cli-v0.0.2) - 2026-10-24

### Added

- *(ingress)* per-app request body limit (ingress.max_body_size) ([#141](https://github.com/jpalczewski/weglarka/pull/141))
- *(ingress)* path-prefix routing (several instances behind one domain)
- *(core)* shared networks between instances ([#137](https://github.com/jpalczewski/weglarka/pull/137))
- *(core)* more than one shared volume per app via volume groups ([#135](https://github.com/jpalczewski/weglarka/pull/135))
- config_root mounts and apps reload ([#121](https://github.com/jpalczewski/weglarka/pull/121))
- *(cli)* secrets remove and apps remove --purge-secrets ([#122](https://github.com/jpalczewski/weglarka/pull/122))
- *(core)* version the state files and refuse a newer schema at startup ([#127](https://github.com/jpalczewski/weglarka/pull/127))
- notify deploys and rollbacks through ntfy ([#115](https://github.com/jpalczewski/weglarka/pull/115))
- *(core)* keep only the current and previous image per app ([#116](https://github.com/jpalczewski/weglarka/pull/116))
- *(core)* per-app container command (arguments to the image entrypoint) ([#84](https://github.com/jpalczewski/weglarka/pull/84))
- *(ingress)* per-app streaming support (proxy_buffering off, longer read timeout) ([#72](https://github.com/jpalczewski/weglarka/pull/72))
- share volumes between instances ([#66](https://github.com/jpalczewski/weglarka/pull/66))
- *(core)* order app starts with depends_on and gate on healthy dependencies ([#65](https://github.com/jpalczewski/weglarka/pull/65))

### Fixed

- *(cli)* include purge_volumes in the apps remove dry run ([#125](https://github.com/jpalczewski/weglarka/pull/125))
- *(cli)* validate volume names before they reach the URL path ([#123](https://github.com/jpalczewski/weglarka/pull/123))

### Other

- version and changelog each crate independently with release-plz ([#68](https://github.com/jpalczewski/weglarka/pull/68))
