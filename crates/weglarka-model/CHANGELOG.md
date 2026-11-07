# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.8](https://github.com/jpalczewski/weglarka/compare/weglarka-model-v0.0.7...weglarka-model-v0.0.8) - 2026-11-07

### Added

- *(model)* basic auth fields, credential parser and schema v25 ([#640](https://github.com/jpalczewski/weglarka/pull/640))
- *(model)* host credential sources and a host-scoped secret store
- *(model)* shared service rules by contract name
- *(model)* shared service rules, overlay and per-kind gate (skeleton)
- *(model)* Redis ACL SHA-256 and SCRAM-SHA-256 digests in SecretOps
- *(model)* digest kinds for SecretOps (skeleton)
- *(model)* shared service types, membership and identity session store behind a gate ([#621](https://github.com/jpalczewski/weglarka/pull/621))
- *(ingress)* allow auth_exempt_paths on apps routed by paths ([#614](https://github.com/jpalczewski/weglarka/pull/614))
- *(ingress)* render oauth_resources and their discovery routes ([#613](https://github.com/jpalczewski/weglarka/pull/613))
- *(model)* oauth_resources field behind a gate ([#609](https://github.com/jpalczewski/weglarka/pull/609))
- *(acme)* prefer_wildcard serves covered domains with the wildcard ([#604](https://github.com/jpalczewski/weglarka/pull/604))
- *(ingress)* shared certificate choice with an optional wildcard preference ([#600](https://github.com/jpalczewski/weglarka/pull/600))
- *(engine)* mount ingress logs read-only into the configured reader ([#587](https://github.com/jpalczewski/weglarka/pull/587))
- *(ingress)* security headers for container apps ([#574](https://github.com/jpalczewski/weglarka/pull/574))
- *(daemon)* group-readable ingress log directory ([#573](https://github.com/jpalczewski/weglarka/pull/573))
- *(model)* site-level static options and a robots preset ([#570](https://github.com/jpalczewski/weglarka/pull/570))
- *(engine)* explicit log driver and size bound for containers ([#557](https://github.com/jpalczewski/weglarka/pull/557))

### Fixed

- *(model)* case-sensitive basic auth map keys
- *(model)* a host secret that is not set yet does not stop the startup
- *(daemon)* record a host config the host binaries cannot parse ([#619](https://github.com/jpalczewski/weglarka/pull/619))
- *(daemon)* the self-update switcher reads only the state schema header ([#618](https://github.com/jpalczewski/weglarka/pull/618))
- *(daemon)* report a served static site as serving, not missing ([#569](https://github.com/jpalczewski/weglarka/pull/569))
- *(daemon)* validate the candidate apps.toml once for add, update and sites ([#564](https://github.com/jpalczewski/weglarka/pull/564))

### Other

- *(model)* extract the line diff from the CLI spec diff
- renumber the host credentials ADR to 0080 after the 0079 collision
- Merge pull request #635 from jpalczewski/feat/591-service-digests
- *(model)* one private-file check and one header-token validator ([#623](https://github.com/jpalczewski/weglarka/pull/623))
- *(model)* check SCRAM verifiers against postgres-protocol
- *(model)* independent known answers for the service digests
- *(engine)* dedupe volume refs, uid ranges and name validation ([#626](https://github.com/jpalczewski/weglarka/pull/626))
- *(podman)* deduplicate the Podman client, filters and test helpers ([#625](https://github.com/jpalczewski/weglarka/pull/625))
- *(model)* one module for the ingress log layout and retention helpers ([#558](https://github.com/jpalczewski/weglarka/pull/558))

## [0.0.7](https://github.com/jpalczewski/weglarka/compare/weglarka-model-v0.0.6...weglarka-model-v0.0.7) - 2026-11-05

### Added

- *(engine)* site release store, configurable extraction limits and sites doctor checks ([#541](https://github.com/jpalczewski/weglarka/pull/541))
- *(engine)* internal_hosts maps served domains to Podman's host-gateway ([#532](https://github.com/jpalczewski/weglarka/pull/532))
- *(daemon)* report containers whose conmon died ([#537](https://github.com/jpalczewski/weglarka/pull/537))
- *(ingress)* retain ingress logs for a configurable number of days
- static sites — per-site rendering options ([#104](https://github.com/jpalczewski/weglarka/pull/104)) ([#500](https://github.com/jpalczewski/weglarka/pull/500))
- *(cli)* weglarka login --browser ([#496](https://github.com/jpalczewski/weglarka/pull/496))
- *(cli)* discover the issuer and audience from the host ([#495](https://github.com/jpalczewski/weglarka/pull/495))
- *(engine)* add image provenance and retention ([#471](https://github.com/jpalczewski/weglarka/pull/471))
- *(platform)* add platform update v1 shared contracts and parser ([#465](https://github.com/jpalczewski/weglarka/pull/465))
- *(identity)* gate an OIDC client on groups through Authelia authorization policies ([#456](https://github.com/jpalczewski/weglarka/pull/456))

### Fixed

- *(daemon)* record and report a switcher stopped by a newer state schema ([#536](https://github.com/jpalczewski/weglarka/pull/536))
- *(daemon)* detect a user manager that misses a newly added group ([#538](https://github.com/jpalczewski/weglarka/pull/538))

### Other

- *(podman)* one contract suite for LibpodClient and FakePodman ([#524](https://github.com/jpalczewski/weglarka/pull/524))
- *(launcher)* skip rehashing unchanged generation binaries ([#513](https://github.com/jpalczewski/weglarka/pull/513))
- *(model)* bounded state-file serialization and batched inventory writes ([#507](https://github.com/jpalczewski/weglarka/pull/507))

## [0.0.6](https://github.com/jpalczewski/weglarka/compare/weglarka-model-v0.0.5...weglarka-model-v0.0.6) - 2026-10-31

### Added

- *(daemon)* generated Prometheus file_sd targets ([#398](https://github.com/jpalczewski/weglarka/pull/398))
- *(daemon)* doctor identity.base_config warns about replaced sections ([#390](https://github.com/jpalczewski/weglarka/pull/390))
- *(engine)* connect the metrics scraper to the metrics networks ([#397](https://github.com/jpalczewski/weglarka/pull/397))
- *(cli)* expose a stored secret to one run with run --secret ([#396](https://github.com/jpalczewski/weglarka/pull/396))
- *(engine)* metrics_port and a per-app metrics network ([#383](https://github.com/jpalczewski/weglarka/pull/383))
- *(api)* host-wide volume listing and a limit on GET /v1/events ([#384](https://github.com/jpalczewski/weglarka/pull/384))
- *(daemon)* host metrics from the daemon without mounts ([#362](https://github.com/jpalczewski/weglarka/pull/362))
- *(daemon)* per-app resource metrics labelled with the instance name ([#357](https://github.com/jpalczewski/weglarka/pull/357))
- *(daemon)* optional /metrics listener on a dedicated network ([#354](https://github.com/jpalczewski/weglarka/pull/354))
- *(daemon)* report container memory use in doctor ([#348](https://github.com/jpalczewski/weglarka/pull/348))
- *(cli)* sign in to a remote host with the device grant and reach it through the panel relay ([#335](https://github.com/jpalczewski/weglarka/pull/335))

### Fixed

- *(engine)* remove generated config of a removed consumer ([#403](https://github.com/jpalczewski/weglarka/pull/403))
- *(daemon)* make OIDC secret rotation atomic ([#389](https://github.com/jpalczewski/weglarka/pull/389))
- *(model)* reject a huge exp as Malformed on purpose and test it ([#375](https://github.com/jpalczewski/weglarka/pull/375))

### Other

- *(model)* add ContainerSpec::new ([#427](https://github.com/jpalczewski/weglarka/pull/427))
- *(engine)* add not-found helpers for libpod results ([#425](https://github.com/jpalczewski/weglarka/pull/425))
- *(model)* move human_bytes to weglarka-model ([#422](https://github.com/jpalczewski/weglarka/pull/422))
- *(model)* pin malformed azp and nonce in id tokens ([#393](https://github.com/jpalczewski/weglarka/pull/393))
- *(model)* take an id token's audience from the client id in verify ([#382](https://github.com/jpalczewski/weglarka/pull/382))

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-model-v0.0.4...weglarka-model-v0.0.5) - 2026-10-29

### Added

- *(daemon)* app logs stream ([#287](https://github.com/jpalczewski/weglarka/pull/287))
- *(daemon)* recent events ([#256](https://github.com/jpalczewski/weglarka/pull/256))
- *(api)* redacted app view and runtime detail ([#252](https://github.com/jpalczewski/weglarka/pull/252))

### Fixed

- *(daemon)* logs stream review follow-ups ([#304](https://github.com/jpalczewski/weglarka/pull/304))

### Other

- *(model)* typed token kinds and structural id-token checks
- *(model)* split JWT verification from access-token claims ([#261](https://github.com/jpalczewski/weglarka/pull/261))

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-model-v0.0.3...weglarka-model-v0.0.4) - 2026-10-29

### Added

- *(daemon)* token admin API with read/admin scopes (ADR 0056) ([#246](https://github.com/jpalczewski/weglarka/pull/246))
- *(identity)* enforce forward-auth policy and groups with generated access rules ([#245](https://github.com/jpalczewski/weglarka/pull/245))
- *(identity)* wire OIDC clients and the provider into the daemon ([#239](https://github.com/jpalczewski/weglarka/pull/239))
- *(engine)* generated config pipeline (render, validate, apply) ([#238](https://github.com/jpalczewski/weglarka/pull/238))
- *(identity)* pure renderers for Authelia OIDC clients and access control ([#233](https://github.com/jpalczewski/weglarka/pull/233))
- *(ingress)* forward auth via nginx auth_request in both modes ([#236](https://github.com/jpalczewski/weglarka/pull/236))
- *(model)* SecretOps and OIDC client credentials ([#229](https://github.com/jpalczewski/weglarka/pull/229))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-core-v0.0.2...weglarka-core-v0.0.3) - 2026-10-26

### Added

- *(core)* sites with environments and promotion ([#206](https://github.com/jpalczewski/weglarka/pull/206))
- *(core)* serve static sites from unpacked OCI releases (#48, #101, #102) ([#184](https://github.com/jpalczewski/weglarka/pull/184))
- *(ingress)* per-app streaming_paths with a long read timeout ([#180](https://github.com/jpalczewski/weglarka/pull/180)) ([#188](https://github.com/jpalczewski/weglarka/pull/188))
- *(ingress)* access_log_skip_paths for noisy poll endpoints ([#189](https://github.com/jpalczewski/weglarka/pull/189))
- *(core)* [**breaking**] blue-green deploys for stateless apps ([#186](https://github.com/jpalczewski/weglarka/pull/186))
- *(core)* allowlisted host mounts and group_add for log collectors ([#185](https://github.com/jpalczewski/weglarka/pull/185))
- *(ingress)* trust the CDN's client address in edge mode ([ingress.cdn]) ([#171](https://github.com/jpalczewski/weglarka/pull/171))
- *(cli)* deploy a locally built image with weglarka push ([#163](https://github.com/jpalczewski/weglarka/pull/163))
- *(cli)* weglarka forward, a temporary port forward ([#165](https://github.com/jpalczewski/weglarka/pull/165))
- *(ingress)* serve wildcard certificates for the domains they cover ([#161](https://github.com/jpalczewski/weglarka/pull/161))
- *(daemon)* wildcard certificates over DNS-01 ([acme.dns]) ([#160](https://github.com/jpalczewski/weglarka/pull/160))
- one-off containers with `weglarka run` ([#157](https://github.com/jpalczewski/weglarka/pull/157))
- *(daemon)* run an ACME worker for edge certificates ([#154](https://github.com/jpalczewski/weglarka/pull/154))
- *(core)* uid/gid for mounted secrets ([#150](https://github.com/jpalczewski/weglarka/pull/150))
- *(cli)* detach private and shared volumes from an app spec ([#149](https://github.com/jpalczewski/weglarka/pull/149))
- *(ingress)* edge mode with nginx owning 80/443 ([#146](https://github.com/jpalczewski/weglarka/pull/146))
- *(core)* persist webhook delivery dedup across restarts ([#145](https://github.com/jpalczewski/weglarka/pull/145))

### Fixed

- *(acme)* wait for DNS-01 records before asking the CA to validate ([#202](https://github.com/jpalczewski/weglarka/pull/202))

### Other

- speed up cargo test with mold, nextest and a shorter dependency gate in tests ([#170](https://github.com/jpalczewski/weglarka/pull/170))
- translate the install guide to English and split it into topic guides ([#164](https://github.com/jpalczewski/weglarka/pull/164))

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/weglarka-core-v0.0.1...weglarka-core-v0.0.2) - 2026-10-24

### Added

- *(daemon)* automatic fallback to the previous daemon image ([#144](https://github.com/jpalczewski/weglarka/pull/144))
- *(core)* supervision decision for automatic self-update fallback ([#143](https://github.com/jpalczewski/weglarka/pull/143))
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
- *(core)* keep the uid-range guard when the container is gone ([#126](https://github.com/jpalczewski/weglarka/pull/126))
- *(core)* parse image repositories with one shared helper ([#124](https://github.com/jpalczewski/weglarka/pull/124))

### Other

- version and changelog each crate independently with release-plz ([#68](https://github.com/jpalczewski/weglarka/pull/68))
