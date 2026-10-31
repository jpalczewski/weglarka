# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.6](https://github.com/jpalczewski/weglarka/compare/weglarka-ingress-v0.0.5...weglarka-ingress-v0.0.6) - 2026-10-31

### Added

- *(engine)* metrics_port and a per-app metrics network ([#383](https://github.com/jpalczewski/weglarka/pull/383))
- *(daemon)* stream an app's access log ([#355](https://github.com/jpalczewski/weglarka/pull/355))
- *(cli)* sign in to a remote host with the device grant and reach it through the panel relay ([#335](https://github.com/jpalczewski/weglarka/pull/335))

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-ingress-v0.0.4...weglarka-ingress-v0.0.5) - 2026-10-30

### Fixed

- *(ingress)* let the probe socket announce https to the identity provider ([#322](https://github.com/jpalczewski/weglarka/pull/322))

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-ingress-v0.0.3...weglarka-ingress-v0.0.4) - 2026-10-29

### Added

- *(identity)* enforce forward-auth policy and groups with generated access rules ([#245](https://github.com/jpalczewski/weglarka/pull/245))
- *(ingress)* forward auth via nginx auth_request in both modes ([#236](https://github.com/jpalczewski/weglarka/pull/236))
- *(core)* identity provider types behind a disabled gate ([#226](https://github.com/jpalczewski/weglarka/pull/226))

### Fixed

- *(ingress)* health probe over a unix probe socket in both modes ([#231](https://github.com/jpalczewski/weglarka/pull/231))

### Other

- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-ingress-v0.0.2...weglarka-ingress-v0.0.3) - 2026-10-26

### Added

- *(core)* sites with environments and promotion ([#206](https://github.com/jpalczewski/weglarka/pull/206))
- *(core)* serve static sites from unpacked OCI releases (#48, #101, #102) ([#184](https://github.com/jpalczewski/weglarka/pull/184))
- *(ingress)* per-app streaming_paths with a long read timeout ([#180](https://github.com/jpalczewski/weglarka/pull/180)) ([#188](https://github.com/jpalczewski/weglarka/pull/188))
- *(ingress)* access_log_skip_paths for noisy poll endpoints ([#189](https://github.com/jpalczewski/weglarka/pull/189))
- *(core)* [**breaking**] blue-green deploys for stateless apps ([#186](https://github.com/jpalczewski/weglarka/pull/186))
- *(core)* allowlisted host mounts and group_add for log collectors ([#185](https://github.com/jpalczewski/weglarka/pull/185))
- *(daemon)* refresh the Cloudflare ranges from the API ([#172](https://github.com/jpalczewski/weglarka/pull/172))
- *(ingress)* trust the CDN's client address in edge mode ([ingress.cdn]) ([#171](https://github.com/jpalczewski/weglarka/pull/171))
- *(ingress)* keep the real client address in edge mode ([#166](https://github.com/jpalczewski/weglarka/pull/166))
- *(ingress)* serve wildcard certificates for the domains they cover ([#161](https://github.com/jpalczewski/weglarka/pull/161))
- *(ingress)* edge mode with nginx owning 80/443 ([#146](https://github.com/jpalczewski/weglarka/pull/146))

### Fixed

- *(ingress)* default $app and keep the client address on catch-all requests ([#193](https://github.com/jpalczewski/weglarka/pull/193))

### Other

- *(ingress)* share the default_server, set $app and client-address helpers ([#192](https://github.com/jpalczewski/weglarka/pull/192))

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/weglarka-ingress-v0.0.1...weglarka-ingress-v0.0.2) - 2026-10-24

### Added

- *(ingress)* per-app request body limit (ingress.max_body_size) ([#141](https://github.com/jpalczewski/weglarka/pull/141))
- *(ingress)* path-prefix routing (several instances behind one domain)
- *(core)* shared networks between instances ([#137](https://github.com/jpalczewski/weglarka/pull/137))
- config_root mounts and apps reload ([#121](https://github.com/jpalczewski/weglarka/pull/121))
- *(core)* per-app container command (arguments to the image entrypoint) ([#84](https://github.com/jpalczewski/weglarka/pull/84))
- *(ingress)* per-app streaming support (proxy_buffering off, longer read timeout) ([#72](https://github.com/jpalczewski/weglarka/pull/72))
- share volumes between instances ([#66](https://github.com/jpalczewski/weglarka/pull/66))
- *(core)* order app starts with depends_on and gate on healthy dependencies ([#65](https://github.com/jpalczewski/weglarka/pull/65))

### Fixed

- *(ingress)* trust nginx's own addresses as the port forwarder's source ([#140](https://github.com/jpalczewski/weglarka/pull/140))

### Other

- version and changelog each crate independently with release-plz ([#68](https://github.com/jpalczewski/weglarka/pull/68))
