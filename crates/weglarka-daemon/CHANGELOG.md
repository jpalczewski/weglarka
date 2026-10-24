# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/v0.0.1...v0.0.2) - 2026-10-24

### Added

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
