# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
