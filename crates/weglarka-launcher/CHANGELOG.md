# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1](https://github.com/jpalczewski/weglarka/compare/weglarka-launcher-v0.0.0...weglarka-launcher-v0.0.1) - 2026-11-05

### Fixed

- *(launcher)* reset the start budget after stable uptime, back off, exit without a selection ([#520](https://github.com/jpalczewski/weglarka/pull/520))
- *(launcher)* exec the cli role and keep its exit code ([#504](https://github.com/jpalczewski/weglarka/pull/504))

### Other

- *(platform)* one podman inspect shared by the launcher, systemd and OpenRC ([#510](https://github.com/jpalczewski/weglarka/pull/510))
- *(launcher)* skip rehashing unchanged generation binaries ([#513](https://github.com/jpalczewski/weglarka/pull/513))
