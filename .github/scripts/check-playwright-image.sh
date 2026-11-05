#!/usr/bin/env bash
# The `panel-e2e` job runs in the official Playwright image (#561), whose browsers belong to one Playwright release.
# Its tag in ci.yml must match the `playwright` package locked in the e2e project's bun.lock, so a Dependabot bump of
# `@playwright/test` fails here instead of silently testing against browsers of another release.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$root/.github/workflows/ci.yml"
lock="$root/crates/weglarka-panel/e2e/bun.lock"

image=$(grep -oE 'mcr\.microsoft\.com/playwright:v[0-9]+\.[0-9]+\.[0-9]+-noble@sha256:[0-9a-f]{64}' "$workflow" | sort -u)
if [ "$(printf '%s\n' "$image" | grep -c .)" != 1 ]; then
  echo "error: expected exactly one digest-pinned mcr.microsoft.com/playwright:v<version>-noble@sha256:… in $workflow, found:" >&2
  printf '%s\n' "${image:-<none>}" >&2
  exit 1
fi
image_version=$(sed -E 's/^.*:v([0-9.]+)-noble@.*$/\1/' <<<"$image")

locked_version=$(grep -oE '"playwright": \["playwright@[0-9]+\.[0-9]+\.[0-9]+"' "$lock" | sed -E 's/.*@([0-9.]+)"$/\1/')
if [ -z "$locked_version" ]; then
  echo "error: no locked \`playwright\` package in $lock" >&2
  exit 1
fi

if [ "$image_version" != "$locked_version" ]; then
  echo "error: the panel-e2e image is Playwright $image_version, bun.lock locks playwright $locked_version" >&2
  echo "bump the image tag and its digest in $workflow (skopeo inspect docker://mcr.microsoft.com/playwright:v$locked_version-noble)" >&2
  exit 1
fi
echo "ok: panel-e2e image and bun.lock are both Playwright $locked_version"
