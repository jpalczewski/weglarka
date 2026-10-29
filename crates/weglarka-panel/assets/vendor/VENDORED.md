# Vendored front-end libraries

Downloaded once from the npm registry tarballs (`dist/` files, unmodified) and embedded with
`include_bytes!` (`src/assets.rs`). No CDN, no Node, no bundler (docs/decisions/0057, decision 2).
A unit test in `src/assets.rs` checks the SHA-256 below against the embedded bytes.

All versions were published at least two weeks before they were vendored.

| File | Package | Version | Published | License | SHA-256 |
|---|---|---|---|---|---|
| `htmx-2.0.11.min.js` | `htmx.org` `dist/htmx.min.js` | 2.0.11 | 2026-09-22 | 0BSD | d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717 |
| `htmx-ext-sse-2.2.4.min.js` | `htmx-ext-sse` `dist/sse.min.js` | 2.2.4 | 2025-10-18 | 0BSD | 98a46496de0c3605fbffdce9167ba427bdd9553184f83f149c261891a92c0136 |
| `alpine-csp-3.17.4.min.js` | `@alpinejs/csp` `dist/cdn.min.js` | 3.17.4 | 2026-09-21 | MIT | 0d18d7f8d7910e2e0212f0f056b12f50bebc3abb7d88d2f7c7cb4c336fe4519a |

Licenses: `LICENSE-htmx` (0BSD) and `LICENSE-alpine` (MIT) sit next to the files.

To update: download the new tarball, copy the file under a name with the new version, update the row and the
table in `src/assets.rs`, and keep the old name out of the table (a versioned name is cached for a year).
htmx is configured in the page (`htmx-config` meta tag: `includeIndicatorStyles: false`, `allowEval: false`).
