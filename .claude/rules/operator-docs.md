---
paths:
  - "docs/**"
  - "README.md"
  - "crates/*/README.md"
---

# Operator documentation (`docs/install.md`, `docs/guides/`)

- A new feature that affects the operator = a new or changed guide in `docs/guides/<topic>.md` (in English) and an entry
  in `docs/guides/README.md`. Name files by topic, **do not number headings**; link to the file, not to "section 6k".
- Links between guides are file links (no `#anchor` into another file); `scripts/adr.sh lint` checks links, anchors,
  heading uniqueness and that every guide is present in the index.
- The repo is public: examples use only `example.com`/`example.org`, host `myhost`, no real domains, host names or
  private projects. Every guide ends with a `## Rollback` section if the change breaks downgrade
  (`deny_unknown_fields`, `schema_version`) — and the field also goes into the table in `verify-and-rollback.md`.
- Language: README, code comments and ADRs are in English (Jacek's decision, 2026-10-23; ADRs 2026-10-24);
  `docs/install.md` and `docs/guides/` are in English (2026-10-25); runtime/CLI messages are being translated
  (issue #32). Write new and changed code in English right away; existing Polish comments in files you do not touch are
  translated by a separate task (do not mix translations with unrelated changes in a PR).
- Implementation decisions with rationale: `docs/decisions/` (index generated from ADR titles:
  [`docs/decisions/README.md`](../../docs/decisions/README.md)); template `docs/decisions/0000-template.md`. Tasks and
  roadmap: GitHub Issues (label `roadmap` = planned features, `bug` = defects).
