# NNNN — Short decision title

Status: proposed (YYYY-MM-DD, issue #NN) · accepted · superseded by NNNN

## Problem

What needs a decision; which constraints apply (security first, then extensible code, then RAM), what is the
failure mode if we get it wrong?

## Decision

What we do and why. List the invariants an implementer must preserve (state files, `spec_hash`, API contract,
rollback, `deny_unknown_fields` compatibility).

## Consequences

What changes for operators and for the code: new CLI/API surface, `apps.toml`/`state.toml` fields, migration and
rollback steps (document them in `docs/install.md`), tests that must exist.

## Rejected alternatives

What we discarded and why — the point of an ADR is to make the rejected path a deliberate choice, not an oversight.
