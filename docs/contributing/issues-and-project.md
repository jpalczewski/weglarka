# Issues and project

Issues are the source of truth for planned work and bugs. The GitHub project
[Węglarka roadmap](https://github.com/users/jpalczewski/projects/12) is only a view over them (board and timeline); if
the two disagree, the issue wins. How work is carried out is in [agent workflow](agent-workflow.md).

## Labels

Existing labels:

| Label | Use it for |
|---|---|
| `bug` | Something that is broken now |
| `enhancement` | A small improvement to existing behaviour |
| `roadmap` | A planned feature or task |
| `documentation` | Docs-only work |
| `release` | Release PRs (set by release automation) |
| `github_actions`, `dependencies` | Dependency update PRs from the bots |

Labels added for the admin panel work. They combine with the ones above (a leak in the panel can be `bug`,
`🛡️ security` and `🖥️ admin-panel` at once):

| Label | When to use it |
|---|---|
| 🛡️ `security` | The issue concerns leaks, authentication, authorization or hardening |
| 🔁 `follow-up` | Debt left by a review or by a merged PR, not a new feature; link the PR it came from |
| 🖥️ `admin-panel` | Part of the panel series ([ADR 0057](../decisions/0057-admin-panel-architecture.md)) |
| 🤖 `agent-ready` | Specified well enough to hand to a session without further questions |
| ❓ `needs-decision` | Waiting for a maintainer; the issue says which decision is needed and the options |

## Project fields

| Field | Values |
|---|---|
| Status | Todo, Next, In Progress, Blocked, Done |
| Area | A crate or area name (for example `api`, `daemon`, `engine`, `cli`, `docs`, `panel`) |
| Priority | Relative urgency within an Area |

`Next` means picked for the near term, and there are at most ten items in it, so the column stays a real shortlist.
A `Blocked` item says what it waits for, either in a comment on the issue or by linking a parent issue; "blocked"
with no reason is not allowed.

Changing the options of a single-select field (for example adding an Area) clears that field on every item.
Export the values first and restore them afterwards; see the lessons in [agent workflow](agent-workflow.md).

## Pull requests

Every PR links its issue with `Closes #NN` in the body so the issue closes on merge. A PR that only partly covers an
issue uses `Refs #NN` instead, and the remainder stays open. Titles follow Conventional Commits (see
[commits and PRs](../../.claude/rules/commits-and-prs.md)).

## Filing an issue an agent can pick up

Label it 🤖 `agent-ready` only if all of this is in the issue:

- **Problem.** What is wrong or missing, and why it matters, with a link to the ADR or PR it comes from.
- **Files.** The paths and symbols to change (and any that must not be touched).
- **Acceptance criteria.** Checkable statements, each one a test or an observable behaviour.
- **Checks.** The commands to run, as in the brief template in [agent workflow](agent-workflow.md).

Example, shaped like a real follow-up:

```markdown
Title: fix(panel): anonymous login flood can fill the pending-login map

Problem: every unauthenticated request to the login route stores a pending login (state, PKCE verifier) that is only
removed when the callback arrives. An anonymous caller can grow the map without bound.

Files: the panel's login module and its tests. Not the daemon.

Acceptance:
- The pending-login map has a fixed capacity and a time-to-live; the oldest entries are dropped first.
- A test inserts more than the capacity and checks the size stays bounded.
- A valid login that is in flight still completes.

Labels: bug, 🛡️ security, 🔁 follow-up, 🖥️ admin-panel, 🤖 agent-ready
```
