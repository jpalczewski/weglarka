---
name: weglarka-cli
description: Operate a Węglarka host with the `weglarka` CLI: inspect apps, status and doctor, manage secrets, deploy, push, run, forward and logs, locally or on a remote host with `--host`. Use when the user asks to look at, change or debug apps on a Węglarka host, or mentions `weglarka login`.
---

# Operating a Węglarka host

The full guide is `docs/guides/agent-cli.md` in https://github.com/jpalczewski/weglarka. This skill is the short form;
read the guide for the tables and the reasoning.

## Where commands go
First match wins: `--socket` / `WEGLARKA_SOCKET`, then `--host https://panel.example.com` / `WEGLARKA_HOST`, then `host`
in `~/.config/weglarka/cli.toml`, then the local `admin.socket`. Remote use needs `weglarka login`; a person approves the
code in a browser, so start the command, show the code and address, and wait. `weglarka whoami` shows the session.

## Rules
1. **Reads are free:** `status`, `apps list`, `apps show`, `doctor`, `secrets list` (names only), `volumes list`,
   `networks list`, `images prune --dry-run`. Prefer `--json` when parsing; exit codes are stable (3 not found, 4 conflict,
   5 rejected, 6 rolled back, 64 usage, 69 unreachable, 70 internal).
2. **Writes need the owner's yes**, per action, with the app and the effect named. Run `--dry-run` first where it exists.
3. **Test writes on a throwaway app** (for example `relay-test` with busybox), then remove it. Never on a real app.
4. **Secrets only from stdin or `--from-file`**, never as an argument; never print a value back.
5. **A declaratively managed host** (playbook, git) is changed in its declaration; use the CLI for reads, diagnosis and
   one-off operations (`run`, `forward`, `push`).
6. `apps remove` has no undo; `push` leaves the loaded image behind (not removed by `images prune`); a 403 means the
   account lacks the group, not that the panel is down.

`weglarka logs <app>... | --all [-f] [-n N|all] [--since 10m] [--timestamps]` prints what containers wrote (default last
100 lines; several apps are prefixed `app | line`, `--json` gives `{"app","stream","line"}`). It needs `admin`, and logs
can hold secrets the app printed, so reading them needs the owner's yes once per task, for the apps or the `--all` scope
that task names; do not ask again for each read within it, and ask again for a new task or apps outside that scope. Do
not paste logs into public places. After a reconnect a few lines may repeat.

Do not put hostnames, tokens or account details from the user's environment into public places (issues, PRs, commits).
