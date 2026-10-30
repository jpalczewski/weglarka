# weglarka-cli (agent plugin)

A skill that teaches a coding agent to operate a Węglarka host with the `weglarka` CLI safely: where commands go,
reads first, writes only with the owner's approval and on a throwaway app, secrets from stdin. The substance lives in
[`docs/guides/agent-cli.md`](../../docs/guides/agent-cli.md); the skill is the short form and points to it.

It contains no host-specific data (no addresses, accounts or credentials). Keep those in your own configuration
(`~/.config/weglarka/cli.toml`) and, if you want an agent to know them, in your own repository.

## Install
This repository is a Claude Code plugin marketplace named `weglarka`. Add it once and install the plugin at user
scope, and the skill is available in every project on that machine:

```bash
claude plugin marketplace add jpalczewski/weglarka
claude plugin install weglarka-cli@weglarka
```

Update with `claude plugin marketplace update weglarka` and then `claude plugin update weglarka-cli@weglarka`; the new
version loads in the next session (or after `/reload-plugins`). The skill appears as `/weglarka-cli:weglarka-cli` and is
also picked up automatically when a task matches its description.

To try it from a checkout without installing: `claude --plugin-dir ./plugins/weglarka-cli`. To validate the manifests:
`claude plugin validate .` (the marketplace) and `claude plugin validate ./plugins/weglarka-cli` (the plugin).

## Other agents
The skill is a plain `SKILL.md` (a frontmatter with `name` and `description`, then markdown). Copy
`skills/weglarka-cli/SKILL.md` into the skills directory of any agent that reads that format, or point the agent at
`docs/guides/agent-cli.md`.
