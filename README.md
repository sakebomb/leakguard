# leakguard

Stop AI coding agents (and plain git) from leaking your machine identity and internal network
into **public** git history.

## The problem

When `user.email` is unset, git auto-invents `user@<hostname>`. On a self-hosted box with mDNS
that becomes `user@nas.local`, `user@MacBook-Pro.local`. AI agents (Claude Code, Cursor, Aider)
then co-sign public commits with that identity, and their diffs paste internal hostnames, LAN IPs
(`192.168.x`, `10.x`), and home paths into permanent public history.

In a passive study of public GitHub commit search, roughly **1 in 3** home-server-identity commits
leaked an internal hostname, and about **91%** resolved to a real GitHub account. The machine name,
its OS and hardware, the AI agent and model, the operator's timezone, and the operator themselves
are all recoverable from data that can never be edited out.

## Install

`leakguard` is two dependency-free files (`leakguard.py` + `map_render.py`). Clone or copy them,
then put it on your PATH:

```sh
git clone https://github.com/sakebomb/leakguard
alias leakguard='python3 /path/to/leakguard/leakguard.py'
```

Requires only Python 3 and git.

## Defense

```sh
leakguard audit          # what does THIS repo's config + history leak?
leakguard harden         # set safe git config + print agent-attribution guidance
leakguard hook           # pre-commit gate (blocks LAN identity + internal leaks in staged diff)
leakguard ci --base main # CI gate (used by the GitHub Action)
```

Install the pre-commit hook globally so it runs in every repo:

```sh
mkdir -p ~/.git-hooks
printf '#!/usr/bin/env sh\nexec leakguard hook\n' > ~/.git-hooks/pre-commit
chmod +x ~/.git-hooks/pre-commit
git config --global core.hooksPath ~/.git-hooks
```

Bypass a false positive once: `LEAKGUARD_ALLOW=1 git commit ...`

### GitHub Action

Block leaky commits on every PR. Copy `.github/workflows/example.yml` into your repo as
`.github/workflows/leakguard.yml`, or add:

```yaml
name: leakguard
on: [pull_request]
jobs:
  leakguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: sakebomb/leakguard@v1
```

No secrets, no network calls, no dependencies beyond python3 + git (both preinstalled on GitHub
runners).

## Also disable AI attribution trailers

They leak the agent and model version (and sometimes your LAN identity):

| Tool | Setting |
|---|---|
| Claude Code | `~/.claude/settings.json`: `{"attribution": {"commit": "", "pr": ""}}` (older builds: `"includeCoAuthoredBy": false`) |
| VS Code | `"git.addAICoAuthor": "off"` |
| Aider | `--no-attribute-author --no-attribute-committer` |

Some tools have had bugs where these settings are intermittently ignored, so the pre-commit hook
is the reliable backstop, not the settings alone.

## Audit your own account (public data)

```sh
leakguard scan <github-user>            # fingerprint: machine, hardware, agent+model, timezone
leakguard scan <github-user> --deep     # + internal hosts/IPs/paths from public diffs
leakguard scan <github-user> --deep --json > case.json
leakguard map case.json > map.dot       # network map from a scan dump
twopi -Tpng map.dot -o map.png          # render (needs graphviz)
```

These read only public GitHub commit search. Use them to audit your own account. There is also a
hosted self-check at **https://leakcheck.madx.co**.

`research/gharchive-trend.sql` reproduces the growth-over-time measurement against the public GH
Archive dataset on BigQuery.

## Scope

Detection is deterministic (regex), the defense path makes no network calls, and there are no
dependencies. It is a guardrail, not a guarantee: it catches the common shapes, not every possible
leak. Review diffs before pushing to public repos.

## License

MIT. Built by [MadX](https://madx.co) as part of research into AI coding agents as a public
data-leakage vector.
