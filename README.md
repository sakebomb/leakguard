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

`leakguard` is three dependency-free files (`leakguard.py` + `detectors.py` + `map_render.py`).
Clone or copy them, then put it on your PATH:

```sh
git clone https://github.com/sakebomb/leakguard
alias leakguard='python3 /path/to/leakguard/leakguard.py'
```

Requires only Python 3 and git.

## What it detects

`hook`/`ci` **block** a commit on: machine identity (LAN commit identity, mDNS `.local`/`.lan`/
`.internal` hosts, Tailscale tailnet names), internal topology (private IPs, home paths), **30+
provider secrets** (AWS, GitHub/GitLab PATs, Stripe, npm/PyPI, OpenAI/Anthropic, Slack, SendGrid,
Google, DigitalOcean, PEM private keys), embedded credentials in `scheme://…:pass@host` URLs, and
sensitive files (`id_rsa`, `*.pfx`/`*.p12`/`*.jks`, `.npmrc`, `.aws/credentials`, `kubeconfig`,
`.env` — sample files allowed). It also enforces a large-file tripwire and scans commit messages.

High-precision by design: a keyword pre-filter, an allowlist layer, and a placeholder-value
denylist keep false positives low, and findings are **masked** — the raw secret is never printed.
Noisier signals (entropy, generic `key=value`, JWTs, ambiguous filenames like `*.pem`) surface as
`audit` **warnings**, not blocking checks. Suppress one line inline with a `leakguard:allow` comment.

## Defense

```sh
leakguard audit             # what does THIS repo leak? secrets, identity, + .gitignore gaps
leakguard harden            # set safe git config + install the hooks
leakguard hook              # pre-commit gate (blocks identity + secrets in the staged diff)
leakguard commit-msg FILE   # commit-msg gate (blocks secrets pasted into the message)
leakguard ci --base main    # CI gate (used by the GitHub Action)
leakguard baseline          # accept a repo's existing leaks; then block only NEW ones
```

Install the pre-commit hook globally so it runs in every repo:

```sh
mkdir -p ~/.git-hooks
printf '#!/usr/bin/env sh\nexec leakguard hook\n' > ~/.git-hooks/pre-commit
chmod +x ~/.git-hooks/pre-commit
git config --global core.hooksPath ~/.git-hooks
```

Bypass a false positive once: `LEAKGUARD_ALLOW=1 git commit ...`

### Install via the pre-commit framework

If you use [pre-commit](https://pre-commit.com), add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/sakebomb/leakguard
    rev: v1.1.0
    hooks:
      - id: leakguard              # scans the staged diff
      - id: leakguard-commit-msg   # optional: scans the commit message
```

Then `pre-commit install --hook-type pre-commit --hook-type commit-msg`. No install step (stdlib only).

### Adopt on a repo that already leaks

For a legacy repo that already contains leaks, `baseline` records the current **committed** findings
(HEAD only, as hashes — the file never stores a raw secret) into `.leakguard-baseline.json`; commit
it, and the gate then suppresses those known findings and blocks only **new** ones.
`leakguard baseline --report` lists what was accepted, **secrets-to-rotate first** — baselining
silences the alert, it does not make a committed secret safe.

The large-file tripwire defaults to 500 KB (`LEAKGUARD_MAX_KB` to tune). Known limitations, by
design: git-LFS pointer files hide the real object size; `10.244.0.0/16` and `10.96.0.0/12` are
treated as benign k8s defaults; and `commit-msg` fails open on an unreadable message file (a
transient FS error must not block every commit), while `hook`/`ci` fail closed.

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

Detection is deterministic (regex + filename globs), the defense path makes no network calls, and
there are no dependencies beyond python3 + git. Secret rules are ported near-verbatim from gitleaks;
the tool never verifies a credential against its provider (that would need network — out of scope by
design). It is a guardrail, not a guarantee: it catches the common shapes, not every possible leak.
Review diffs before pushing to public repos.

## License

MIT. Built by [MadX](https://madx.co) as part of research into AI coding agents as a public
data-leakage vector.
