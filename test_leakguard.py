"""Regression tests for leakguard's detection + gate exit codes.

These lock the behaviors fixed after the pre-Marketplace review and the PR #18
self-review: fail-CLOSED CI on unresolvable/empty HEAD, co-author-trailer coverage
in CI (the dominant leak vector), the Docker/K8s/CI false-positive suppression,
the cluster.local + ts.net cases, and the hook's not-a-repo guard.

Fixture leak strings are assembled from fragments (see `lan`/`ip`/`home`) so this
file's own source lines never contain a contiguous leak pattern — otherwise
leakguard's CI self-scan (the example workflow) would flag its own test fixtures.

Run:  pytest ideas/git-agent-leakage/tool/test_leakguard.py -q
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # import sibling detectors
import detectors  # noqa: E402

LG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leakguard.py")


# ---- fragment builders: keep contiguous leak patterns out of this file's source
def lan(host, tld="local"):
    return host + "." + tld           # a dotted LAN hostname, assembled at runtime


def ip(*octets):
    return ".".join(octets)           # a dotted IPv4 address, assembled at runtime


def home(user):
    return "/home/" + user + "/"       # a home-directory path, assembled at runtime


def tok(prefix, char, n, suffix=""):
    return prefix + char * n + suffix  # a provider token, assembled at runtime


def conn(scheme, user, pw, host):
    return scheme + "://" + user + ":" + pw + "@" + host  # a creds URL, assembled at runtime


def run(cmd, cwd, env=None):
    """Run a leakguard subcommand in a controlled env; return (code, output)."""
    e = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    e.pop("LEAKGUARD_ALLOW", None)  # never inherit a bypass or CI base-ref into the tests
    if env:
        e.update(env)
    r = subprocess.run([sys.executable, LG, *cmd], cwd=cwd,
                       capture_output=True, text=True, env=e)
    return r.returncode, r.stdout + r.stderr


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    """A git repo with a clean, non-LAN identity."""
    d = tmp_path
    git(d, "init", "-q")
    git(d, "config", "user.email", "clean@users.noreply.github.com")
    git(d, "config", "user.name", "Test")
    return d


def stage(repo, name, content):
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)  # allow nested paths like .aws/credentials
    p.write_text(content)
    git(repo, "add", name)


def commit(repo, name, content, message):
    stage(repo, name, content)
    git(repo, "commit", "-q", "-m", message)


# ---------------- hook ----------------

def test_hook_blocks_real_leak(repo):
    stage(repo, "cfg.yaml", f"host: {lan('truenas')}\nip: {ip('10','0','9','176')}\np: {home('alice')}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert lan("truenas") in out and ip("10", "0", "9", "176") in out


def test_hook_passes_benign_container_defaults(repo):
    stage(repo, "cfg.yaml",
          f"db: host.docker.internal\npod: {ip('10','244','1','5')}\nsvc: {ip('10','96','0','1')}\n"
          f"ci: {home('runner')}work\nnode: {home('node')}app\nloop: {ip('127','0','0','1')}\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_suppresses_cluster_local(repo):
    stage(repo, "svc.yaml", f"url: postgres.default.svc.{lan('cluster')}\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_still_catches_real_local_beside_cluster_local(repo):
    stage(repo, "m.yaml", f"k8s: svc.{lan('cluster')}\nnas: {lan('truenas')}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert lan("truenas") in out


def test_hook_flags_tailscale_tsnet(repo):
    stage(repo, "ts.yaml", f"peer: {lan('laptop.tailfe8c', 'ts.net')}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert lan("ts", "net") in out


def test_hook_blocks_lan_commit_identity(repo):
    git(repo, "config", "user.email", lan("hermes@nas"))
    stage(repo, "a.txt", "hello\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert lan("nas") in out


def test_hook_fails_closed_outside_repo(tmp_path):
    code, out = run(["hook"], tmp_path)  # tmp_path is NOT a git repo
    assert code == 1
    assert "not a git repository" in out.lower()


def test_hook_bypass_env(repo):
    stage(repo, "cfg.yaml", f"host: {lan('truenas')}\n")
    code, _ = run(["hook"], repo, env={"LEAKGUARD_ALLOW": "1"})
    assert code == 0


# ---------------- ci ----------------

def test_ci_fails_closed_on_unborn_head(repo):
    # empty repo, no commits: must NOT report clean
    code, _ = run(["ci"], repo)
    assert code == 2


def test_ci_fails_closed_on_unresolvable_base(repo):
    commit(repo, "a.txt", "hi\n", "init")
    code, out = run(["ci", "--base", "nope-not-a-branch"], repo)
    assert code == 2
    assert "cannot resolve base" in out.lower()


def test_ci_catches_lan_coauthor_trailer(repo):
    # the dominant leak vector: LAN identity hidden in a Co-authored-by trailer
    commit(repo, "a.txt", "hi\n",
           "feat: x\n\nCo-authored-by: Claude <noreply@" + lan("jupiter") + ">")
    code, out = run(["ci"], repo)
    assert code == 1
    assert lan("jupiter") in out


def test_ci_clean_agent_coauthor_passes(repo):
    commit(repo, "a.txt", "hi\n",
           "feat: x\n\nCo-authored-by: Claude <noreply@anthropic.com>")
    code, _ = run(["ci"], repo)
    assert code == 0


def test_ci_clean_commit_passes(repo):
    commit(repo, "ok.txt", "hello world\n", "chore: clean")
    code, _ = run(["ci"], repo)
    assert code == 0


def test_ci_catches_leak_in_diff(repo):
    commit(repo, "cfg.yaml", f"host: {lan('umbrel')}\nip: {ip('192','168','1','20')}\n", "add config")
    code, out = run(["ci"], repo)
    assert code == 1
    assert lan("umbrel") in out or ip("192", "168", "1", "20") in out


# ---------------- secrets: provider tokens ----------------

def test_hook_blocks_github_pat(repo):
    stage(repo, "cfg.yaml", f"token: {tok('ghp_', 'a', 36)}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "github-pat" in out


def test_hook_blocks_stripe_secret_key(repo):
    stage(repo, "cfg.yaml", f"key: {tok('sk_live_', 'A', 30)}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "stripe-secret-key" in out


def test_hook_blocks_anthropic_key(repo):
    stage(repo, "cfg.yaml", f"key: {tok('sk-ant-api03-', 'x', 93, 'AA')}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "anthropic-api-key" in out


def test_hook_allows_stripe_publishable_key(repo):
    # pk_ publishable keys are public by design and must not be flagged
    stage(repo, "cfg.yaml", f"pub: {tok('pk_live_', 'A', 30)}\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_allows_aws_example_doc_key(repo):
    stage(repo, "cfg.yaml", "key: " + "AKIA" + "IOSFODNN7" + "EXAMPLE" + "\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_allows_placeholder_value(repo):
    stage(repo, "cfg.yaml", 'api_key = "changeme"\npassword: secret\n')
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_never_prints_raw_secret(repo):
    raw = tok("ghp_", "a", 36)
    stage(repo, "cfg.yaml", f"token: {raw}\n")
    _, out = run(["hook"], repo)
    assert raw not in out            # only the masked form may appear
    assert raw[:4] in out            # ... but the finding is still shown


# ---------------- secrets: connection strings ----------------

def test_hook_blocks_connection_string_creds(repo):
    stage(repo, "db.yaml", "url: " + conn("postgres", "admin", "S3cretPass99", lan("db", "internal") + ":5432") + "\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "connection-string-creds" in out


def test_hook_allows_connection_string_placeholder_pw(repo):
    stage(repo, "db.yaml", "url: " + conn("postgres", "user", "password", "localhost:5432") + "\n")
    code, _ = run(["hook"], repo)
    assert code == 0


# ---------------- sensitive filenames ----------------

def test_hook_blocks_private_key_filename(repo):
    stage(repo, "deploy/id_rsa", "x\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "id_rsa" in out


def test_hook_blocks_aws_credentials_file(repo):
    stage(repo, ".aws/credentials", "x\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "credentials" in out


def test_hook_blocks_dotenv_but_allows_example(repo):
    stage(repo, ".env", "FOO=bar\n")
    stage(repo, ".env.example", "FOO=example\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert ".env " in out or ".env\n" in out
    assert ".env.example" not in out  # the sample file must not be flagged


def test_hook_allows_public_key_file(repo):
    stage(repo, "deploy/server.pub", "ssh-ed25519 AAAA...\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_ci_catches_secret_in_range(repo):
    commit(repo, "cfg.yaml", f"token: {tok('ghp_', 'b', 36)}\n", "add token")
    code, out = run(["ci"], repo)
    assert code == 1
    assert "github-pat" in out


# ---------------- detectors unit checks ----------------

def test_mask_never_returns_full_value():
    raw = tok("ghp_", "a", 36)
    assert detectors.mask(raw) != raw
    assert raw not in detectors.mask(raw)


def test_mask_caps_disclosure_on_short_secrets():
    # a short 9-20 char secret must not leak more than ~1/3 of its characters
    # (regression guard for the old first-4+last-2 rule that showed 6-of-9 = 67%).
    for n in (9, 12, 16, 20):
        v = "".join(chr(ord("a") + (i % 26)) for i in range(n))
        m = detectors.mask(v)
        revealed = sum(1 for c in m if c != "*")
        assert revealed <= max(3, n // 4), f"mask leaked {revealed}/{n} chars: {m!r}"
        assert v not in m


def test_scan_secret_line_keyword_prefilter_is_case_insensitive():
    # a real value with an uppercased prefix context still resolves the token
    hits = detectors.scan_secret_line("KEY=" + tok("ghp_", "c", 36))
    assert any(rid == "github-pat" for rid, _ in hits)


# ---- positive detection samples: one BLOCK-tier rule per entry ----
# Every value is assembled at runtime from fragments so this file's own source never
# contains a contiguous provider-token literal (an external scanner run over this repo
# would otherwise flag the test fixtures themselves). Each `line` embeds the value plus,
# where the rule uses a keyword pre-filter that the token prefix doesn't already supply
# (discord/twilio/mailgun/telegram), the provider keyword in context.
def _block_samples():
    return [
        ("aws-access-key", "aws_key=" + tok("AKIA", "A", 16)),
        ("github-pat", "token=" + tok("ghp_", "a", 36)),
        ("github-oauth", "token=" + tok("gho_", "b", 36)),
        ("github-fine-grained-pat", "token=" + tok("github_pat_", "c", 82)),
        ("gitlab-pat", "token=" + tok("glpat-", "d", 20)),
        ("gitlab-pat-routable", "token=" + tok("glpat-", "e", 27) + "." + tok("ab", "1", 7)),
        ("npm-access-token", "token=" + tok("npm_", "f", 36)),
        ("pypi-upload-token", "token=" + tok("pypi-AgEIcHlwaS5vcmc", "g", 50)),
        ("stripe-secret-key", "key=" + tok("sk_live_", "h", 24)),
        ("sendgrid-api-key", "key=" + tok("SG.", "i", 22) + "." + tok("", "j", 43)),
        ("openai-api-key", "key=" + tok("sk-proj-", "k", 20, "T3BlbkFJ") + tok("", "l", 20)),
        ("anthropic-api-key", "key=" + tok("sk-ant-api03-", "m", 95)),
        ("slack-bot-token", "token=" + tok("xoxb-", "n", 20)),
        ("slack-webhook-url",
         "url=https://hooks.slack.com/services/T" + "A" * 8 + "/B" + "A" * 8 + "/" + "o" * 20),
        ("google-api-key", "key=" + tok("AIza", "p", 35)),
        ("google-oauth-client-secret", "secret=" + tok("GOCSPX-", "q", 28)),
        ("digitalocean-token", "token=" + tok("dop_v1_", "a", 64)),
        ("discord-bot-token",
         "discord bot token=" + "M" + "r" * 24 + "." + "s" * 6 + "." + "t" * 30),
        ("twilio-api-key", "twilio api key=" + tok("SK", "a", 32)),
        ("mailgun-private-key", "mailgun key=" + tok("key-", "a", 32)),
        ("telegram-bot-token", "telegram bot=" + "12345678" + ":" + "u" * 35),
        ("private-key", "-----BEGIN PRIVATE KEY-----"),
        ("connection-string-creds", "db=" + conn("postgres", "dbuser", "s3cretpassw0rd", "db.host")),
    ]


def test_every_block_rule_has_a_positive_sample():
    """A new BLOCK rule with no positive sample is a coverage hole — force one.

    This is the guard that keeps the 17-rules-untested regression from reopening:
    it fails the moment SECRET_RULES gains a rule that _block_samples() doesn't cover.
    """
    covered = {rid for rid, _ in _block_samples()}
    all_ids = {r.id for r in detectors.SECRET_RULES}
    assert all_ids <= covered, f"BLOCK rules with no positive detection sample: {sorted(all_ids - covered)}"


@pytest.mark.parametrize("rule_id,line", _block_samples(), ids=[s[0] for s in _block_samples()])
def test_block_rule_fires_on_its_sample(rule_id, line):
    """Each BLOCK rule must actually detect a valid sample of its own token.

    Mutation-checked: deleting a rule's regex turns exactly this rule's case red.
    """
    ids = [rid for rid, _ in detectors.scan_secret_line(line)]
    assert rule_id in ids, f"{rule_id} did not fire on its sample; got {ids}"


def test_sensitive_file_config_credentials_scoped_to_known_dirs():
    """The dir-scoping guard: bare `config`/`credentials` must NOT block (removing the
    guard would flag nearly every commit touching a file named `config`)."""
    assert detectors.sensitive_file("src/config") is None
    assert detectors.sensitive_file("app/credentials") is None
    assert detectors.sensitive_file(".kube/config") is not None
    assert detectors.sensitive_file(".aws/credentials") is not None


def test_scan_secret_line_inline_allow_marker_suppresses_then_fires_without():
    """The documented `leakguard:allow` false-positive escape hatch must work — and
    must NOT swallow the same line once the marker is removed."""
    real = "token=" + tok("ghp_", "a", 36)
    assert detectors.scan_secret_line(real + "  # leakguard:allow") == []
    assert any(rid == "github-pat" for rid, _ in detectors.scan_secret_line(real))


# ---------------- Phase 2: entropy / generic heuristics (audit-only, WARN) ----------------

# a 32-char high-entropy value with no provider prefix, assembled to avoid a literal run
RANDISH = "kJ8xQ2mN4pR7" + "vW1zL5tY9bC3" + "dF6gH0aS"


def test_hook_does_not_block_on_entropy(repo):
    # a bare high-entropy quoted string must NOT fail the blocking gate
    stage(repo, "app.conf", f'blob: "{RANDISH}"\n')
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_does_not_block_on_generic_keyword(repo):
    stage(repo, "app.conf", f'api_key = "{RANDISH}"\n')
    code, _ = run(["hook"], repo)
    assert code == 0


def test_audit_warns_on_generic_and_entropy(repo):
    # distinct values on distinct lines: one keyword-shaped, one bare high-entropy blob
    other = "aZ9" + "qW4eR7tY2uI5oP8s" + "dF1gH6jK"
    commit(repo, "app.conf", f'api_key = "{RANDISH}"\nblob: "{other}"\n', "add config")
    code, out = run(["audit"], repo)
    assert code == 0                       # audit never fails the process
    assert "generic:api_key" in out
    assert "base64-entropy" in out
    assert RANDISH not in out and other not in out   # heuristic findings are masked too


def test_generic_ignores_placeholder_and_benign_keys():
    assert detectors.scan_generic_line('password = "changeme"') == []
    assert detectors.scan_generic_line(f'public_key = "{RANDISH}"') == []


def test_entropy_ignores_uuid_and_low_entropy():
    assert detectors.scan_entropy_line('id: "550e8400-e29b-41d4-a716-446655440000"') == []
    assert detectors.scan_entropy_line('word: "authorization"') == []


def test_shannon_matches_known_values():
    assert detectors.shannon("", detectors._B64_CHARSET) == 0.0
    assert detectors.shannon("aaaaaaaa", detectors._B64_CHARSET) == 0.0  # single symbol -> 0
    assert detectors.shannon(RANDISH, detectors._B64_CHARSET) > 4.5


# ---------------- Phase 3: baseline / commit-msg / large-file / .gitignore ----------------

def test_baseline_suppresses_existing_but_blocks_new(repo):
    # a repo that already has a leak: baseline it, then a NEW leak must still block
    commit(repo, "app.conf", f"token: {tok('ghp_', 'a', 36)}\n", "legacy leak")
    code, _ = run(["baseline"], repo)
    assert code == 0
    assert (repo / ".leakguard-baseline.json").exists()
    # a new file re-uses the accepted token AND introduces a fresh one
    stage(repo, "other.conf", f"old: {tok('ghp_', 'a', 36)}\nnew: {tok('sk_live_', 'A', 30)}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "stripe-secret-key" in out        # the new secret blocks
    assert "github-pat" not in out           # the baselined one is suppressed
    assert "suppressed" in out


def test_baseline_file_stores_no_raw_secret(repo):
    raw = tok("ghp_", "a", 36)
    commit(repo, "app.conf", f"token: {raw}\n", "legacy")
    run(["baseline"], repo)
    assert raw not in (repo / ".leakguard-baseline.json").read_text()


def test_commit_msg_blocks_secret_in_message(repo, tmp_path):
    msg = tmp_path / "msg.txt"
    msg.write_text(f"fix: rotate\n\nold key {tok('ghp_', 'a', 36)}\n")
    code, out = run(["commit-msg", str(msg)], repo)
    assert code == 1
    assert "github-pat" in out


def test_commit_msg_allows_clean_message(repo, tmp_path):
    msg = tmp_path / "msg.txt"
    msg.write_text("fix: a perfectly ordinary commit message\n")
    code, _ = run(["commit-msg", str(msg)], repo)
    assert code == 0


def test_hook_blocks_large_file(repo):
    (repo / "big.bin").write_bytes(b"x" * 200_000)
    git(repo, "add", "big.bin")
    code, out = run(["hook"], repo, env={"LEAKGUARD_MAX_KB": "100"})
    assert code == 1
    assert "large-file" in out


def test_hook_allows_file_under_size_threshold(repo):
    (repo / "small.bin").write_bytes(b"x" * 50_000)
    git(repo, "add", "small.bin")
    code, _ = run(["hook"], repo, env={"LEAKGUARD_MAX_KB": "100"})
    assert code == 0


def test_audit_reports_gitignore_gaps(repo):
    commit(repo, "app.py", "print(1)\n", "add py")
    code, out = run(["audit"], repo)
    assert code == 0
    assert "missing: .env" in out


def test_fingerprint_is_stable_and_valueless():
    raw = tok("ghp_", "a", 36)
    fp = detectors.fingerprint("github-pat", raw)
    assert fp == detectors.fingerprint("github-pat", raw) and len(fp) == 16
    assert detectors.fingerprint("other-kind", raw) != fp   # kind is part of the hash


# ---------------- review fixes (2026-08-18 security + quality pass) ----------------

def test_hook_blocks_dotenv_in_unicode_dir(repo):
    # git octal-escapes non-ASCII paths by default; the gate must still see them
    stage(repo, "détox/.env", "SECRET=1\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert ".env" in out


def test_hook_blocks_large_file_with_unicode_name(repo):
    (repo / "big ünïcödé.bin").write_bytes(b"x" * 200_000)
    git(repo, "add", "big ünïcödé.bin")
    code, out = run(["hook"], repo, env={"LEAKGUARD_MAX_KB": "100"})
    assert code == 1
    assert "large-file" in out


def test_baseline_does_not_launder_staged_secret(repo):
    # baseline reads HEAD only: a merely-staged secret must NOT become accepted
    commit(repo, "readme.txt", "clean\n", "init")
    stage(repo, "secret.conf", f"token: {tok('ghp_', 'a', 36)}\n")
    code, out = run(["baseline"], repo)
    assert code == 0
    assert "0 accepted" in out                 # nothing from HEAD
    code, out = run(["hook"], repo)            # staged secret still blocks
    assert code == 1 and "github-pat" in out


def test_baseline_warns_to_rotate_committed_secrets(repo):
    commit(repo, "secret.conf", f"token: {tok('ghp_', 'a', 36)}\n", "oops")
    code, out = run(["baseline"], repo)
    assert code == 0
    assert "ROTATE" in out


def test_hook_blocks_redis_url_without_username(repo):
    # redis://:password@host (no username) is the canonical Redis form
    url = "redis" + "://:" + "R3alPass99" + "@" + lan("cache", "internal") + ":6379"
    stage(repo, "r.conf", f"url: {url}\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "connection-string-creds" in out


def test_hook_allows_pass_placeholder_in_url(repo):
    url = "mongodb" + "://user:" + "pass" + "@localhost:27017/db"
    stage(repo, "docs.md", f"Example: {url}\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_jwt_is_warn_not_block(repo):
    jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiIxIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    commit(repo, "app.js", f'const t = "{jwt}"\n', "add jwt fixture")
    code, _ = run(["hook"], repo)
    assert code == 0                           # JWTs no longer block
    code, out = run(["audit"], repo)
    assert code == 0 and "[jwt]" in out        # ... but audit still surfaces them


def test_hook_allows_credentials_json_fixture(repo):
    stage(repo, "tests/fixtures/credentials.json", '{"client_secret": "mock"}\n')
    code, _ = run(["hook"], repo)
    assert code == 0                           # demoted to WARN tier
    assert detectors.warn_file("tests/fixtures/credentials.json")


def test_topology_scanned_in_lockfile(repo):
    # lockfiles are skipped for token-shape secrets but NOT for topology leaks
    url = "git+ssh://build@" + ip("10", "0", "9", "176") + "/internal/pkg.git"
    stage(repo, "package-lock.json", '{"resolved": "' + url + '"}\n')
    code, out = run(["hook"], repo)
    assert code == 1
    assert ip("10", "0", "9", "176") in out


def test_ci_scans_commit_message_body(repo):
    commit(repo, "a.txt", "hi\n", f"fix: rotate\n\nold key {tok('ghp_', 'a', 36)}")
    code, out = run(["ci"], repo)
    assert code == 1
    assert "github-pat" in out


def test_warn_file_is_separate_from_block_tier():
    assert detectors.warn_file("server.pem") and detectors.sensitive_file("server.pem") is None
    assert detectors.sensitive_file("deploy/id_rsa")   # block tier still fires


def test_gitignore_gaps_respects_present_entries(repo):
    (repo / ".gitignore").write_text(".env\n__pycache__/\n*.pyc\n")
    commit(repo, "app.py", "print(1)\n", "add py + gitignore")
    git(repo, "add", ".gitignore")
    _, out = run(["audit"], repo)
    assert "missing: .env" not in out          # present -> not flagged
    assert "missing: *.pem" in out             # still missing -> flagged


# ---------------- adoption: baseline --report + pre-commit manifest ----------------

def test_baseline_report_lists_secrets_to_rotate(repo):
    commit(repo, "app.conf", f"token: {tok('ghp_', 'a', 36)}\nhost: {lan('nas')}\n", "legacy")
    run(["baseline"], repo)
    code, out = run(["baseline", "--report"], repo)
    assert code == 0
    assert "SECRETS TO ROTATE" in out and "github-pat" in out
    assert "identity / topology" in out        # topology grouped separately from secrets


def test_baseline_report_without_baseline_file_errors(repo):
    code, out = run(["baseline", "--report"], repo)   # no baseline written yet
    assert code == 1
    assert "no readable" in out


def test_precommit_manifest_declares_both_hooks():
    manifest = os.path.join(os.path.dirname(LG), ".pre-commit-hooks.yaml")
    text = open(manifest).read()
    assert "id: leakguard" in text and "id: leakguard-commit-msg" in text
    assert "leakguard.py hook" in text and "leakguard.py commit-msg" in text
    assert "stages: [commit-msg]" in text
