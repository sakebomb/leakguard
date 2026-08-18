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

LG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leakguard.py")


# ---- fragment builders: keep contiguous leak patterns out of this file's source
def lan(host, tld="local"):
    return host + "." + tld           # a dotted LAN hostname, assembled at runtime


def ip(*octets):
    return ".".join(octets)           # a dotted IPv4 address, assembled at runtime


def home(user):
    return "/home/" + user + "/"       # a home-directory path, assembled at runtime


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
    (repo / name).write_text(content)
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
