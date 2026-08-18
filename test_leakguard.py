"""Regression tests for leakguard's detection + gate exit codes.

These lock the behaviors fixed after the pre-Marketplace review and the PR #18
self-review: fail-CLOSED CI on unresolvable/empty HEAD, co-author-trailer coverage
in CI (the dominant leak vector), the Docker/K8s/CI false-positive suppression,
the cluster.local + ts.net cases, and the hook's not-a-repo guard.

Run:  pytest ideas/git-agent-leakage/tool/test_leakguard.py -q
"""
import os
import subprocess
import sys

import pytest

LG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leakguard.py")


def run(cmd, cwd, env=None):
    """Run a leakguard subcommand; return (exit_code, combined_output)."""
    e = dict(os.environ)
    e.pop("LEAKGUARD_ALLOW", None)  # never inherit a bypass into the tests
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
    stage(repo, "cfg.yaml", "host: truenas.local\nip: 10.0.9.176\npath: /home/alice/x\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "truenas.local" in out and "10.0.9.176" in out


def test_hook_passes_benign_container_defaults(repo):
    stage(repo, "cfg.yaml",
          "db: host.docker.internal\npod: 10.244.1.5\nsvc: 10.96.0.1\n"
          "ci: /home/runner/work\nnode: /home/node/app\nloop: 127.0.0.1\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_suppresses_cluster_local(repo):
    stage(repo, "svc.yaml", "url: postgres.default.svc.cluster.local\n")
    code, _ = run(["hook"], repo)
    assert code == 0


def test_hook_still_catches_real_local_beside_cluster_local(repo):
    stage(repo, "m.yaml", "k8s: svc.cluster.local\nnas: truenas.local\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "truenas.local" in out
    assert "cluster.local\n" not in out.replace("svc.cluster.local", "")  # only truenas flagged


def test_hook_flags_tailscale_tsnet(repo):
    stage(repo, "ts.yaml", "peer: laptop.tailfe8c.ts.net\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "ts.net" in out


def test_hook_blocks_lan_commit_identity(repo):
    git(repo, "config", "user.email", "hermes@nas.local")
    stage(repo, "a.txt", "hello\n")
    code, out = run(["hook"], repo)
    assert code == 1
    assert "nas.local" in out


def test_hook_fails_closed_outside_repo(tmp_path):
    code, out = run(["hook"], tmp_path)  # tmp_path is NOT a git repo
    assert code == 1
    assert "not a git repository" in out.lower()


def test_hook_bypass_env(repo):
    stage(repo, "cfg.yaml", "host: truenas.local\n")
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
           "feat: x\n\nCo-authored-by: Claude <noreply@jupiter.local>")
    code, out = run(["ci"], repo)
    assert code == 1
    assert "jupiter.local" in out


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
    commit(repo, "cfg.yaml", "host: umbrel.local\nip: 192.168.1.20\n", "add config")
    code, out = run(["ci"], repo)
    assert code == 1
    assert "umbrel.local" in out or "192.168.1.20" in out
