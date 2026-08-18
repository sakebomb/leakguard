#!/usr/bin/env python3
"""leakguard - find and stop AI coding agents (and plain git) from leaking your
machine identity and internal topology into public git history.

DEFENSE
  leakguard hook                 pre-commit gate: block LAN identity + internal leaks in staged diff
  leakguard commit-msg <file>    commit-msg gate: block secrets/identity pasted into the message
  leakguard ci [--base REF]      CI gate: scan a commit range (for the GitHub Action)
  leakguard baseline [--report]  accept a repo's existing leaks (block only NEW ones); --report
                                 lists the accepted findings, secrets-to-rotate first
  leakguard audit                report LAN identity + secrets + .gitignore gaps in this repo
  leakguard harden               set safe git config + print agent-attribution guidance

RESEARCH / SELF-CHECK (PUBLIC data only)
  leakguard scan <user> [--deep] [--json]     what a GitHub account's public commits reveal
  leakguard dossier <user>                    full profile: identity + homelab + daily routine
  leakguard map <scan.json>                   Graphviz DOT homelab map from a `scan --deep --json` dump

Bypass a pre-commit false positive once:  LEAKGUARD_ALLOW=1 git commit ...
"""
import sys, os, re, json, subprocess, time, argparse
from collections import Counter, namedtuple
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # resolve sibling modules
import detectors  # noqa: E402  (sibling module; requires the sys.path insert above)

# ---------------- shared detection ----------------
# leaf-anchored: matches nas.local / user@umbrel.local, NOT mail.internal.bigcorp.com
LAN_HOST = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]{0,40}\.(?:local|lan|home|internal|home\.arpa)(?![a-zA-Z0-9.-])", re.I)
TSNET    = re.compile(r"\b[a-z0-9][a-z0-9-]{0,60}\.ts\.net\b", re.I)  # Tailscale MagicDNS: leaks the tailnet name
RFC1918  = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
HOMEPATH = re.compile(r"/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|[Cc]:\\Users\\[^\\\s]+")
# Secret + sensitive-file detection lives in the sibling detectors module (30+ provider
# rules, keyword pre-filter, allowlist layer, placeholder denylist, filename globs).
# well-known public defaults that are not real leaks (Docker/K8s/CI containers, loopback).
# `cluster.local` is the default Kubernetes DNS suffix (boilerplate, never a personal machine).
BENIGN   = re.compile(r"host\.docker\.internal|docker\.internal|cluster\.local|/home/(?:node|runner|vscode|appuser|coder|nonroot)/|(?<![\d.])127\.0\.0\.1(?![\d.])|172\.17\.\d{1,3}\.\d{1,3}|10\.244\.\d{1,3}\.\d{1,3}|10\.96\.\d{1,3}\.\d{1,3}|192\.168\.99\.\d{1,3}", re.I)
COAUTHOR = re.compile(r"(?im)^\s*co-authored-by:\s*(.*?)\s*<([^>]+)>")
# git-log identity format: author + committer + every Co-authored-by trailer (one line each)
LOG_IDS_FMT = "%ae%n%ce%n%(trailers:key=Co-authored-by,valueonly)"
TZ       = re.compile(r"([+-]\d{2}:?\d{2})$")
HOUR     = re.compile(r"T(\d{2}):")
MODEL    = re.compile(r"(Claude\s+(?:Sonnet|Opus|Haiku)\s+[0-9][0-9.]*)", re.I)
AGENTS   = [("Claude Code", r"anthropic\.com|claude code|co-authored-by:\s*claude"),
            ("Cursor", r"cursor\.com|cursoragent"), ("Aider", r"aider\.chat|\(aider\)"),
            ("OpenCode", r"opencode\.ai"), ("Codex", r"openai\.com|codex-connector")]
HARDWARE = [("Apple Mac mini", r"mac[-_]?mini"), ("Apple MacBook", r"macbook"), ("Apple iMac", r"\bimac\b"),
            ("Apple Mac Studio/Pro", r"mac[-_]?(studio|pro)"), ("UGREEN NAS", r"ugreen|dxp\d"),
            ("Synology NAS", r"synology|diskstation|\bds\d{2,}"), ("TrueNAS", r"truenas|freenas"),
            ("Unraid", r"unraid"), ("Raspberry Pi", r"raspberrypi|\brpi\b|pi-?hole"),
            ("Umbrel", r"umbrel"), ("Proxmox", r"proxmox|\bpve\b"), ("Home Assistant", r"homeassistant|hassio"),
            ("Bitaxe miner", r"bitaxe"), ("Generic NAS", r"\bnas\b")]

def c(code, s):  # color if tty
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s
red = lambda s: c("31", s); ylw = lambda s: c("33", s); grn = lambda s: c("32", s)

def sh(*args):
    return subprocess.run(args, capture_output=True, text=True)

# core.quotePath=false: git octal-escapes non-ASCII paths by default, which would let a
# secret/large file under a unicode-named path slip name lists AND the +++ b/ diff header.
def git(*args):
    return sh("git", "-c", "core.quotePath=false", *args).stdout.strip()

def git_out(*args):
    """Return (ok, stdout). ok is False when git exits non-zero (e.g. an unresolved ref)."""
    r = sh("git", "-c", "core.quotePath=false", *args)
    return (r.returncode == 0, r.stdout)

def machine_host(email):
    if not email or "@" not in email:
        return None
    h = email.rsplit("@", 1)[1].strip().lower()
    if LAN_HOST.search(h + " ") or ("." not in h and h not in ("localhost",) and "noreply" not in h):
        return h
    return None

def is_lan_identity(email):
    if not email:
        return False
    if machine_host(email):
        return True
    host = email.rsplit("@", 1)[-1] if "@" in email else ""
    return host == (os.uname().nodename if hasattr(os, "uname") else "")

BASELINE_FILE = ".leakguard-baseline.json"
MAX_SHOWN = 20  # cap findings printed per gate run, so a huge diff can't flood output
# topology/identity leaks. matched value is shown in full (it is the point), not masked.
TOPO_CHECKS = (("internal-hostname", LAN_HOST), ("tailscale-tailnet", TSNET),
               ("private-ip", RFC1918), ("home-path", HOMEPATH))
# A hard finding: kind, fpval (fingerprinted + baselined), display (printed), secret?, path.
# fpval excludes the path on purpose: a secret is a secret regardless of which file holds it.
Finding = namedtuple("Finding", "kind fpval display secret path")
Finding.__new__.__defaults__ = (None,)  # path optional

def name_only(*args):
    """Changed file paths from a git command, empty on git error."""
    ok, out = git_out(*args)
    return [ln for ln in out.splitlines() if ln.strip()] if ok else []

def load_baseline():
    """Set of accepted finding fingerprints from BASELINE_FILE (empty if none)."""
    try:
        with open(BASELINE_FILE) as fh:
            return set(json.load(fh).get("findings", {}))
    except (OSError, ValueError):
        return set()

def line_findings(line, path=None, skip_secrets=False):
    """Hard findings on one added line: topology (shown raw) + secrets (masked).

    Topology always runs (even in lockfiles); secret scanning is skipped for
    SKIP_PATH_GLOBS files (token-shape noise) via skip_secrets.
    """
    out = []
    clean = BENIGN.sub("", line)  # ignore well-known public defaults
    for label, pat in TOPO_CHECKS:
        m = pat.search(clean)
        if m:
            out.append(Finding(label, m.group(0), m.group(0), False, path))
    if not skip_secrets:
        for rid, raw in detectors.scan_secret_line(line):
            out.append(Finding(rid, raw, detectors.mask(raw), True, path))
    return out

def oversized(paths, size_fn):
    """Findings for staged/committed files above LEAKGUARD_MAX_KB (default 500)."""
    try:
        max_kb = int(os.environ.get("LEAKGUARD_MAX_KB", "500"))
    except ValueError:
        max_kb = 500
    out = []
    for p in paths:
        kb = size_fn(p)
        if kb is not None and kb > max_kb:
            out.append(Finding("large-file", p, f"{p} ({kb} KB > {max_kb} KB)", False, p))
    return out

def collect_findings(diff, files, size_fn=None):
    """All hard findings across a diff + changed-file list (topology, secrets,
    sensitive filenames, and oversized files when size_fn is given)."""
    out = []
    for path, line in detectors.iter_added(diff, skip=False):  # topology sees lockfiles too
        out += line_findings(line, path, skip_secrets=detectors.skip_path(path))
    for p in files:
        reason = detectors.sensitive_file(p)
        if reason:
            out.append(Finding("sensitive-file", p, f"{p} - {reason}", False, p))
    if size_fn:
        out += oversized(files, size_fn)
    return out

def message_findings(text):
    """Hard findings inside commit-message text (git-secrets' commit-msg vector)."""
    out = []
    for line in (text or "").splitlines():
        out += [f._replace(display=f.display + "  (commit message)") for f in line_findings(line)]
    return out

def report_findings(findings, baseline):
    """Print findings not in the baseline (masking secrets). Returns True if any block."""
    fresh = [f for f in findings if detectors.fingerprint(f.kind, f.fpval) not in baseline]
    if fresh:
        print(red("FOUND:"))
        for f in fresh[:MAX_SHOWN]:
            loc = f"  in {f.path}" if f.path and f.path not in f.display else ""
            print(f"    [{f.kind}] {f.display}{loc}")
        if len(fresh) > MAX_SHOWN:
            print(ylw(f"    ... and {len(fresh) - MAX_SHOWN} more (showing first {MAX_SHOWN})"))
    suppressed = len(findings) - len(fresh)
    if suppressed:
        print(ylw(f"  ({suppressed} known finding(s) suppressed by {BASELINE_FILE})"))
    return bool(fresh)

def staged_kb(p):
    ok, out = git_out("cat-file", "-s", f":{p}")
    return int(out.strip()) // 1024 if ok and out.strip().isdigit() else None

def head_kb(p):
    ok, out = git_out("cat-file", "-s", f"HEAD:{p}")
    return int(out.strip()) // 1024 if ok and out.strip().isdigit() else None

# ---------------- gh (PUBLIC data, for scan/dossier) ----------------
def gh(args, accept=None):
    cmd = ["gh", "api"] + args
    if accept: cmd += ["-H", f"Accept: {accept}"]
    for a in range(5):
        r = sh(*cmd)
        if r.returncode == 0:
            try: return json.loads(r.stdout)
            except Exception: return None
        if "rate limit" in (r.stdout + r.stderr).lower():
            time.sleep(30 * (a + 1)); continue
        return None
    return None

# ---------------- DEFENSE subcommands ----------------
def cmd_hook(_):
    if os.environ.get("LEAKGUARD_ALLOW") == "1":
        print(ylw("leakguard: bypassed via LEAKGUARD_ALLOW=1")); return 0
    if not git_out("rev-parse", "--git-dir")[0]:
        # git broken/missing or not a repo: fail CLOSED, never wave a commit through blind
        print(red("leakguard: not a git repository (or git unavailable) - failing closed")); return 1
    fail = False
    email = git("config", "user.email")
    if is_lan_identity(email):
        print(red(f"BLOCK: commit identity is a LAN/auto hostname: {email}"))
        print("  -> run: leakguard harden   (or: git config user.email you@users.noreply.github.com)")
        fail = True
    diff = git("diff", "--cached")
    files = name_only("diff", "--cached", "--name-only", "--diff-filter=ACM")
    if report_findings(collect_findings(diff, files, size_fn=staged_kb), load_baseline()):
        fail = True
    if fail:
        print(ylw("\nBlocked by leakguard. Fix it, or bypass once: LEAKGUARD_ALLOW=1 git commit ..."))
        return 1
    return 0

def cmd_ci(a):
    base = a.base or os.environ.get("GITHUB_BASE_REF") or ""
    if base:
        # PR: diff base..HEAD. Try origin/<base> then a local <base> ref.
        ok, diff = git_out("diff", f"origin/{base}...HEAD")
        rng = f"origin/{base}...HEAD"
        if not ok:
            ok, diff = git_out("diff", f"{base}...HEAD"); rng = f"{base}...HEAD"
        if not ok:
            # fail CLOSED: never report clean when we could not compute the range
            print(red(f"leakguard CI ERROR: cannot resolve base ref '{base}'."))
            print(ylw("  Check out with fetch-depth: 0 so the base branch is available:"))
            print("    - uses: actions/checkout@v4\n      with: { fetch-depth: 0 }")
            return 2
        # include co-author trailers: the dominant leak vector rides there, not in %ae/%ce
        _, ids_out = git_out("log", f"--format={LOG_IDS_FMT}", rng)
        _, msgs = git_out("log", "--format=%B", rng)
        files = name_only("diff", "--name-only", "--diff-filter=ACM", rng)
    else:
        # push / no base: scan the tip commit only
        ok, diff = git_out("show", "HEAD")
        if not ok:
            # fail CLOSED: empty/unborn/detached HEAD or non-repo must not report "clean"
            print(red("leakguard CI ERROR: cannot read HEAD (empty repo, unborn/detached HEAD, or not a git repository)."))
            return 2
        _, ids_out = git_out("log", "-1", f"--format={LOG_IDS_FMT}")
        _, msgs = git_out("log", "-1", "--format=%B")
        files = name_only("diff-tree", "--no-commit-id", "--name-only", "--diff-filter=ACM", "-r", "HEAD")
    fail = False
    findings = collect_findings(diff, files, size_fn=head_kb) + message_findings(msgs)
    if report_findings(findings, load_baseline()):
        fail = True
    for e in set((ids_out or "").splitlines()):
        if e and is_lan_identity(e):
            print(red(f"FOUND (LAN commit identity in range): {e}")); fail = True
    print((red("leakguard CI: leaks found") if fail else grn("leakguard CI: clean")))
    return 1 if fail else 0

def scan_tree_findings():
    """All hard findings across files COMMITTED in HEAD (not the staged index).

    HEAD-only on purpose: baselining reads only what is already committed, so a secret
    you just staged cannot be laundered into the accept-list in one step. Topology is
    scanned even in lockfiles; secrets are skipped there (SKIP_PATH_GLOBS).
    """
    findings = []
    for p in name_only("ls-tree", "-r", "--name-only", "HEAD"):
        reason = detectors.sensitive_file(p)
        if reason:
            findings.append(Finding("sensitive-file", p, f"{p} - {reason}", False, p))
        ok, blob = git_out("show", f"HEAD:{p}")        # committed content only
        if not ok or "\x00" in blob[:2048]:            # skip unreadable / binary files
            continue
        skip_sec = detectors.skip_path(p)
        for line in blob.splitlines():
            findings += line_findings(line, p, skip_secrets=skip_sec)
    return findings

def baseline_report():
    """Read-only triage of an existing baseline: what was accepted, secrets to rotate first."""
    try:
        findings = json.load(open(BASELINE_FILE)).get("findings", {})
    except (OSError, ValueError):
        print(red(f"no readable {BASELINE_FILE} - run: leakguard baseline")); return 1
    secrets = [v for v in findings.values() if v.get("secret")]
    topo = [v for v in findings.values() if not v.get("secret") and v.get("kind") != "sensitive-file"]
    files = [v for v in findings.values() if v.get("kind") == "sensitive-file"]
    print(f"== leakguard baseline report ==\n{len(findings)} accepted finding(s) in {BASELINE_FILE}\n")
    print(red(f"SECRETS TO ROTATE ({len(secrets)}):") if secrets else grn("secrets to rotate: none"))
    for v in secrets:
        print(f"  [{v['kind']}] {v.get('hint', '')}" + (f"  {v['path']}" if v.get("path") else ""))
    for title, group in (("identity / topology", topo), ("sensitive files", files)):
        if group:
            print(ylw(f"\n{title} ({len(group)}):"))
            for v in group:
                print(f"  [{v['kind']}] {v.get('hint', '')}")
    return 0

def cmd_baseline(a):
    if a.report:
        return baseline_report()
    if not git_out("rev-parse", "--git-dir")[0]:
        print(red("leakguard: not a git repository")); return 1
    findings = scan_tree_findings()
    data = {"version": 1, "findings": {}}
    for f in findings:
        fp = detectors.fingerprint(f.kind, f.fpval)   # hash only: the file never stores a raw secret
        data["findings"][fp] = {"kind": f.kind, "path": f.path, "secret": f.secret,
                                "hint": detectors.mask(f.fpval) if f.secret else f.display}
    with open(BASELINE_FILE, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True); fh.write("\n")
    print(grn(f"wrote {BASELINE_FILE}: {len(data['findings'])} accepted finding(s) from HEAD."))
    print(ylw("hook/ci now suppress these; NEW leaks still block. Commit the baseline to share it."))
    secret_ct = sum(1 for f in findings if f.secret)
    if secret_ct:
        print(red(f"\nWARNING: {secret_ct} of these are live SECRET(s) already committed."))
        print(red("Baselining only silences the alert - it does NOT make them safe. ROTATE them now."))
    return 0

def cmd_commit_msg(a):
    if os.environ.get("LEAKGUARD_ALLOW") == "1":
        return 0
    try:
        text = open(a.file, encoding="utf-8", errors="replace").read()
    except OSError:
        # deliberately fail OPEN here (unlike hook/ci): a transient FS error reading the
        # temp message file must not block every commit. git always supplies a real path.
        return 0
    body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
    if report_findings(message_findings(body), load_baseline()):
        print(ylw("\nSecret/identity leak in the commit message. Bypass once: LEAKGUARD_ALLOW=1 git commit ..."))
        return 1
    return 0

def gitignore_gaps(tracked):
    """Standard .gitignore entries missing for the project types present in `tracked`."""
    try:
        present = set(open(".gitignore").read().split())
    except OSError:
        present = set()
    bases = {os.path.basename(t) for t in tracked}
    want = [".env", "*.pem", "*.key"]
    if any(t.endswith(".py") for t in tracked) or {"requirements.txt", "pyproject.toml"} & bases:
        want += ["__pycache__/", "*.pyc"]
    if "package.json" in bases:
        want += ["node_modules/"]
    if any(t.endswith(".tf") for t in tracked):
        want += [".terraform/", "*.tfstate", "*.tfvars"]
    return [w for w in dict.fromkeys(want) if w not in present]

def cmd_audit(_):
    print("== leakguard audit ==")
    email, name = git("config", "user.email"), git("config", "user.name")
    print(f"current identity: {name or '<unset>'} <{email or '<unset>'}>")
    print(red("  ! LAN/auto identity - leaks your machine name on every commit")
          if is_lan_identity(email) else grn("  ok - not a LAN identity"))
    ids = git("log", "-200", "--format=%ae%n%ce%n%(trailers:key=Co-authored-by,valueonly)").splitlines()
    lan = sorted({e for e in ids if e and LAN_HOST.search(e + " ")})
    print("\nLAN identities in recent history:")
    print("\n".join("  ! " + x for x in lan) if lan else grn("  none found"))
    diff = git("log", "-50", "-p")
    hosts = sorted(set(m.group(0).lower() for m in LAN_HOST.finditer(diff)))[:20]
    print("\ninternal hosts in recent diffs:")
    print("\n".join("  ! " + x for x in hosts) if hosts else grn("  none found"))
    print("\nsecrets in recent diffs:")
    secrets = detectors.scan_diff_secrets(diff)
    if secrets:
        for rid, raw, path in secrets:
            print(red(f"  ! [{rid}] {detectors.mask(raw)}" + (f"  ({path})" if path else "")))
    else:
        print(grn("  none found"))
    print("\npossible secrets (entropy / keyword heuristics - review, not blocking):")
    heur = detectors.scan_diff_heuristic(diff)
    if heur:
        for kind, masked, path in heur:
            print(ylw(f"  ~ [{kind}] {masked}" + (f"  ({path})" if path else "")))
    else:
        print(grn("  none found"))
    print("\nsensitive files (recent + tracked):")
    tracked = name_only("ls-files")
    files = set(name_only("log", "-50", "--name-only", "--format=")) | set(tracked)
    flagged = sorted({f"{p} - {r}" for p in files
                      for r in (detectors.sensitive_file(p) or detectors.warn_file(p),) if r})
    print("\n".join("  ! " + x for x in flagged) if flagged else grn("  none found"))
    print("\n.gitignore gaps (standard entries missing for this project):")
    gaps = gitignore_gaps(tracked)
    print("\n".join("  ! missing: " + g for g in gaps) if gaps else grn("  none - key patterns covered"))
    return 0

def cmd_harden(_):
    print("== leakguard harden ==")
    sh("git", "config", "--global", "user.useConfigOnly", "true")
    print(grn("set: user.useConfigOnly=true (git errors instead of inventing user@hostname.local)"))
    email = git("config", "--global", "user.email")
    if not email or is_lan_identity(email):
        print(ylw("action needed: set a clean global identity, e.g."))
        print("    git config --global user.name  'Your Name'")
        print("    git config --global user.email 'you@users.noreply.github.com'")
    else:
        print(grn(f"global identity looks clean: {email}"))
    print("""
Disable AI-agent attribution trailers (they leak agent + model, sometimes your LAN identity):
  Claude Code  ~/.claude/settings.json:  {"attribution": {"commit": "", "pr": ""}}
               (older builds: "includeCoAuthoredBy": false, "gitAttribution": false)
  VS Code      settings.json:            "git.addAICoAuthor": "off"
  Aider        flags:                    --no-attribute-author --no-attribute-committer

Install the hooks globally (pre-commit scans the diff; commit-msg scans the message):
  mkdir -p ~/.git-hooks
  printf '#!/usr/bin/env sh\\nexec leakguard hook\\n' > ~/.git-hooks/pre-commit
  printf '#!/usr/bin/env sh\\nexec leakguard commit-msg "$1"\\n' > ~/.git-hooks/commit-msg
  chmod +x ~/.git-hooks/pre-commit ~/.git-hooks/commit-msg
  git config --global core.hooksPath ~/.git-hooks

Adopt leakguard on a repo that already has leaks (accept them, block only NEW ones):
  leakguard baseline        # writes .leakguard-baseline.json (hashes only, no raw secrets)""")
    return 0

# ---------------- RESEARCH subcommands (PUBLIC data) ----------------
def fetch_author_commits(user, pages):
    items = []
    for p in range(1, pages + 1):
        d = gh(["-X", "GET", "search/commits", "-f", f"q=author:{user}", "-f", "per_page=100", "-f", f"page={p}"],
               accept="application/vnd.github.cloak-preview+json")
        got = (d or {}).get("items", []) if isinstance(d, dict) else []
        items += got
        if len(got) < 100: break
        time.sleep(3)
    return items

def fingerprint(items, deep):
    f = {k: Counter() for k in ("hosts","hw","agents","models","tz","coauth","ihosts","ips","paths","hours")}
    f["repos"] = set(); f["diffs"] = 0
    for it in items:
        cm = it.get("commit") or {}; msg = cm.get("message") or ""
        f["repos"].add((it.get("repository") or {}).get("full_name"))
        for e in ((cm.get("author") or {}).get("email"), (cm.get("committer") or {}).get("email")):
            h = machine_host(e)
            if h:
                f["hosts"][h] += 1
                for n, p in HARDWARE:
                    if re.search(p, h, re.I): f["hw"][n] += 1
        for m in COAUTHOR.finditer(msg): f["coauth"][m.group(2)] += 1
        for n, p in AGENTS:
            if re.search(p, msg, re.I): f["agents"][n] += 1
        for m in MODEL.finditer(msg): f["models"][m.group(1)] += 1
        d = (cm.get("author") or {}).get("date") or ""
        mt = TZ.search(d.strip()); mh = HOUR.search(d)
        if mt: f["tz"][mt.group(1)] += 1
        if mh: f["hours"][int(mh.group(1))] += 1
    if deep:
        for it in items[:120]:
            repo = (it.get("repository") or {}).get("full_name"); sha = it.get("sha")
            if not (repo and sha): continue
            cj = gh([f"repos/{repo}/commits/{sha}"]); f["diffs"] += 1
            if isinstance(cj, dict):
                patch = "\n".join((x.get("patch") or "") for x in (cj.get("files") or []))
                for m in LAN_HOST.finditer(patch): f["ihosts"][m.group(0).lower()] += 1
                for m in RFC1918.finditer(patch): f["ips"][m.group(0)] += 1
                for m in HOMEPATH.finditer(patch): f["paths"][m.group(0)] += 1
            if f["diffs"] % 20 == 0: time.sleep(2)
    return f

def cmd_scan(a):
    items = fetch_author_commits(a.user, a.pages)
    if not items:
        print(f"no public commits for author:{a.user} (or rate-limited)"); return 1
    f = fingerprint(items, a.deep)
    if a.json:
        keys = ["hosts","hw","agents","models","tz","coauth","ihosts","ips","paths","hours"]
        out = {"user": a.user, "commits": len(items), "repos": len(f["repos"])}
        out.update({k: dict(f[k]) for k in keys})
        print(json.dumps(out, indent=1)); return 0
    P = lambda cnt, n=12: ", ".join(f"{k} (x{v})" for k, v in cnt.most_common(n)) or "none"
    print(f"\n=== leakguard scan: what @{a.user}'s public commits reveal ===")
    print(f"commits: {len(items)}  repos: {len(f['repos'])}")
    print(f"[MACHINE IDENTITY] {P(f['hosts'])}\n[HARDWARE] {P(f['hw'])}\n[AI AGENT] {P(f['agents'])}")
    print(f"[AGENT MODEL] {P(f['models'])}\n[TIMEZONE] {P(f['tz'])}\n[CO-AUTHOR IDS] {P(f['coauth'])}")
    if a.deep:
        print(f"\n--- deep ({f['diffs']} diffs) ---")
        print(f"[INTERNAL HOSTS] {P(f['ihosts'],20)}\n[LAN IPs] {P(f['ips'],20)}\n[HOME PATHS] {P(f['paths'],10)}")
    exposed = bool(f["hosts"] or f["ihosts"] or f["ips"])
    print("\nVERDICT: " + (red("EXPOSED") if exposed else grn("clean")))
    return 0

def cmd_dossier(a):
    prof = gh([f"users/{a.user}"]) or {}
    items = fetch_author_commits(a.user, a.pages)
    if not items:
        print(f"no public commits for author:{a.user}"); return 1
    f = fingerprint(items, True)
    subs = Counter(".".join(ip.split(".")[:3]) + ".0/24" for ip in f["ips"])
    P = lambda cnt, n=15: ", ".join(f"{k} (x{v})" for k, v in cnt.most_common(n)) or "none"
    hours = f["hours"]; mx = max(hours.values()) if hours else 0
    dark = sorted(set(range(24)) - set(hours.keys()))
    print(f"# OSINT dossier (PUBLIC git only): @{a.user}\n\n> Reconstructed passively. Nothing was probed.\n")
    print("## 1. Who\n"
          f"- Name: {prof.get('name') or 'n/a'}\n- Employer: {prof.get('company') or 'n/a'}\n"
          f"- Location: {prof.get('location') or 'n/a'}\n- Site: {prof.get('blog') or 'n/a'}  X: {prof.get('twitter_username') or 'n/a'}\n"
          f"- Email: {prof.get('email') or 'n/a'}  Repos: {prof.get('public_repos')}  Since: {prof.get('created_at')}\n"
          f"- Co-author IDs leaked: {P(f['coauth'])}\n")
    print(f"## 2. Machine & agent\n- Region: {P(f['tz'])}\n- Agent: {P(f['agents'])}  Model: {P(f['models'])}\n")
    print(f"## 3. Home network\n- Subnets: {P(subs)}\n- Hostnames ({len(f['ihosts'])}): {P(f['ihosts'],40)}\n- LAN IPs ({len(f['ips'])}): {P(f['ips'],40)}\n")
    print("## 4. Daily routine (local-time commit activity)\n```")
    for h in range(24):
        n = hours.get(h, 0)
        print(f"  {h:02d}:00  {'#'*int(round(32*n/mx)) if mx else '':32s} {n}")
    print("```")
    print(f"- Dark hours (asleep/away): {', '.join(f'{h:02d}:00' for h in dark) or 'none'}\n\n*Sample: {len(items)} commits / {len(f['repos'])} repos.*")
    return 0

def cmd_map(a):
    from map_render import emit_dot  # local module
    emit_dot(json.load(open(a.jsonfile)))
    return 0

# ---------------- dispatch ----------------
def build_parser():
    p = argparse.ArgumentParser(prog="leakguard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hook").set_defaults(fn=cmd_hook)
    ci = sub.add_parser("ci"); ci.add_argument("--base", default=None); ci.set_defaults(fn=cmd_ci)
    sub.add_parser("audit").set_defaults(fn=cmd_audit)
    sub.add_parser("harden").set_defaults(fn=cmd_harden)
    bl = sub.add_parser("baseline"); bl.add_argument("--report", action="store_true")
    bl.set_defaults(fn=cmd_baseline)
    cm = sub.add_parser("commit-msg"); cm.add_argument("file"); cm.set_defaults(fn=cmd_commit_msg)
    sc = sub.add_parser("scan"); sc.add_argument("user"); sc.add_argument("--deep", action="store_true")
    sc.add_argument("--json", action="store_true"); sc.add_argument("--pages", type=int, default=3); sc.set_defaults(fn=cmd_scan)
    do = sub.add_parser("dossier"); do.add_argument("user"); do.add_argument("--pages", type=int, default=2); do.set_defaults(fn=cmd_dossier)
    mp = sub.add_parser("map"); mp.add_argument("jsonfile"); mp.set_defaults(fn=cmd_map)
    return p

def main():
    a = build_parser().parse_args()
    sys.exit(a.fn(a))

if __name__ == "__main__":
    main()
