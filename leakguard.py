#!/usr/bin/env python3
"""leakguard - find and stop AI coding agents (and plain git) from leaking your
machine identity and internal topology into public git history.

DEFENSE
  leakguard hook                 pre-commit gate: block LAN identity + internal leaks in staged diff
  leakguard ci [--base REF]      CI gate: scan a commit range (for the GitHub Action)
  leakguard audit                report LAN identity in this repo's config + recent history
  leakguard harden               set safe git config + print agent-attribution guidance

RESEARCH / SELF-CHECK (PUBLIC data only)
  leakguard scan <user> [--deep] [--json]     what a GitHub account's public commits reveal
  leakguard dossier <user>                    full profile: identity + homelab + daily routine
  leakguard map <scan.json>                   Graphviz DOT homelab map from a `scan --deep --json` dump

Bypass a pre-commit false positive once:  LEAKGUARD_ALLOW=1 git commit ...
"""
import sys, os, re, json, subprocess, time, argparse
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # resolve sibling map_render

# ---------------- shared detection ----------------
# leaf-anchored: matches nas.local / user@umbrel.local, NOT mail.internal.bigcorp.com
LAN_HOST = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]{0,40}\.(?:local|lan|home|internal|home\.arpa)(?![a-zA-Z0-9.-])", re.I)
TSNET    = re.compile(r"\b[a-z0-9][a-z0-9-]{0,60}\.ts\.net\b", re.I)  # Tailscale MagicDNS: leaks the tailnet name
RFC1918  = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
HOMEPATH = re.compile(r"/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|[Cc]:\\Users\\[^\\\s]+")
SECRET   = re.compile(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50}|xox[baprs]-[A-Za-z0-9-]{10}|AIza[0-9A-Za-z_-]{35}|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")
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

def git(*args):
    return sh("git", *args).stdout.strip()

def git_out(*args):
    """Return (ok, stdout). ok is False when git exits non-zero (e.g. an unresolved ref)."""
    r = sh("git", *args)
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

def scan_added_lines(diff, label, pat):
    hits = []
    for ln in diff.splitlines():
        if not ln.startswith("+") or ln.startswith("+++"):
            continue  # only real added content, never the +++ file-header line
        if "leakguard:allow" in ln:
            continue  # inline suppression escape hatch
        if pat.search(BENIGN.sub("", ln)):  # ignore well-known public defaults
            hits.append(ln)
            if len(hits) >= 5:
                break
    if hits:
        print(red(f"FOUND ({label}):"))
        for h in hits: print("    " + h[:160])
    return bool(hits)

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
    for label, pat in (("internal hostname", LAN_HOST), ("tailscale tailnet name", TSNET),
                       ("private/LAN IP", RFC1918), ("home directory path", HOMEPATH),
                       ("possible secret", SECRET)):
        if scan_added_lines(diff, label, pat): fail = True
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
    else:
        # push / no base: scan the tip commit only
        ok, diff = git_out("show", "HEAD")
        if not ok:
            # fail CLOSED: empty/unborn/detached HEAD or non-repo must not report "clean"
            print(red("leakguard CI ERROR: cannot read HEAD (empty repo, unborn/detached HEAD, or not a git repository)."))
            return 2
        _, ids_out = git_out("log", "-1", f"--format={LOG_IDS_FMT}")
    fail = False
    for label, pat in (("internal hostname", LAN_HOST), ("tailscale tailnet name", TSNET),
                       ("private/LAN IP", RFC1918), ("home directory path", HOMEPATH),
                       ("possible secret", SECRET)):
        if scan_added_lines(diff, label, pat): fail = True
    for e in set((ids_out or "").splitlines()):
        if e and is_lan_identity(e):
            print(red(f"FOUND (LAN commit identity in range): {e}")); fail = True
    print((red("leakguard CI: leaks found") if fail else grn("leakguard CI: clean")))
    return 1 if fail else 0

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

Install the pre-commit hook globally:
  mkdir -p ~/.git-hooks
  printf '#!/usr/bin/env sh\\nexec leakguard hook\\n' > ~/.git-hooks/pre-commit
  chmod +x ~/.git-hooks/pre-commit
  git config --global core.hooksPath ~/.git-hooks""")
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
