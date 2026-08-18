"""leakguard secret + sensitive-file detection engine.

Zero-dependency (stdlib only). Kept in a sibling module so leakguard.py stays the
CLI/gate orchestration and this stays the detection *data* + matchers.

Design (high-precision, commit-time-gate posture):
  - Provider token rules are shape-specific enough to BLOCK a commit on their own.
    Each carries a cheap keyword pre-filter (gitleaks' core perf trick) so a growing
    rule list stays fast on large diffs: the regex only runs if a keyword substring
    is present in the line.
  - Noisier generic key=value + Shannon-entropy heuristics live here too but are
    WARN-only (surfaced by `audit`, never by the blocking hook/ci) so they cannot
    stop a legit commit. See `scan_generic_line` / `scan_entropy_line`.
  - Findings never expose the raw secret: `mask()` redacts before anything is printed.

Regexes are ported near-verbatim from gitleaks' config (Go RE2 -> Python `re`); the
entropy formula + base64/hex thresholds follow Yelp/detect-secrets. See tool/README.md.
"""
import hashlib
import math
import re
from collections import namedtuple
from fnmatch import fnmatch

# A provider rule. `allow` (optional compiled regex) suppresses a hit when it matches
# the captured value (e.g. AWS's own EXAMPLE doc keys). `keywords` is a cheap literal
# pre-filter; empty means "always run the regex".
SecretRule = namedtuple("SecretRule", "id keywords regex allow")


def _rule(rid, keywords, pattern, allow=None):
    return SecretRule(rid, tuple(k.lower() for k in keywords),
                      re.compile(pattern), re.compile(allow) if allow else None)


# ---------------- provider token rules (BLOCK) ----------------
SECRET_RULES = [
    # AWS access key id family (gitleaks omits AGPA/AIDA/AROA/... which git-secrets
    # includes; we keep the fuller set). AWS doc placeholders end in EXAMPLE.
    _rule("aws-access-key", ["akia", "asia", "abia", "acca", "agpa", "aida",
                             "aroa", "aipa", "anpa", "anva", "a3t"],
          r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b",
          allow=r".*EXAMPLE$"),
    _rule("github-pat", ["ghp_"], r"\b(ghp_[0-9A-Za-z]{36})\b"),
    _rule("github-oauth", ["gho_", "ghu_", "ghs_", "ghr_"], r"\b(gh[ousr]_[0-9A-Za-z]{36})\b"),
    _rule("github-fine-grained-pat", ["github_pat_"], r"\b(github_pat_\w{82})\b"),
    _rule("gitlab-pat", ["glpat-"], r"\b(glpat-[0-9A-Za-z_-]{20})\b"),
    _rule("gitlab-pat-routable", ["glpat-"],
          r"\b(glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7})\b"),
    _rule("npm-access-token", ["npm_"], r"\b(npm_[A-Za-z0-9]{36})\b"),
    _rule("pypi-upload-token", ["pypi-"], r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000})\b"),
    # Stripe SECRET/restricted keys only. Publishable pk_ keys are public by design.
    _rule("stripe-secret-key", ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "rk_prod_"],
          r"\b((?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99})\b"),
    _rule("sendgrid-api-key", ["sg."], r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
    # OpenAI keys embed T3BlbkFJ (base64 "OpenAI"); the marker keeps this precise.
    _rule("openai-api-key", ["t3blbkfj"],
          r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b"),
    # length as a range (not exact {93}AA) so a minor future format drift still matches;
    # the sk-ant-<type>- prefix already makes this high-precision.
    _rule("anthropic-api-key", ["sk-ant-"],
          r"\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{90,120})\b"),
    _rule("slack-bot-token", ["xox"], r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b"),
    _rule("slack-webhook-url", ["hooks.slack.com"],
          r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"),
    _rule("google-api-key", ["aiza"], r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    _rule("google-oauth-client-secret", ["gocspx-"], r"\b(GOCSPX-[0-9A-Za-z_-]{28})\b"),
    _rule("digitalocean-token", ["dop_v1_", "doo_v1_", "dor_v1_"],
          r"\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b"),
    # 3-segment Discord bot token shape (community regex; gitleaks' own is wrong).
    _rule("discord-bot-token", ["discord", "bot"],
          r"\b([MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b"),
    # Context-gated: the bare shapes are too generic without the provider keyword.
    _rule("twilio-api-key", ["twilio"], r"\b(SK[0-9a-fA-F]{32})\b"),
    _rule("mailgun-private-key", ["mailgun"], r"\b(key-[0-9a-f]{32})\b"),
    _rule("telegram-bot-token", ["telegram"], r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b"),
    # PEM private keys (any flavor). Content-based; no filename needed.
    _rule("private-key", ["private key"],
          r"(-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY(?: BLOCK)?-----)"),
    # Credentials embedded in a URL: postgres://user:pass@host, mysql://, redis://,
    # mongodb://, amqp://, https://. Universal gap across gitleaks/detect-secrets.
    # Username is OPTIONAL so the canonical no-user Redis form redis://:pass@host is
    # caught. Capture group 1 is the password so the placeholder denylist can vet it.
    _rule("connection-string-creds", ["://"],
          r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]*:([^/\s:@]{3,})@[^\s/]+"),
]

# WARN-tier rules: detected but surfaced only by `audit`, never the blocking gate.
# JWTs are dual-use (the jwt.io sample and tutorial/fixture tokens are everywhere and
# not secret), so blocking on them is too noisy for a high-precision commit gate.
WARN_SECRET_RULES = [
    _rule("jwt", ["eyj"],
          r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
]

# Captured values equal to one of these (case-insensitive) are placeholders, not
# secrets. Neither gitleaks nor detect-secrets ships a value denylist like this.
PLACEHOLDERS = {
    "changeme", "change-me", "change_me", "password", "passwd", "pwd", "pass", "secret",
    "xxx", "xxxx", "xxxxx", "example", "test", "test123", "dummy", "placeholder",
    "your-password", "your_password", "yourpassword", "redacted", "none", "null",
    "admin", "root", "user", "username", "mypassword", "hunter2", "todo",
    "1234", "12345", "123456", "abc123", "foobar", "changethis",
}

# Files whose *content* we never scan (lockfiles, minified bundles, sourcemaps) plus
# leakguard's own detector/test files, which legitimately contain token shapes.
# Basename globs (skip_path also matches these against the basename, so a bare name
# covers the file at any directory depth - no "*/name" duplicate needed).
SKIP_PATH_GLOBS = (
    "*.min.js", "*.min.css", "*.map",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "Gemfile.lock", "composer.lock", "go.sum",
    "detectors.py", "test_leakguard.py", ".leakguard-baseline.json",
)

# ---------------- sensitive-file rules ----------------
# BLOCK: a committed file of one of these names is almost always a real key/credential.
SENSITIVE_FILE_GLOBS = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "*.pfx", "*.p12", "*.jks", "*.keystore",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    "credentials",  # e.g. .aws/credentials
    "kubeconfig", "config",  # scoped to kube dirs below
    "*.ovpn", ".htpasswd",
)
# Names that would otherwise trip a BLOCK glob but are safe / public.
SENSITIVE_FILE_ALLOW = ("*.pub", "*.example", "*.sample", "*.template", "*.dist")
# WARN-only (surfaced by `audit`, never blocks): frequently-but-not-always sensitive.
# credentials.json / service-account*.json are here (not BLOCK) because mock OAuth/GCP
# test fixtures use those exact names; a real GCP key still BLOCKS via private-key content.
WARN_FILE_GLOBS = ("*.pem", "*.key", "*.tfvars", "terraform.tfstate",
                   "terraform.tfstate.backup", "known_hosts", "secrets.yml",
                   "secrets.yaml", "*.kdbx", "credentials.json", "service-account*.json")

# .env and variants are secret unless an explicit sample suffix.
_ENV = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$")
_ENV_ALLOW = re.compile(r"\.env\.(example|sample|template|dist|local\.example)$", re.I)


def mask(value):
    """Redact a matched secret for safe logging: reveal at most ~1/4 of the value.

    Enough of a hint to recognize which secret (prefix + a trailing char), but a
    short 9-20 char password no longer leaks 50-67% of itself. Prefix caps at 4,
    suffix at 2, and the revealed total never exceeds a quarter of the length, so
    the middle always keeps a solid run of stars regardless of length.
    """
    v = value.strip()
    if not v:
        return ""
    if len(v) <= 8:
        return v[0] + "*" * (len(v) - 1)
    show = max(3, len(v) // 4)          # total revealed chars, floor of 3
    pre = min(4, show - 1)              # leading hint, capped at 4
    suf = min(2, show - pre)            # trailing hint, capped at 2
    return f"{v[:pre]}{'*' * (len(v) - pre - suf)}{v[-suf:]}"


def fingerprint(kind, value):
    """Stable short hash of a finding, so a baseline can record it WITHOUT the raw
    value ever touching disk (the baseline file itself must never leak a secret)."""
    return hashlib.sha256(f"{kind}\x00{value}".encode("utf-8", "replace")).hexdigest()[:16]


def skip_path(path):
    """True if a file's content should not be scanned for SECRETS (lockfiles, minified,
    leakguard's own rule/test files). Topology detection is NOT subject to this - a
    private IP in a lockfile URL is still a real leak."""
    p = (path or "").strip()
    base = p.rsplit("/", 1)[-1]
    return any(fnmatch(p, g) or fnmatch(base, g) for g in SKIP_PATH_GLOBS)


def scan_secret_line(line, rules=SECRET_RULES):
    """Return a list of (rule_id, raw_value) findings for one added source line.

    Applies the keyword pre-filter, the per-rule allow regex, and the placeholder
    denylist. `line` should be a raw added line (no leading '+'). The raw value is
    returned (never printed directly) so callers can fingerprint it; mask() before
    display. Pass rules=WARN_SECRET_RULES to run the audit-only (non-blocking) rules.
    """
    low = line.lower()
    if "leakguard:allow" in low:
        return []
    out = []
    for rule in rules:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.regex.finditer(line):
            value = m.group(1) if m.lastindex else m.group(0)
            if rule.allow and rule.allow.search(value):
                continue
            if value.lower() in PLACEHOLDERS:
                continue
            out.append((rule.id, value))
            break  # one finding per rule per line is enough to fail the gate
    return out


def sensitive_file(path):
    """Return a reason string if `path` is a BLOCK-worthy sensitive file, else None."""
    p = (path or "").strip()
    if not p:
        return None
    base = p.rsplit("/", 1)[-1]
    if any(fnmatch(base, g) for g in SENSITIVE_FILE_ALLOW):
        return None
    if _ENV.search(p) and not _ENV_ALLOW.search(p):
        return "env file (may contain secrets)"
    # `config`/`credentials` are only sensitive inside kube/aws/gcloud dirs.
    if base in ("config", "credentials") and not re.search(r"(^|/)\.(kube|aws|config/gcloud|docker)/", p):
        return None
    if base == "kubeconfig" or any(fnmatch(base, g) for g in SENSITIVE_FILE_GLOBS):
        return "sensitive filename (key/credential file)"
    return None


def warn_file(path):
    """Return a reason if `path` is WARN-worthy (audit only), else None."""
    p = (path or "").strip()
    base = p.rsplit("/", 1)[-1]
    if any(fnmatch(base, g) for g in SENSITIVE_FILE_ALLOW):
        return None
    if any(fnmatch(base, g) for g in WARN_FILE_GLOBS):
        return "possibly sensitive file (review before pushing)"
    return None


def iter_added(diff, skip=True):
    """Yield (path, added_line) for each added content line in a unified diff.

    Tracks the current file, the +++ header, and any line carrying an inline
    `leakguard:allow`. When skip=True, files matching SKIP_PATH_GLOBS are omitted
    (secret scanning); pass skip=False to see every file (topology scanning, which
    must still inspect lockfiles). `added_line` has the leading '+' removed.
    """
    path = None
    for ln in diff.splitlines():
        if ln.startswith("+++ b/"):
            path = ln[6:].strip()
            continue
        if ln.startswith("+++") or ln.startswith("diff --git"):
            continue
        if not ln.startswith("+"):
            continue
        if skip and path and skip_path(path):
            continue
        if "leakguard:allow" in ln.lower():
            continue
        yield path, ln[1:]


def scan_diff_secrets(diff, limit=20):
    """Return [(rule_id, raw_value, path)] for provider secret hits in a diff.

    Raw values (mask() at the print site). Used by `audit`'s recent-diffs section.
    """
    findings = []
    for path, line in iter_added(diff):
        for rule_id, raw in scan_secret_line(line):
            findings.append((rule_id, raw, path))
            if len(findings) >= limit:
                return findings
    return findings


# ---------------- WARN-only heuristics (audit, never the blocking gate) ----------------
# Shannon entropy over a FIXED charset (detect-secrets' method): absent chars score 0.
_B64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
_HEX_CHARSET = "1234567890abcdefABCDEF"
_B64_LIMIT = 4.5   # detect-secrets Base64HighEntropyString default
_HEX_LIMIT = 3.0   # detect-secrets HexHighEntropyString default

# Only quoted string literals are considered for entropy (kills incidental noise).
_QUOTED = re.compile(r"""['"`]([A-Za-z0-9+/=_-]{20,200})['"`]""")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_B64_ONLY = re.compile(r"^[A-Za-z0-9+/=_-]+$")

# key=value assignment where the key name signals a credential. `auth`/`token` are
# required to be part of a compound word (auth_token) to avoid matching `author`.
_GENERIC = re.compile(r"""(?ix)
    \b( [\w.-]{0,40}?
        (?: api[_.-]?key | apikey | access[_.-]?key | client[_.-]?secret
          | secret | token | password | passwd | pwd | credential | creds
          | auth[_.-]?token | private[_.-]?key ) )
    \s* (?: :=|=>|==|=|:{1,3} ) \s*
    ['"`]? ([\w.=+/~-]{10,150}) ['"`]?
""")
# key names that look credential-ish but whose value is not a secret.
_GENERIC_ALLOW_KEY = re.compile(
    r"(?i)(?:^|[._-])(?:public_?key|api_?id|token_?type|token_?url|access_?key_?id|"
    r"csrf|xsrf|id_?token_?hint|key_?id|keyword|keyring|keyboard|monkey|donkey)$")
# ordinary words that clear a naive length/entropy gate but are never secrets.
_STOPWORDS = {"true", "false", "none", "null", "undefined", "localhost", "enabled",
              "disabled", "example", "default", "unknown", "bearer", "application",
              "authorization", "content-type", "text/plain", "your-token-here"}


def shannon(data, charset):
    """Shannon entropy of `data` measured over a fixed `charset` (bits/char)."""
    if not data:
        return 0.0
    entropy = 0.0
    for ch in charset:
        p = data.count(ch) / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_boring(value):
    """True if a candidate value is a placeholder / stopword / template / trivial."""
    low = value.lower()
    if low in PLACEHOLDERS or low in _STOPWORDS:
        return True
    if _UUID.match(value):
        return True
    if any(t in value for t in ("${", "{{", "<", ">", "%s", "%(")):
        return True
    if len(set(value)) <= 2:                      # all-one-or-two chars (aaaa, xyxy)
        return True
    deltas = {ord(b) - ord(a) for a, b in zip(value, value[1:])}
    return len(value) > 3 and len(deltas) == 1    # arithmetic run (abcd, 1234)


def scan_entropy_line(line):
    """Return [(kind, masked)] for high-entropy quoted strings on a line."""
    out = []
    for s in _QUOTED.findall(line):
        if _is_boring(s):
            continue
        if _HEX_ONLY.match(s):
            e = shannon(s, _HEX_CHARSET)
            if s.isdigit():                       # pure digits: taper the FP penalty
                e -= 1.2 / math.log2(len(s))
            if e >= _HEX_LIMIT:
                out.append(("hex-entropy", mask(s)))
        elif _B64_ONLY.match(s) and shannon(s, _B64_CHARSET) >= _B64_LIMIT:
            out.append(("base64-entropy", mask(s)))
    return out


def scan_generic_line(line):
    """Return [(key, masked)] for credential-shaped key=value assignments on a line."""
    out = []
    for m in _GENERIC.finditer(line):
        key, value = m.group(1), m.group(2)
        if _GENERIC_ALLOW_KEY.search(key) or _is_boring(value):
            continue
        if value.lower() in PLACEHOLDERS or shannon(value, _B64_CHARSET) < 3.0:
            continue                              # low-entropy value = likely not a secret
        out.append((key.strip(" .-_"), mask(value)))
    return out


def scan_diff_heuristic(diff, limit=40):
    """WARN-only pass: [(kind, masked, path)] from generic + entropy heuristics.

    Deliberately separate from scan_diff_secrets so callers can keep these OUT of the
    blocking gate. Skips lines already caught by a high-precision provider rule.
    """
    findings, seen = [], set()

    def add(kind, masked, path):
        if (masked, path) in seen:                # generic runs first, so its label wins
            return
        seen.add((masked, path))
        findings.append((kind, masked, path))

    for path, line in iter_added(diff):
        if scan_secret_line(line):                # already a hard finding; don't double-warn
            continue
        for rid, raw in scan_secret_line(line, WARN_SECRET_RULES):   # jwt etc.
            add(rid, mask(raw), path)
        for key, masked in scan_generic_line(line):
            add(f"generic:{key}", masked, path)
        for kind, masked in scan_entropy_line(line):
            add(kind, masked, path)
        if len(findings) >= limit:
            return findings[:limit]
    return findings
