# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Supply chain monitoring — parse agent install commands and assess risk."""

import hashlib
import json
import re
import subprocess

INSTALL_PATTERNS = {
    "npm install": "npm",
    "npm i ": "npm",
    "yarn add": "yarn",
    "pnpm add": "pnpm",
    "pip install": "pip",
    "pip3 install": "pip",
    "cargo add": "cargo",
    "go get": "go",
    "gem install": "gem",
    "brew install": "brew",
    "apt install": "apt",
    "apt-get install": "apt",
    "npx ": "npx",
}

# Flags that take no argument — skip the token
SKIP_FLAGS = {
    "--save-dev",
    "--global",
    "-g",
    "--break-system-packages",
    "--no-cache-dir",
    "--quiet",
    "-q",
    "-U",
    "--upgrade",
    "-y",
    "--yes",
    "--force",
    "-D",
    "--dev",
    "--save",
    "--save-exact",
    "--production",
    "--legacy-peer-deps",
    "--no-optional",
    "--no-default-features",
    "--optional",
    "--user",
    "--system",
}

# Flags that consume the NEXT token as their argument — skip both
FLAGS_WITH_VALUES = {
    "--index-url",
    "--extra-index-url",
    "-i",
    "--trusted-host",
    "--constraint",
    "-c",
    "--config-settings",
    "--features",
    "--platform",
    "--implementation",
    "--python-version",
    "--target",
    "-t",
    "--prefix",
    "--root",
}

REGISTRIES = {
    "npm": "npmjs.org",
    "yarn": "npmjs.org",
    "pnpm": "npmjs.org",
    "npx": "npmjs.org",
    "pip": "pypi.org",
    "cargo": "crates.io",
    "go": "proxy.golang.org",
    "gem": "rubygems.org",
    "brew": "formulae.brew.sh",
    "apt": "apt",
}

# Tokens that are NEVER packages — shell noise
SHELL_NOISE = {
    "tail",
    "head",
    "grep",
    "cat",
    "echo",
    "wc",
    "tee",
    "sort",
    "uniq",
    "xargs",
    "sed",
    "awk",
    "tr",
    "true",
    "false",
    "test",
    "sleep",
    "|",
    "||",
    "&&",
    ";",
    "\\",
    "2>&1",
    "2>/dev/null",
    ">",
    ">>",
    "python3",
    "python",
    "python3.12",
    "python3.14",
    "python3.11",
    "pip",
    "pip3",
    "install",
    "docker-compose",
    "docker",
    "exec",
    "-T",
    "source",
    "activate",
    "cd",
    "mkdir",
    "rm",
    "cp",
    "mv",
    "chmod",
    "chown",
    "sudo",
    "sh",
    "-c",
    "bash",
    "done",
    "user-local",
    "user",
    "local",
    "global",
    "system",
    "start",
    "enable",
    "service",
    "restart",
    "status",
    "stop",
    "daemon-reload",
    "systemctl",
}

KNOWN_TYPOSQUATS = {
    "requets": "requests",
    "requsts": "requests",
    "reqeusts": "requests",
    "request": "requests",
    "colurs": "colors",
    "colers": "colors",
    "axois": "axios",
    "axio": "axios",
    "axioss": "axios",
    "loddash": "lodash",
    "loadash": "lodash",
    "lodahs": "lodash",
    "expresss": "express",
    "exress": "express",
    "underscor": "underscore",
    "undescore": "underscore",
    "beutifulsoup": "beautifulsoup4",
    "djanga": "django",
    "dajngo": "django",
    "flassk": "flask",
    "flaask": "flask",
    "numpyy": "numpy",
    "numpi": "numpy",
    "pandass": "pandas",
    "pnadas": "pandas",
    "tenserflow": "tensorflow",
    "tensorflw": "tensorflow",
    "pytorh": "pytorch",
    "pytroch": "pytorch",
}

HIGH_RISK_PACKAGES = {
    "mitmproxy": "Network MITM proxy",
    "cryptography": "Crypto operations",
    "paramiko": "SSH client — remote access",
    "fabric": "Remote execution framework",
    "alpaca-trade-api": "Live trading API",
    "yfinance": "Financial data API",
    "stripe": "Payment processing",
    "plaid": "Bank account access",
    "plaid-python": "Bank account access",
    "subprocess32": "Process execution",
    "pyautogui": "Screen/input automation",
    "selenium": "Browser automation",
    "playwright": "Browser automation",
}

SKIP_WORDS = {
    "to",
    "for",
    "and",
    "or",
    "the",
    "in",
    "on",
    "at",
    "by",
    "up",
    "is",
    "it",
    "no",
    "do",
    "if",
    "of",
    "as",
    "so",
    "we",
    "an",
    "be",
    "he",
    "me",
    "my",
    "load",
    "gate",
    "quality",
    "scripts",
    "tests",
    "build",
    "install",
    "run",
    "test",
    "check",
    "set",
    "get",
    "all",
    "new",
    "use",
    "add",
    "api",
    "app",
    "bin",
    "lib",
    "src",
    "out",
    "log",
    "env",
    "dev",
    "opt",
    "var",
    "tmp",
    "not",
    "but",
    "bi",
    "py",
    "go",
    "sh",
    "ok",
    "os",
    "re",
    "id",
}

# Valid package name pattern: starts with letter/@ then alphanumeric/dash/dot/underscore/slash(scoped)
_VALID_PKG_RE = re.compile(r"^[a-zA-Z@][a-zA-Z0-9._/:-]*[a-zA-Z0-9]$|^[a-zA-Z][a-zA-Z0-9]$")


def _is_valid_package_name(name):
    """Check if a token looks like a real package name."""
    if not name or len(name) < 2:
        return False
    # Special entries (editable install, from requirements.txt) — valid but not "packages"
    if name.startswith("("):
        return True  # validated separately, categorized as "metadata"
    # 1-char tokens are never packages; 2-char checked against SKIP_WORDS above
    if len(name) < 2:
        return False
    if name.lower() in SKIP_WORDS or name.lower() in SHELL_NOISE:
        return False
    # No trailing punctuation
    if name[-1] in (")", "}", '"', "'", ",", ";", "\\"):
        return False
    if name.endswith("-"):
        return False
    # Scoped npm (@scope/pkg) and Go modules (github.com/x/y) allow /
    if name.startswith("@") or name.startswith("github.com/"):
        return _VALID_PKG_RE.match(name) is not None
    # Regular packages: no / allowed (would be a path)
    if "/" in name:
        return False
    return _VALID_PKG_RE.match(name) is not None


LOCKFILES = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "pip",
    "Pipfile.lock": "pip",
    "poetry.lock": "pip",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "Gemfile.lock": "gem",
}


def _isolate_install_segment(command):
    """Split on shell operators and find the segment with the install keyword."""
    # Split on |, &&, ||, ; — take the segment that contains an install pattern
    segments = re.split(r"\s*(?:\|\||&&|[|;])\s*", command)
    for seg in segments:
        seg = seg.strip()
        for prefix in INSTALL_PATTERNS:
            if prefix in seg:
                # Strip redirects
                seg = re.sub(r"\s*2>[>&/\w]*", "", seg)
                seg = re.sub(r"\s*>[>&\s/\w]*$", "", seg)
                return seg.strip()
    return None


def _strip_docker_prefix(segment):
    """If command starts with docker/docker-compose, find the inner install command."""
    for prefix in INSTALL_PATTERNS:
        idx = segment.find(prefix)
        if idx > 0:
            return segment[idx:]
    return segment


def parse_install_command(command):
    """Parse a shell command to extract installed packages."""
    if not command:
        return []

    segment = _isolate_install_segment(command)
    if not segment:
        return []

    segment = _strip_docker_prefix(segment)

    matched_manager = None
    matched_prefix = ""
    for prefix, manager in INSTALL_PATTERNS.items():
        if prefix in segment:
            matched_manager = manager
            matched_prefix = prefix
            break

    if not matched_manager:
        return []

    idx = segment.index(matched_prefix) + len(matched_prefix)
    remainder = segment[idx:].strip()
    tokens = remainder.split()
    registry = REGISTRIES.get(matched_manager, "")

    # npx: only first non-flag token
    if matched_manager == "npx":
        for t in tokens:
            if not t.startswith("-") and t not in SHELL_NOISE and _is_valid_package_name(t):
                return [{"name": t, "version": "latest", "pinned": False, "manager": "npx", "registry": registry}]
        return []

    packages = []
    skip_next = False

    for i, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue

        # Skip flags
        if token.startswith("-"):
            if token in FLAGS_WITH_VALUES:
                skip_next = True
            # pip -r / -e handling
            if token == "-r" and matched_manager == "pip" and i + 1 < len(tokens):
                skip_next = True
                packages.append(
                    {
                        "name": f"(from {tokens[i + 1]})",
                        "version": "file",
                        "pinned": True,
                        "manager": matched_manager,
                        "registry": registry,
                    }
                )
            elif token == "-e" and matched_manager == "pip" and i + 1 < len(tokens):
                skip_next = True
                packages.append(
                    {
                        "name": "(editable install)",
                        "version": "editable",
                        "pinned": True,
                        "manager": matched_manager,
                        "registry": registry,
                    }
                )
            continue

        if token in SKIP_FLAGS or token in SHELL_NOISE or token.lower() in SKIP_WORDS:
            continue

        # Skip tokens that look like paths, variables, or noise
        if token.startswith("/") or token.startswith("~"):
            continue
        if "=" in token and not any(op in token for op in ("==", ">=", "<=", "~=", "!=")):
            continue  # Shell variable like PYTHONPATH=.
        if token.startswith('"') or token.startswith("'") or token.startswith("{") or token.startswith("("):
            continue

        name, version, pinned = _parse_package_token(token, matched_manager)
        if name and _is_valid_package_name(name):
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "pinned": pinned,
                    "manager": matched_manager,
                    "registry": registry,
                }
            )

    return packages


def _parse_package_token(token, manager):
    """Parse a single package token into (name, version, pinned)."""
    if manager in ("npm", "yarn", "pnpm"):
        if token.startswith("@") and "@" in token[1:]:
            parts = token.split("@")
            if len(parts) >= 3:
                return "@" + parts[1], parts[2], True
            return "@" + parts[1], "latest", False
        if "@" in token:
            name, version = token.rsplit("@", 1)
            return name, version, True
        return token, "latest", False

    if manager == "pip":
        for op in ("==", ">=", "<=", "~=", "!="):
            if op in token:
                name, version = token.split(op, 1)
                return name, version, True
        return token, "latest", False

    if manager == "go":
        if "@" in token:
            name, version = token.rsplit("@", 1)
            return name, version, True
        return token, "latest", False

    # brew, apt, gem, cargo — simple names
    return token, "latest", False


def assess_risk(package, active_cves=None):
    """Return numeric risk score (0-10) for a package.

    Args:
        package: dict with name, pinned, manager keys
        active_cves: optional dict with critical/high/medium counts of ACTIVE CVEs
    """
    score = 0
    reasons = []
    name = (package.get("name") or "").lower()

    if name in KNOWN_TYPOSQUATS:
        score += 5
        reasons.append(f"typosquat of '{KNOWN_TYPOSQUATS[name]}' (+5)")

    if not package.get("pinned", False):
        score += 1
        reasons.append("unpinned (+1)")

    if package.get("manager") == "npx":
        score += 3
        reasons.append("remote execution via npx (+3)")

    if name in HIGH_RISK_PACKAGES:
        score += 3
        reasons.append(f"{HIGH_RISK_PACKAGES[name]} (+3)")

    if any(kw in name for kw in ("trade", "finance", "stripe", "plaid")):
        score += 2
        reasons.append("financial API (+2)")

    # CVE weight from active (version-affected) vulnerabilities
    if active_cves:
        crit = active_cves.get("critical", 0)
        high = active_cves.get("high", 0)
        med = active_cves.get("medium", 0)
        if crit > 0:
            score += 5
            reasons.append(f"{crit} active critical CVE(s) (+5)")
        if high > 0:
            score += 3
            reasons.append(f"{high} active high CVE(s) (+3)")
        if med > 0:
            score += 1
            reasons.append(f"{med} active medium CVE(s) (+1)")

    return score, reasons


def risk_level(score):
    """Map numeric score to severity label."""
    if score >= 7:
        return "critical"
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def categorize_package(name, manager):
    """Categorize: package, tool_exec, build_tool, or metadata."""
    if name.startswith("("):
        return "metadata"
    if manager == "npx":
        return "tool_exec"
    if manager in ("brew", "apt"):
        return "build_tool"
    return "package"


def extract_project(path):
    """Extract project name from a file path."""
    if not path:
        return None
    path = path.replace("~", "/Users/placeholder")
    for marker in ("/Documents/", "/Projects/", "/repos/", "/src/"):
        if marker in path:
            after = path.split(marker, 1)[1]
            proj = after.split("/")[0]
            if proj:
                return proj
    return None


def store_dependency(db, timestamp, session_id, agent_type, package, command, cwd=None):
    """Store a parsed dependency in agent_dependencies with dedup."""
    score, reasons = assess_risk(package)
    level = risk_level(score)
    category = categorize_package(package["name"], package["manager"])
    project = extract_project(cwd) if cwd else extract_project(command)
    dedup_key = f"{session_id}|{package['name']}|{package.get('version', '')}|{command[:100]}"
    dedup_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]
    try:
        db.execute(
            """INSERT OR IGNORE INTO agent_dependencies
               (timestamp, session_id, agent_type, action, package_manager,
                package_name, package_version, pinned, registry_url,
                command, risk_flags, risk_score, category, project, dedup_hash)
               VALUES (?, ?, ?, 'install', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp,
                session_id,
                agent_type,
                package["manager"],
                package["name"],
                package.get("version", "latest"),
                1 if package.get("pinned") else 0,
                package.get("registry", ""),
                command[:500],
                json.dumps({"score": score, "level": level, "reasons": reasons}),
                score,
                category,
                project,
                dedup_hash,
            ),
        )
        return score
    except Exception:
        return score


def backfill_dependencies(db):
    """Backfill agent_dependencies from existing tool_use events."""
    rows = db.execute(
        """SELECT e.timestamp, e.session_id, e.data_json, s.agent_type, s.cwd
           FROM events e
           LEFT JOIN sessions s ON e.session_id = s.session_id
           WHERE e.event_type='tool_use' AND e.data_json LIKE '%Bash%'
           ORDER BY e.id ASC"""
    ).fetchall()

    count = 0
    for r in rows:
        try:
            data = json.loads(r["data_json"] if hasattr(r, "keys") else r[2])
        except (json.JSONDecodeError, TypeError):
            continue
        command = data.get("command", "") or data.get("input_preview", "")
        if not command:
            continue
        packages = parse_install_command(command)
        ts = r["timestamp"] if hasattr(r, "keys") else r[0]
        sid = r["session_id"] if hasattr(r, "keys") else r[1]
        agent = (r["agent_type"] if hasattr(r, "keys") else r[3]) or None
        cwd = (r["cwd"] if hasattr(r, "keys") else r[4]) or None
        for pkg in packages:
            store_dependency(db, ts, sid, agent, pkg, command, cwd)
            count += 1

    db.commit()
    return count


# ── Environment inventory ──────────────────────────────────


def get_pip_packages():
    """Get all installed Python packages via ``python -m pip list``.

    Uses ``sys.executable -m pip`` instead of bare ``pip`` so the call
    works under launchd, where the shell PATH is stripped and a bare
    ``pip`` command often doesn't resolve. This is the same class of
    bug we hit with mitmdump — rely on the Python interpreter path,
    never on PATH lookups, for subprocess-launched tooling.
    """
    import sys

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        return [{"name": p["name"], "version": p["version"], "manager": "pip"} for p in data]
    except Exception:
        return []


def get_brew_packages():
    """Get all installed Homebrew packages.

    Tries the common absolute paths first (``/opt/homebrew/bin/brew``
    for Apple Silicon, ``/usr/local/bin/brew`` for Intel) before
    falling back to PATH lookup — the absolute paths are the only
    ones that reliably work under launchd.
    """
    import shutil

    candidates = [
        "/opt/homebrew/bin/brew",
        "/usr/local/bin/brew",
        shutil.which("brew"),
    ]
    brew_bin = next((c for c in candidates if c and __import__("os").path.exists(c)), None)
    if brew_bin is None:
        return []
    try:
        result = subprocess.run(
            [brew_bin, "list", "--versions"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        pkgs = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if parts:
                pkgs.append(
                    {"name": parts[0], "version": parts[-1] if len(parts) > 1 else "unknown", "manager": "brew"}
                )
        return pkgs
    except Exception:
        return []


def get_full_environment():
    """Gather full package inventory from all managers."""
    pkgs = get_pip_packages() + get_brew_packages()
    return pkgs


def store_environment_packages(db, packages):
    """Store environment packages with dedup (UPSERT)."""
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    for p in packages:
        try:
            db.execute(
                """INSERT INTO environment_packages
                   (scan_timestamp, package_name, package_version, manager, source)
                   VALUES (?, ?, ?, ?, 'environment')
                   ON CONFLICT(package_name, manager) DO UPDATE SET
                   package_version=excluded.package_version,
                   scan_timestamp=excluded.scan_timestamp""",
                (ts, p["name"], p["version"], p["manager"]),
            )
        except Exception:
            pass
    db.commit()


def populate_watchlist(db):
    """Auto-populate the package watchlist based on risk signals."""
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    # Agent-installed packages → high priority, 6h
    agent_pkgs = db.execute(
        "SELECT DISTINCT package_name, package_manager FROM agent_dependencies WHERE category='package'"
    ).fetchall()
    for r in agent_pkgs:
        name = r["package_name"] if hasattr(r, "keys") else r[0]
        mgr = r["package_manager"] if hasattr(r, "keys") else r[1]
        try:
            db.execute(
                """INSERT OR IGNORE INTO package_watchlist
                   (package_name, manager, watch_reason, added_timestamp, priority, check_interval_hours)
                   VALUES (?, ?, 'agent_installed', ?, 'high', 6)""",
                (name, mgr, ts),
            )
        except Exception:
            pass
    # Packages with CVEs → high priority
    vuln_pkgs = db.execute("SELECT DISTINCT package_name FROM package_vulnerabilities").fetchall()
    for r in vuln_pkgs:
        name = r["package_name"] if hasattr(r, "keys") else r[0]
        try:
            db.execute(
                """INSERT OR IGNORE INTO package_watchlist
                   (package_name, manager, watch_reason, added_timestamp, priority, check_interval_hours)
                   VALUES (?, 'pip', 'has_cves', ?, 'high', 6)""",
                (name, ts),
            )
        except Exception:
            pass
    db.commit()
    counts = {}
    for r in db.execute("SELECT priority, COUNT(*) FROM package_watchlist GROUP BY priority").fetchall():
        counts[r[0] if hasattr(r, "keys") else r["priority"]] = r[1] if hasattr(r, "keys") else r[1]
    return counts


def generate_sbom(db):
    """Generate a CycloneDX-style SBOM JSON from agent dependencies + vulns."""
    packages = db.execute(
        """SELECT DISTINCT ad.package_name, ad.package_version, ad.package_manager,
                  ad.agent_type, ad.risk_score, ad.category, ad.project
           FROM agent_dependencies ad WHERE ad.category='package'
           ORDER BY ad.package_name"""
    ).fetchall()
    components = []
    for p in packages:
        rd = dict(p) if hasattr(p, "keys") else {"package_name": p[0], "package_version": p[1], "package_manager": p[2]}
        vulns = db.execute(
            "SELECT vuln_id, severity, cvss_score, fix_version FROM package_vulnerabilities WHERE package_name=?",
            (rd["package_name"],),
        ).fetchall()
        comp = {
            "type": "library",
            "name": rd["package_name"],
            "version": rd.get("package_version") or "latest",
            "purl": f"pkg:{rd.get('package_manager', 'pip')}/{rd['package_name']}@{rd.get('package_version', 'latest')}",
            "properties": [
                {"name": "ai-monitor:agent_installed", "value": "true"},
                {"name": "ai-monitor:agent_type", "value": str(rd.get("agent_type", ""))},
                {"name": "ai-monitor:capability_risk_score", "value": str(rd.get("risk_score", 0))},
                {"name": "ai-monitor:project", "value": str(rd.get("project", ""))},
            ],
        }
        if vulns:
            comp["vulnerabilities"] = [
                {
                    "id": dict(v)["vuln_id"] if hasattr(v, "keys") else v[0],
                    "severity": dict(v)["severity"] if hasattr(v, "keys") else v[1],
                }
                for v in vulns
            ]
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "tools": [{"vendor": "GoCloudForge", "name": "AI Runtime Monitor"}],
        },
        "components": components,
    }
