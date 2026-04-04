"""Supply chain monitoring — parse agent install commands and assess risk."""

import hashlib
import json
import re

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
    "--save-dev", "--global", "-g", "--break-system-packages",
    "--no-cache-dir", "--quiet", "-q", "-U", "--upgrade", "-y",
    "--yes", "--force", "-D", "--dev", "--save", "--save-exact",
    "--production", "--legacy-peer-deps", "--no-optional",
    "--no-default-features", "--optional", "--user", "--system",
}

# Flags that consume the NEXT token as their argument — skip both
FLAGS_WITH_VALUES = {
    "--index-url", "--extra-index-url", "-i", "--trusted-host",
    "--constraint", "-c", "--config-settings", "--features",
    "--platform", "--implementation", "--python-version",
    "--target", "-t", "--prefix", "--root",
}

REGISTRIES = {
    "npm": "npmjs.org", "yarn": "npmjs.org", "pnpm": "npmjs.org", "npx": "npmjs.org",
    "pip": "pypi.org", "cargo": "crates.io", "go": "proxy.golang.org",
    "gem": "rubygems.org", "brew": "formulae.brew.sh", "apt": "apt",
}

# Tokens that are NEVER packages — shell noise
SHELL_NOISE = {
    "tail", "head", "grep", "cat", "echo", "wc", "tee", "sort", "uniq",
    "xargs", "sed", "awk", "tr", "true", "false", "test", "sleep",
    "|", "||", "&&", ";", "\\", "2>&1", "2>/dev/null", ">", ">>",
    "python3", "python", "python3.12", "python3.14", "python3.11",
    "pip", "pip3", "install", "docker-compose", "docker", "exec",
    "-T", "source", "activate", "cd", "mkdir", "rm", "cp", "mv",
    "chmod", "chown", "sudo", "sh", "-c", "bash", "done",
}

KNOWN_TYPOSQUATS = {
    "requets": "requests", "requsts": "requests",
    "reqeusts": "requests", "request": "requests",
    "colurs": "colors", "colers": "colors",
    "axois": "axios", "axio": "axios", "axioss": "axios",
    "loddash": "lodash", "loadash": "lodash", "lodahs": "lodash",
    "expresss": "express", "exress": "express",
    "underscor": "underscore", "undescore": "underscore",
    "beutifulsoup": "beautifulsoup4",
    "djanga": "django", "dajngo": "django",
    "flassk": "flask", "flaask": "flask",
    "numpyy": "numpy", "numpi": "numpy",
    "pandass": "pandas", "pnadas": "pandas",
    "tenserflow": "tensorflow", "tensorflw": "tensorflow",
    "pytorh": "pytorch", "pytroch": "pytorch",
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

LOCKFILES = {
    "package-lock.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "pip", "Pipfile.lock": "pip", "poetry.lock": "pip",
    "Cargo.lock": "cargo", "go.sum": "go", "Gemfile.lock": "gem",
}


def _isolate_install_segment(command):
    """Split on shell operators and find the segment with the install keyword."""
    # Split on |, &&, ||, ; — take the segment that contains an install pattern
    segments = re.split(r'\s*(?:\|\||&&|[|;])\s*', command)
    for seg in segments:
        seg = seg.strip()
        for prefix in INSTALL_PATTERNS:
            if prefix in seg:
                # Strip redirects
                seg = re.sub(r'\s*2>[>&/\w]*', '', seg)
                seg = re.sub(r'\s*>[>&\s/\w]*$', '', seg)
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
            if not t.startswith("-") and t not in SHELL_NOISE:
                return [{"name": t, "version": "latest", "pinned": False,
                         "manager": "npx", "registry": registry}]
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
                packages.append({
                    "name": f"(from {tokens[i + 1]})",
                    "version": "file", "pinned": True,
                    "manager": matched_manager, "registry": registry,
                })
            elif token == "-e" and matched_manager == "pip" and i + 1 < len(tokens):
                skip_next = True
                packages.append({
                    "name": "(editable install)",
                    "version": "editable", "pinned": True,
                    "manager": matched_manager, "registry": registry,
                })
            continue

        if token in SKIP_FLAGS or token in SHELL_NOISE:
            continue

        # Skip tokens that look like paths, variables, or noise
        if token.startswith("/") or token.startswith("~"):
            continue
        if "=" in token and not any(op in token for op in ("==", ">=", "<=", "~=", "!=")):
            continue  # Shell variable like PYTHONPATH=.
        if token.startswith('"') or token.startswith("'") or token.startswith("{") or token.startswith("("):
            continue

        name, version, pinned = _parse_package_token(token, matched_manager)
        if name and len(name) > 1 and name not in SHELL_NOISE:
            packages.append({
                "name": name, "version": version, "pinned": pinned,
                "manager": matched_manager, "registry": registry,
            })

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


def assess_risk(package):
    """Return numeric risk score (0-10) for a package."""
    score = 0
    name = (package.get("name") or "").lower()

    if name in KNOWN_TYPOSQUATS:
        score += 5

    if not package.get("pinned", False):
        score += 1

    if package.get("manager") == "npx":
        score += 3

    if name in HIGH_RISK_PACKAGES:
        score += 3

    # Financial/trading APIs
    if any(kw in name for kw in ("trade", "finance", "stripe", "plaid")):
        score += 2

    return score


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
    """Categorize: package, tool_exec, or build_tool."""
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
    score = assess_risk(package)
    level = risk_level(score)
    category = categorize_package(package["name"], package["manager"])
    project = extract_project(cwd) if cwd else extract_project(command)
    dedup_key = f"{session_id}|{package['name']}|{package.get('version','')}|{command[:100]}"
    dedup_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]
    try:
        db.execute(
            """INSERT OR IGNORE INTO agent_dependencies
               (timestamp, session_id, agent_type, action, package_manager,
                package_name, package_version, pinned, registry_url,
                command, risk_flags, risk_score, category, project, dedup_hash)
               VALUES (?, ?, ?, 'install', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp, session_id, agent_type,
                package["manager"], package["name"],
                package.get("version", "latest"),
                1 if package.get("pinned") else 0,
                package.get("registry", ""),
                command[:500],
                json.dumps({"score": score, "level": level}),
                score, category, project,
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
