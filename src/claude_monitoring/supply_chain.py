"""Supply chain monitoring — parse agent install commands and assess risk."""

import hashlib
import json

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

SKIP_FLAGS = {
    "--save-dev", "--global", "-g", "-e", "--break-system-packages",
    "--no-cache-dir", "--quiet", "-q", "-U", "--upgrade", "-y",
    "--yes", "--force", "-D", "--dev", "--save", "--save-exact",
    "--production", "--legacy-peer-deps", "--no-optional",
    "--features", "--optional", "--no-default-features",
}

# Flags that consume the next token as their argument
ARG_FLAGS = {
    "--index-url", "--extra-index-url", "-i", "--trusted-host",
    "--constraint", "-c", "--config-settings", "--features",
}

REGISTRIES = {
    "npm": "npmjs.org", "yarn": "npmjs.org", "pnpm": "npmjs.org", "npx": "npmjs.org",
    "pip": "pypi.org",
    "cargo": "crates.io",
    "go": "proxy.golang.org",
    "gem": "rubygems.org",
    "brew": "formulae.brew.sh",
    "apt": "apt",
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


def parse_install_command(command):
    """Parse a shell command to extract installed packages.

    Returns list of dicts with keys: name, version, pinned, manager, registry.
    """
    if not command:
        return []

    matched_manager = None
    matched_prefix = ""
    for prefix, manager in INSTALL_PATTERNS.items():
        if prefix in command:
            matched_manager = manager
            matched_prefix = prefix
            break

    if not matched_manager:
        return []

    # Extract the part after the install keyword
    idx = command.index(matched_prefix) + len(matched_prefix)
    remainder = command[idx:].strip()
    tokens = remainder.split()
    registry = REGISTRIES.get(matched_manager, "")

    if matched_manager == "npx":
        # npx: only first non-flag token is the package
        for t in tokens:
            if not t.startswith("-"):
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
            if token in ARG_FLAGS:
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
                    "name": f"(editable: {tokens[i + 1]})",
                    "version": "editable", "pinned": True,
                    "manager": matched_manager, "registry": registry,
                })
            continue

        if token in SKIP_FLAGS:
            continue

        # Parse name@version or name==version
        name, version, pinned = _parse_package_token(token, matched_manager)
        if name:
            packages.append({
                "name": name, "version": version, "pinned": pinned,
                "manager": matched_manager, "registry": registry,
            })

    return packages


def _parse_package_token(token, manager):
    """Parse a single package token into (name, version, pinned)."""
    if manager in ("npm", "yarn", "pnpm"):
        # Handle scoped: @scope/pkg@version
        if token.startswith("@") and "@" in token[1:]:
            # Could be @scope/pkg or @scope/pkg@version
            parts = token.split("@")
            # parts[0] is empty (before first @), parts[1] is scope/pkg, parts[2+] is version
            if len(parts) >= 3:
                name = "@" + parts[1]
                version = parts[2]
                return name, version, True
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

    if manager == "cargo":
        # cargo add serde — flags handled above
        if not token.startswith("-"):
            return token, "latest", False
        return None, None, False

    # brew, apt, gem — simple names
    return token, "latest", False


def assess_risk(package):
    """Return list of risk flags for a package."""
    risks = []
    name = (package.get("name") or "").lower()

    if name in KNOWN_TYPOSQUATS:
        risks.append(f"typosquat:{KNOWN_TYPOSQUATS[name]}")

    if not package.get("pinned", False):
        risks.append("unpinned")

    if package.get("manager") == "npx":
        risks.append("remote_exec")

    if name.startswith("@"):
        risks.append("scoped")

    return risks


def store_dependency(db, timestamp, session_id, agent_type, package, command):
    """Store a parsed dependency in agent_dependencies with dedup."""
    risk_flags = assess_risk(package)
    dedup_key = f"{session_id}|{package['name']}|{package.get('version','')}|{command[:100]}"
    dedup_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]
    try:
        db.execute(
            """INSERT OR IGNORE INTO agent_dependencies
               (timestamp, session_id, agent_type, action, package_manager,
                package_name, package_version, pinned, registry_url,
                command, risk_flags, dedup_hash)
               VALUES (?, ?, ?, 'install', ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp, session_id, agent_type,
                package["manager"], package["name"],
                package.get("version", "latest"),
                1 if package.get("pinned") else 0,
                package.get("registry", ""),
                command[:500],
                json.dumps(risk_flags),
                dedup_hash,
            ),
        )
        return risk_flags
    except Exception:
        return risk_flags


def backfill_dependencies(db):
    """Backfill agent_dependencies from existing tool_use events."""
    rows = db.execute(
        """SELECT timestamp, session_id, data_json FROM events
           WHERE event_type='tool_use' AND data_json LIKE '%Bash%'
           ORDER BY id ASC"""
    ).fetchall()

    count = 0
    for r in rows:
        try:
            data = json.loads(r["data_json"] if isinstance(r, dict) else r[2])
        except (json.JSONDecodeError, TypeError):
            continue
        command = data.get("command", "") or data.get("input_preview", "")
        if not command:
            continue
        packages = parse_install_command(command)
        ts = r["timestamp"] if isinstance(r, dict) else r[0]
        sid = r["session_id"] if isinstance(r, dict) else r[1]
        for pkg in packages:
            store_dependency(db, ts, sid, None, pkg, command)
            count += 1

    db.commit()
    return count
