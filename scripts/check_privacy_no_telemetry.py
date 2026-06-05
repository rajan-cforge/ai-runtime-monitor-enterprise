#!/usr/bin/env python3
"""Privacy gate — block telemetry-shaped outbound HTTP in the v0.2.2 attack-surface package.

Per the v0.2.2 implementation directive §11.2 (gate #4) and Rajan's
2026-06-04 gate-ownership ruling: this gate must be live BEFORE Phase 4
ships the first outbound HTTP (the OSV.dev CVE-correlation client).

**Scope** (deliberately narrow): only `src/claude_monitoring/attack_surface/`.
The rest of the codebase has its own outbound-HTTP audit history (sync.py
is user-opt-in control-plane sync; validators.py does credential-test
calls; threat_intel.py downloads public feeds). This gate is the
v0.2.2-specific guardrail that stops anyone sneaking telemetry into the
new attack-surface code path.

**What "telemetry" means here**:
- ANY outbound HTTP (GET, POST, PUT, PATCH, DELETE, HEAD) to a URL whose
  hostname is not in :data:`ALLOWED_HOSTNAMES`.
- Detected via AST scan, not regex — formatting variations (multi-line
  URLs, f-strings, kwarg ordering) cannot bypass the check.

**What this gate does NOT catch** (honest limitations):
- Dynamic URL construction via `urljoin`, `f"{base}/{path}"`, etc. where
  the hostname is computed at runtime. Mitigation: the
  `discovery-security-model-compliance` gate (P1.2) will flag direct
  `requests`/`urllib` imports in attack_surface code; sources should use
  a wrapped helper that hardcodes the hostname.
- Session/Client method calls: `s = requests.Session(); s.get(...)`,
  `client = httpx.Client(); client.post(...)`, etc. The scanner does not
  track variable bindings to flag method calls on session instances.
  Dataflow tracking is significantly more complex (would require
  ``ast.Assign`` walking + name resolution). Discovery sources are
  forbidden from using ``Session``/``Client`` in attack_surface — code
  review must catch this. The ``discovery-security-model-compliance``
  gate (P1.2) is the right place to add a "no requests.Session in
  attack_surface" check.
- Subprocess shells that exfiltrate via `curl` — covered by the
  existing forbidden subprocess-shell-kwarg ban (CLAUDE.md forbidden
  pattern, enforced by `check_design_patterns.py`).
- `socket.connect` raw TCP — not the threat model here; attack-surface
  code has no business doing raw sockets, and would land in code review.

Exit codes:
- 0: no violations
- 1: violations found (prints file:line:reason)

Wiring: invoked from `.github/workflows/ci.yml` as a step in the `lint`
job, alongside `check_design_patterns.py`.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface"

ALLOWED_HOSTNAMES: frozenset[str] = frozenset(
    {
        # Phase 4 — CVE correlation via OSV.dev (RESERVED, not yet wired)
        "api.osv.dev",
        "osv.dev",
        # Loopback — internal dashboard API only
        "localhost",
        "127.0.0.1",
        "::1",
    }
)
"""Hostnames the attack-surface package is permitted to talk to.

Every entry MUST be justified in the comment above. Adding a hostname
requires a PR that names the consuming source / scanner and the audit
trail. Empty fallback to "trust the comment" is forbidden.
"""

HTTP_CLIENT_CALLS: frozenset[str] = frozenset(
    {
        # requests library
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.request",
        # urllib
        "urllib.request.urlopen",
        "urllib.request.Request",
        # httpx (not currently a dep but reserve)
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.head",
        "httpx.request",
    }
)


def _build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Build a name -> canonical-dotted-name alias map from a module's imports.

    Resolves three import forms used in the wild:

    1. ``import requests``               → ``{"requests": "requests"}``
    2. ``import requests as rq``         → ``{"rq": "requests"}``
    3. ``from requests import post``     → ``{"post": "requests.post"}``
       ``from requests import post as p``→ ``{"p": "requests.post"}``
    4. ``import urllib.request``         → ``{"urllib.request": "urllib.request"}``
       ``import urllib.request as ur``   → ``{"ur": "urllib.request"}``

    Without this, the bypass ``from requests import post; post("evil")``
    silently passes the gate. WITH this, the second statement's
    ``call_name`` ("post") resolves to "requests.post" via the alias map.

    Module-level only — the map does not track per-function rebindings
    or other shadowing, which are acknowledged limitations.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                local_name = name.asname or name.name
                aliases[local_name] = name.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue  # relative imports — not our threat surface
            for name in node.names:
                if name.name == "*":
                    continue  # star imports — unresolvable; documented limitation
                local_name = name.asname or name.name
                aliases[local_name] = f"{node.module}.{name.name}"
    return aliases


def _dotted_call_name(call: ast.Call, alias_map: dict[str, str]) -> str | None:
    """Return the dotted call name resolved through the alias map.

    Handles three patterns:
    - ``requests.post(...)`` — ``Attribute(Name("requests"), "post")``
      → leading Name resolved via alias_map ("requests" → "requests"),
      attr appended → "requests.post"
    - ``urllib.request.urlopen(...)`` — nested Attribute chain → leading
      Name "urllib" via alias_map → "urllib.request.urlopen"
    - ``post(...)`` after ``from requests import post`` — ``Name("post")``
      → resolved via alias_map → "requests.post"

    Returns the canonical dotted name (e.g. ``"requests.post"``), or
    None if the call is not a Name- or Attribute-rooted call (e.g.,
    a method call on a runtime value like ``session.get`` where session
    is a variable binding — see "Session/Client" limitation in the
    module docstring).
    """
    if isinstance(call.func, ast.Name):
        return alias_map.get(call.func.id, call.func.id)
    if isinstance(call.func, ast.Attribute):
        parts: list[str] = []
        node: ast.expr = call.func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            root = alias_map.get(node.id, node.id)
            return ".".join([root, *reversed(parts)])
    return None


def _extract_url_literal(call: ast.Call) -> str | None:
    """Return the first positional-arg or ``url=`` kwarg URL literal.

    Returns the literal string if found, or ``None`` if the URL is
    computed at runtime (f-string, variable, expression). Runtime URLs
    are flagged separately — the gate can't statically verify them.
    """
    # First positional arg
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    # url= kwarg
    for kw in call.keywords:
        if kw.arg == "url" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _hostname_from_url(url: str) -> str | None:
    """Return the hostname for a fully-qualified URL, or ``None``."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    return parsed.hostname


def _scan_file(path: Path) -> list[tuple[int, str]]:
    """Return ``[(line_no, reason), ...]`` for violations in ``path``."""
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [(exc.lineno or 0, f"syntax error: {exc.msg}")]

    alias_map = _build_alias_map(tree)
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _dotted_call_name(node, alias_map)
        if call_name not in HTTP_CLIENT_CALLS:
            continue
        url = _extract_url_literal(node)
        if url is None:
            violations.append(
                (
                    node.lineno,
                    f"{call_name}() with runtime-computed URL — cannot statically verify destination; "
                    f"use a wrapped helper that hardcodes the allowed hostname",
                )
            )
            continue
        hostname = _hostname_from_url(url)
        if hostname is None:
            violations.append(
                (
                    node.lineno,
                    f"{call_name}() with unparseable URL literal {url!r}",
                )
            )
            continue
        if hostname not in ALLOWED_HOSTNAMES:
            violations.append(
                (
                    node.lineno,
                    f"{call_name}() targets hostname {hostname!r} which is not in ALLOWED_HOSTNAMES; "
                    f"add it to scripts/check_privacy_no_telemetry.py with an audit-trail comment",
                )
            )
    return violations


def main() -> int:
    if not SCAN_ROOT.is_dir():
        # Defensive: if attack_surface/ doesn't exist yet, nothing to scan.
        # This shouldn't happen post-P1.1 but keep the script idempotent.
        print(f"PASS: {SCAN_ROOT} does not exist; nothing to scan.")
        return 0

    python_files = sorted(SCAN_ROOT.rglob("*.py"))
    if not python_files:
        print(f"PASS: no Python files under {SCAN_ROOT.relative_to(REPO_ROOT)} to scan.")
        return 0

    total_violations: list[tuple[Path, int, str]] = []
    for py in python_files:
        for line_no, reason in _scan_file(py):
            total_violations.append((py, line_no, reason))

    if not total_violations:
        print(f"PASS: scanned {len(python_files)} file(s) in attack_surface/; no telemetry-shaped HTTP detected.")
        return 0

    print(f"FAIL: {len(total_violations)} privacy violation(s) in attack_surface/:", file=sys.stderr)
    for py, line_no, reason in total_violations:
        rel = py.relative_to(REPO_ROOT)
        print(f"  {rel}:{line_no}: {reason}", file=sys.stderr)
    print(
        "\nIf the call is legitimate, add the hostname to ALLOWED_HOSTNAMES in "
        "scripts/check_privacy_no_telemetry.py with a comment naming the consuming "
        "source/scanner and the audit trail.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
