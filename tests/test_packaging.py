# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for pyproject.toml invariants pinned by PR #52.

PR #52 promoted ``mitmproxy`` from the ``[watch]`` optional extra to a
base dependency. These tests ensure the contract holds against
accidental regression:

- ``mitmproxy`` is in ``[project].dependencies``
- ``[watch]`` is preserved as an empty no-op alias for backwards-compat
- ``mitmproxy`` is NOT in any other extra (would imply duplicate
  declaration)
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


def _load_pyproject() -> dict:
    path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    return tomllib.loads(path.read_text())


def test_mitmproxy_is_a_base_dependency():
    """The silent-failure footgun from pre-PR-52 was that
    ``pip install ai-runtime-monitor`` produced a half-working product
    because mitmproxy lived in the ``[watch]`` extra. mitmproxy is now
    base; this test pins that."""
    project = _load_pyproject()["project"]
    deps = project["dependencies"]
    assert any(dep.startswith("mitmproxy") for dep in deps), (
        f"mitmproxy must be in [project].dependencies; found: {deps}"
    )


def test_watch_extra_is_empty_no_op():
    """Backwards-compat: existing install commands
    ``pip install "ai-runtime-monitor[watch]"`` must keep working.
    Empty list is the right shape — pip accepts it and resolves to a
    no-op install. Non-empty would imply duplicate-declaration of
    mitmproxy (or a new extra we haven't audited)."""
    extras = _load_pyproject()["project"]["optional-dependencies"]
    assert "watch" in extras, "the [watch] extra must remain defined as a no-op alias"
    assert extras["watch"] == [], f"[watch] extra must be empty so it's a true no-op; found: {extras['watch']}"


def test_mitmproxy_only_declared_once():
    """If mitmproxy ends up in both base and any extra, every install
    path resolves it twice — harmless to pip but a sign the migration
    didn't fully clean up. Pin the invariant."""
    project = _load_pyproject()["project"]
    deps = project["dependencies"]
    extras = project.get("optional-dependencies", {})

    base_has_mitm = any(d.startswith("mitmproxy") for d in deps)
    extras_with_mitm = [name for name, items in extras.items() if any(item.startswith("mitmproxy") for item in items)]
    assert base_has_mitm
    assert extras_with_mitm == [], f"mitmproxy is declared in both base and {extras_with_mitm}; remove the duplicate"
