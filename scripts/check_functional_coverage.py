#!/usr/bin/env python3
"""Warn when a src/ module has no corresponding integration test.

This is a **warn-only** check (always exits 0) intended as a nudge —
not a hard gate. Unit tests still live under ``tests/`` flat; this
script looks for matching files under ``tests/integration/`` so we
can ratchet toward an integration suite covering every module.

Mapping: ``src/claude_monitoring/foo.py`` →
``tests/integration/test_foo.py``.

Modules excluded from the check:
  - ``__init__.py``, ``__main__.py`` — entry points / package markers
  - Files under ``constants`` / pure-data modules (configurable)

Usage:
    python scripts/check_functional_coverage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path("src/claude_monitoring")
INT_TEST_ROOT = Path("tests/integration")

EXCLUDE = {"__init__.py", "__main__.py"}


def missing_integration_tests() -> list[str]:
    """Return module stems that have no ``tests/integration/test_<stem>.py``."""
    if not SRC_ROOT.exists():
        return []
    missing: list[str] = []
    for path in sorted(SRC_ROOT.glob("*.py")):
        if path.name in EXCLUDE:
            continue
        stem = path.stem
        candidate = INT_TEST_ROOT / f"test_{stem}.py"
        if not candidate.exists():
            missing.append(stem)
    return missing


def main(argv: list[str]) -> int:
    missing = missing_integration_tests()
    if not missing:
        print(f"PASS: every {SRC_ROOT} module has an integration test.")
        return 0

    print(f"WARN: {len(missing)} module(s) lack an integration test under {INT_TEST_ROOT}/:")
    for stem in missing:
        print(f"  - {stem}  (expected {INT_TEST_ROOT}/test_{stem}.py)")
    print(
        "\nThis is a nudge, not a gate. Add integration tests progressively; "
        "this script will start failing the build once we cover every module."
    )
    return 0  # warn-only — always succeed


if __name__ == "__main__":
    sys.exit(main(sys.argv))
