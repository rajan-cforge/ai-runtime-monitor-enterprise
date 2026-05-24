#!/usr/bin/env python3
"""Coverage ratchet — fail CI if a PR drops coverage below threshold.

Compares two cobertura XML coverage reports (base branch vs PR branch).
Fails (exit 1) if:
  - line coverage dropped by more than LINE_DROP_TOLERANCE (default 0.1%)
  - branch coverage dropped by more than BRANCH_DROP_TOLERANCE (default 0.5%)

Pass (exit 0) on any improvement or drops within tolerance.

Usage:
    python scripts/coverage_ratchet.py <base-coverage.xml> <pr-coverage.xml>

Tolerances exist because coverage measurement is mildly non-deterministic
(test order, parallel collection); a hard zero-drop rule would block
legitimate PRs that don't actually reduce test coverage.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LINE_DROP_TOLERANCE = 0.1  # percentage points
BRANCH_DROP_TOLERANCE = 0.5  # percentage points


def read_rates(xml_path: Path) -> tuple[float, float]:
    """Return (line_pct, branch_pct) from a cobertura XML report.

    cobertura's root element has `line-rate` and `branch-rate` as
    decimals (0.0–1.0). Convert to percent. Missing branch-rate (older
    coverage configs) returns 0.0; the ratchet treats absent branch
    coverage as "no branch data to compare".
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    line = float(root.attrib.get("line-rate", "0")) * 100
    branch = float(root.attrib.get("branch-rate", "0")) * 100
    return line, branch


def ratchet(base_path: Path, pr_path: Path) -> int:
    """Return 0 on PASS, 1 on FAIL. Prints a structured summary either way."""
    base_line, base_branch = read_rates(base_path)
    pr_line, pr_branch = read_rates(pr_path)

    line_drop = base_line - pr_line
    branch_drop = base_branch - pr_branch

    print(f"Base:   line={base_line:.2f}%  branch={base_branch:.2f}%")
    print(f"PR:     line={pr_line:.2f}%  branch={pr_branch:.2f}%")
    print(f"Delta:  line={-line_drop:+.2f}%  branch={-branch_drop:+.2f}%")

    failures: list[str] = []
    if line_drop > LINE_DROP_TOLERANCE:
        failures.append(f"line coverage dropped by {line_drop:.2f}% (tolerance {LINE_DROP_TOLERANCE:.2f}%)")
    if branch_drop > BRANCH_DROP_TOLERANCE:
        failures.append(f"branch coverage dropped by {branch_drop:.2f}% (tolerance {BRANCH_DROP_TOLERANCE:.2f}%)")

    if failures:
        print("\nFAIL:")
        for f in failures:
            print(f"  - {f}")
        print(
            "\nAdd tests covering the affected code, or document the "
            "intentional drop in the PR body and override the ratchet "
            "via [skip-ratchet] in the commit subject (not yet implemented)."
        )
        return 1

    print("\nPASS: coverage maintained or improved within tolerance.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            f"Usage: {argv[0]} <base-coverage.xml> <pr-coverage.xml>",
            file=sys.stderr,
        )
        return 2
    return ratchet(Path(argv[1]), Path(argv[2]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
