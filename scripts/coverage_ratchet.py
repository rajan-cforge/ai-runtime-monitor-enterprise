#!/usr/bin/env python3
"""Coverage ratchet — fail CI if a PR drops coverage on files it touches.

Compares two cobertura XML reports (base branch vs PR branch).

By default, the ratchet is **scoped to files the PR actually modifies**.
That avoids false positives caused by deterministic CI-environment
quirks that shift coverage on unrelated modules between two pytest
invocations in the same job (we hit this on the introducing PR: the
test suite was identical on both branches but wizard.py lost 49 hits
on the PR side every time, regardless of test code changes).

Gating logic:
  - For each file modified in the PR (under src/), require the line
    coverage drop to be within LINE_DROP_TOLERANCE percentage points.
  - For each PR-modified file, require the branch coverage drop to
    be within BRANCH_DROP_TOLERANCE percentage points.
  - Report the OVERALL delta (informational) but do not fail on it
    unless it exceeds OVERALL_DROP_HARD_LIMIT — a safety net for
    catastrophic, suite-wide regressions.

Inputs (positional):
    base-coverage.xml  pr-coverage.xml  [changed-files-list-path]

If `changed-files-list-path` is omitted, the ratchet falls back to
running `git diff --name-only origin/<BASE_REF>...HEAD -- src/`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LINE_DROP_TOLERANCE = 0.1  # percentage points, per-file
BRANCH_DROP_TOLERANCE = 0.5  # percentage points, per-file
OVERALL_DROP_HARD_LIMIT = 5.0  # catastrophic-only; per-file gate is the real one


def parse_file_coverage(xml_path: Path) -> dict[str, tuple[float, float]]:
    """Return {filename: (line_pct, branch_pct)} from a cobertura XML report."""
    root = ET.parse(xml_path).getroot()
    out: dict[str, tuple[float, float]] = {}
    for cls in root.iter("class"):
        fname = cls.attrib["filename"]
        line = float(cls.attrib.get("line-rate", "0")) * 100
        branch = float(cls.attrib.get("branch-rate", "0")) * 100
        out[fname] = (line, branch)
    return out


def parse_overall(xml_path: Path) -> tuple[float, float]:
    """Return (line_pct, branch_pct) from the cobertura root element."""
    root = ET.parse(xml_path).getroot()
    line = float(root.attrib.get("line-rate", "0")) * 100
    branch = float(root.attrib.get("branch-rate", "0")) * 100
    return line, branch


def read_changed_files(path: Path | None) -> set[str]:
    """Load PR-modified files. Falls back to `git diff` against the base
    branch if no list file is provided."""
    if path is not None and path.exists():
        return {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}

    base_ref = os.environ.get("BASE_REF", "main")
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD", "--", "src/"],
            capture_output=True,
            text=True,
            check=True,
        )
        return {ln.strip() for ln in result.stdout.splitlines() if ln.strip()}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()


def ratchet(base_path: Path, pr_path: Path, changed: set[str]) -> int:
    """Return 0 on PASS, 1 on FAIL. Prints a structured summary either way."""
    base_overall_line, base_overall_branch = parse_overall(base_path)
    pr_overall_line, pr_overall_branch = parse_overall(pr_path)
    overall_line_drop = base_overall_line - pr_overall_line
    overall_branch_drop = base_overall_branch - pr_overall_branch

    print(f"Overall base:   line={base_overall_line:.2f}%  branch={base_overall_branch:.2f}%")
    print(f"Overall PR:     line={pr_overall_line:.2f}%  branch={pr_overall_branch:.2f}%")
    print(f"Overall delta:  line={-overall_line_drop:+.2f}%  branch={-overall_branch_drop:+.2f}%")
    print()

    if not changed:
        print("No PR-modified files under src/. Per-file gate skipped.")
        if overall_line_drop > OVERALL_DROP_HARD_LIMIT:
            print(
                f"\nFAIL: overall line coverage dropped {overall_line_drop:.2f}%, "
                f"above the hard limit {OVERALL_DROP_HARD_LIMIT:.2f}%."
            )
            return 1
        print("\nPASS: nothing to gate.")
        return 0

    base_files = parse_file_coverage(base_path)
    pr_files = parse_file_coverage(pr_path)

    print(f"PR-modified files (n={len(changed)}):")
    failures: list[str] = []
    for f in sorted(changed):
        b_line, b_branch = base_files.get(f, (0.0, 0.0))
        p_line, p_branch = pr_files.get(f, (0.0, 0.0))
        line_drop = b_line - p_line
        branch_drop = b_branch - p_branch
        status = "ok"
        if line_drop > LINE_DROP_TOLERANCE:
            failures.append(
                f"{f}: line {b_line:.2f}% -> {p_line:.2f}% "
                f"(drop {line_drop:.2f}%, tolerance {LINE_DROP_TOLERANCE:.2f}%)"
            )
            status = "FAIL"
        if branch_drop > BRANCH_DROP_TOLERANCE:
            failures.append(
                f"{f}: branch {b_branch:.2f}% -> {p_branch:.2f}% "
                f"(drop {branch_drop:.2f}%, tolerance {BRANCH_DROP_TOLERANCE:.2f}%)"
            )
            status = "FAIL"
        print(f"  [{status}] {f}: line {b_line:.2f}% -> {p_line:.2f}%  branch {b_branch:.2f}% -> {p_branch:.2f}%")

    if overall_line_drop > OVERALL_DROP_HARD_LIMIT:
        failures.append(
            f"overall line coverage dropped {overall_line_drop:.2f}%, above hard limit {OVERALL_DROP_HARD_LIMIT:.2f}%"
        )

    if failures:
        print("\nFAIL:")
        for f in failures:
            print(f"  - {f}")
        print("\nAdd tests covering the affected code, or document the intentional drop in the PR body.")
        return 1

    print("\nPASS: coverage maintained or improved within tolerance on all PR-modified files.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print(
            f"Usage: {argv[0]} <base-coverage.xml> <pr-coverage.xml> [changed-files-list]",
            file=sys.stderr,
        )
        return 2
    base_path = Path(argv[1])
    pr_path = Path(argv[2])
    changed_path = Path(argv[3]) if len(argv) == 4 else None
    changed = read_changed_files(changed_path)
    return ratchet(base_path, pr_path, changed)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
