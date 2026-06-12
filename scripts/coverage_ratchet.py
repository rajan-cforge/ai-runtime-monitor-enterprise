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

Per-file baseline (judge ruling 2026-06-12, R1 gate maintenance)
----------------------------------------------------------------
``scripts/coverage_ratchet_baseline.txt`` lists per-file line-coverage
floors that the ratchet enforces in PLACE OF the diff comparison for
the listed files. Files NOT in the baseline keep the existing
diff-based gate.

This mechanism exists because a pure module split (e.g., extracting
``DashboardHandler`` from ``monitor.py`` into ``dashboard_handler.py``)
makes the diff gate fire spuriously: covered lines migrate from one
file to another, so the source file shows a per-file drop even
though overall coverage holds flat or improves. The judge ruled
against runtime escape flags (``--allow-drop`` becomes a permanent
loophole) and against admin-merging past red required checks (sets the
worst possible precedent). Instead, the baseline is REFRESHED in its
own judge-reviewed micro-PR with evidence: overall delta ≥ 0 AND
migration accounting (where the moved lines now count).

Refresh entries in-place via:
    python scripts/coverage_ratchet.py --update-baseline <coverage.xml> <path> [<path> ...]

To ADD a new entry, edit the baseline file manually — that forces the
new entry to show up in the diff so the judge sees the addition.

Inputs (positional):
    base-coverage.xml  pr-coverage.xml  [changed-files-list-path]

If ``changed-files-list-path`` is omitted, the ratchet falls back to
running ``git diff --name-only origin/<BASE_REF>...HEAD -- src/``.
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = PROJECT_ROOT / "scripts" / "coverage_ratchet_baseline.txt"


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


def load_baseline() -> dict[str, float]:
    """Read per-file line-coverage floors from the committed baseline.

    Returns ``{path: expected_line_pct}``. Each non-blank, non-comment
    line in the baseline file is parsed as ``<path> <line_pct>``.
    """
    if not BASELINE_PATH.exists():
        return {}
    out: dict[str, float] = {}
    for line in BASELINE_PATH.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) != 2:
            continue
        try:
            out[parts[0]] = float(parts[1])
        except ValueError:
            continue
    return out


def write_baseline(floors: dict[str, float]) -> None:
    """Rewrite the baseline file with the given per-file floors.

    The header documents the refresh discipline so future contributors
    don't reinvent it. The body is sorted ``<path> <line_pct>`` rows.
    """
    header = (
        "# Per-file line-coverage baseline for the coverage ratchet.\n"
        "#\n"
        "# Each entry: `<path> <line_pct>`. The ratchet\n"
        "# (scripts/coverage_ratchet.py) gates any PR-modified file with a\n"
        "# baseline entry against `<pr_line_pct> >= <floor> - LINE_DROP_TOLERANCE`,\n"
        "# IN PLACE OF the diff comparison. Files NOT listed here keep the\n"
        "# existing diff-based gate.\n"
        "#\n"
        "# Refresh discipline (mirrors check_design_patterns_baseline.txt;\n"
        "# judge ruling 2026-06-12, R1 gate maintenance):\n"
        "# this file is JUDGE-REVIEWED. Refresh entries only via an explicit,\n"
        "# committed PR that includes evidence:\n"
        "#   (a) overall delta >= 0% on the PR triggering the refresh\n"
        "#   (b) migration accounting — for module splits, account for where\n"
        "#       the moved lines now count (covered lines preserved across\n"
        "#       the split)\n"
        "# Auto-pass mechanisms (runtime --allow-drop flags, env vars, label\n"
        "# overrides) are forbidden — every legitimate per-file drop is its\n"
        "# own explicit, committed, judge-reviewed two-line refresh.\n"
        "#\n"
        "# Update existing entries with:\n"
        "#   python scripts/coverage_ratchet.py --update-baseline <coverage.xml> <path>\n"
        "# Add a new entry by editing this file manually — that forces the\n"
        "# new entry to show up in the diff so the judge sees the addition.\n"
        "#\n"
    )
    lines = [f"{p} {floors[p]:.2f}" for p in sorted(floors)]
    BASELINE_PATH.write_text(header + "\n".join(lines) + ("\n" if lines else ""))


def update_baseline(coverage_xml: Path, paths_to_refresh: list[str]) -> int:
    """Refresh baseline entries for the listed paths from ``coverage_xml``.

    Updates each listed path's floor to its measured value in
    ``coverage_xml``. Listed paths NOT yet in the baseline are added
    (they show up in the diff so the judge sees the addition). Paths
    not in ``coverage_xml`` are skipped with a warning.

    Returns 0 on success, 1 if no listed path was found in the coverage
    report.
    """
    cov = parse_file_coverage(coverage_xml)
    floors = load_baseline()
    updated = 0
    for p in paths_to_refresh:
        if p not in cov:
            print(f"WARN: {p} not in {coverage_xml}; skipped")
            continue
        line_pct, _branch_pct = cov[p]
        floors[p] = line_pct
        updated += 1
    if updated == 0:
        print(f"ERROR: none of {paths_to_refresh} were found in {coverage_xml}")
        return 1
    write_baseline(floors)
    try:
        loc = BASELINE_PATH.relative_to(PROJECT_ROOT)
    except ValueError:
        loc = BASELINE_PATH
    print(f"Baseline updated: {updated} entry/entries refreshed; {len(floors)} total at {loc}")
    return 0


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

    pr_files_for_filter = parse_file_coverage(pr_path)
    # `git diff --name-only` includes deleted files. A deleted file has no PR
    # coverage entry AND is absent from disk, so the per-file gate would read
    # "93% -> 0%" and fail — but the file is gone, so there is nothing to
    # test. Drop deletions from the per-file gate; deletion-induced
    # overall-coverage drift is still caught by OVERALL_DROP_HARD_LIMIT
    # below. Both conditions are required so fake-path test fixtures
    # (file absent on disk but present in the PR cobertura) still gate.
    deleted = {f for f in changed if (not Path(f).exists()) and f not in pr_files_for_filter}
    if deleted:
        print(f"Deleted files (skipped from per-file gate, n={len(deleted)}):")
        for f in sorted(deleted):
            print(f"  - {f}")
        print()
        changed = changed - deleted

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
    baseline_floors = load_baseline()

    print(f"PR-modified files (n={len(changed)}):")
    failures: list[str] = []
    for f in sorted(changed):
        p_line, p_branch = pr_files.get(f, (0.0, 0.0))
        status = "ok"

        if f in baseline_floors:
            # Judge-ratified floor. The diff-based gate is suppressed for
            # this file; the floor explicitly encodes the expected
            # post-refactor coverage (e.g., for pure module splits where
            # the diff-based gate would fire spuriously).
            floor = baseline_floors[f]
            line_drop = floor - p_line
            if line_drop > LINE_DROP_TOLERANCE:
                failures.append(
                    f"{f}: line {p_line:.2f}% below baseline floor {floor:.2f}% "
                    f"(drop {line_drop:.2f}%, tolerance {LINE_DROP_TOLERANCE:.2f}%)"
                )
                status = "FAIL"
            print(f"  [{status}] {f}: line {p_line:.2f}%  (baseline floor {floor:.2f}%, diff-gate suppressed)")
        else:
            # No baseline entry → existing diff-based gate.
            b_line, b_branch = base_files.get(f, (0.0, 0.0))
            line_drop = b_line - p_line
            branch_drop = b_branch - p_branch
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
        print(
            "\nAdd tests covering the affected code, OR — if this is a structural\n"
            "change (e.g. pure module split) where coverage migrated to another file\n"
            "with overall delta >= 0 — refresh the per-file baseline in its OWN\n"
            "micro-PR with evidence. See scripts/coverage_ratchet_baseline.txt."
        )
        return 1

    print("\nPASS: coverage maintained or improved within tolerance on all PR-modified files.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--update-baseline":
        if len(argv) < 4:
            print(
                f"Usage: {argv[0]} --update-baseline <coverage.xml> <path> [<path> ...]",
                file=sys.stderr,
            )
            return 2
        coverage_xml = Path(argv[2])
        paths = list(argv[3:])
        return update_baseline(coverage_xml, paths)

    if len(argv) not in (3, 4):
        print(
            f"Usage: {argv[0]} <base-coverage.xml> <pr-coverage.xml> [changed-files-list]\n"
            f"       {argv[0]} --update-baseline <coverage.xml> <path> [<path> ...]",
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
