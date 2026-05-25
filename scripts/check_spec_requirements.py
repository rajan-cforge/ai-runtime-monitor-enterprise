#!/usr/bin/env python3
"""Validate that a PR diff satisfies the rules in `.github/spec-requirements.yaml`.

Reads a unified diff from a patch file, walks the YAML rule table, and for
each rule whose conditions match the diff, checks whether the requirements
are met. Exits non-zero if any BLOCK rule is violated. WARN rules emit
messages but don't fail the gate.

Layer 6.5 enforcement in docs/SSDLC_ENFORCEMENT.md.

Usage:
    python scripts/check_spec_requirements.py --diff <patch-file> [--rules <path>]

Exit codes:
    0  all BLOCK rules satisfied (WARN rules may have fired)
    1  one or more BLOCK rules violated
    2  usage error (missing patch file, malformed YAML, etc.)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path, PurePath

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = PROJECT_ROOT / ".github" / "spec-requirements.yaml"


def parse_diff(patch_text: str) -> tuple[set[str], list[str]]:
    """Return ``(files_touched, all_added_lines)`` from a unified diff.

    Added lines preserve their leading ``+`` so rules that anchor on that
    column (e.g., ``^\\+\\s*"pkg>=..."`` for the new-dependency rule) can
    fire correctly. The git diff header lines (`+++ b/file`) are excluded.
    """
    files: set[str] = set()
    added_lines: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                # `diff --git a/x b/x` -> the `b/x` operand is the new path
                files.add(parts[3][2:])
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line)
    return files, added_lines


def _file_matches_any(files: set[str], patterns: list[str]) -> bool:
    """Glob-match the touched files against ``patterns``.

    Uses ``pathlib.PurePath.match`` (NOT ``fnmatch``) so ``**`` is the
    recursive-directory wildcard a shell user expects. ``fnmatch`` treats
    ``**`` as ``*`` which silently breaks rules like
    ``src/claude_monitoring/**/*.py``.

    A pattern may carry a legacy ``:Class`` suffix (from the original
    dispatch draft); the suffix is stripped — finer-grained class scoping
    is out of scope for v1 and should be handled by per-method rules.
    """
    for f in files:
        p = PurePath(f)
        for pat in patterns:
            head = pat.split(":", 1)[0]
            if p.match(head):
                return True
    return False


def rule_applies(rule: dict, files: set[str], added_text: str) -> bool:
    """Determine if the rule's `when_*` conditions match this PR."""
    has_file_cond = "when_file_matches" in rule
    has_pattern_cond = "when_diff_contains_pattern" in rule or "when_change_touches_pattern" in rule

    file_match = _file_matches_any(files, rule["when_file_matches"]) if has_file_cond else True

    pattern_match = True
    if "when_diff_contains_pattern" in rule:
        try:
            pattern_match = any(re.search(pat, added_text) for pat in rule["when_diff_contains_pattern"])
        except re.error:
            # Malformed pattern in the rule; treat as non-matching and log.
            print(f"warning: rule '{rule.get('id')}' has malformed regex; skipping", file=sys.stderr)
            return False
    if "when_change_touches_pattern" in rule:
        pattern_match = pattern_match and any(pat in added_text for pat in rule["when_change_touches_pattern"])

    if has_file_cond and has_pattern_cond:
        return file_match and pattern_match
    if has_file_cond:
        return file_match
    if has_pattern_cond:
        return pattern_match
    # A rule with neither condition is malformed; do not apply.
    return False


def rule_satisfied(rule: dict, files: set[str]) -> tuple[bool, list[str]]:
    """Check if the rule's `requires_*` conditions are satisfied.

    Returns ``(ok, missing)`` — `ok` is True if every required check passes;
    `missing` is the list of human-readable reasons when False.

    Requirements semantics:
      - `requires_doc_update`: the named doc must appear in the diff's
        touched-files set (i.e., the PR updated it).
      - `requires_doc`: the named doc must exist on disk OR be in the diff.
        Used for "this doc must exist somewhere" gates like
        `dependency-rationale.md`.
      - `requires_files`: same as `requires_doc` but for source/test files.

    `requires_pr_label` and `requires_review` are out-of-band (GitHub UI
    actions) and not checkable here — they're documented for human
    reviewers but the validator skips them.
    """
    missing: list[str] = [
        f"doc not updated: {doc}"
        for doc in (rule.get("requires_doc_update") or [])
        if doc not in files
    ]
    missing.extend(
        f"required doc missing: {doc}"
        for doc in (rule.get("requires_doc") or [])
        if doc not in files and not (PROJECT_ROOT / doc).exists()
    )
    missing.extend(
        f"required file missing: {f}"
        for f in (rule.get("requires_files") or [])
        if f not in files and not (PROJECT_ROOT / f).exists()
    )
    return (len(missing) == 0, missing)


def run(rules_doc: dict, patch_text: str) -> int:
    """Evaluate every rule against the diff; return exit code."""
    files, added_lines = parse_diff(patch_text)
    added_text = "\n".join(added_lines)

    if not files:
        print("No file changes detected; spec-requirements check passes vacuously")
        return 0

    block_violations = 0
    warn_violations = 0

    for rule in rules_doc.get("rules", []) or []:
        try:
            if not rule_applies(rule, files, added_text):
                continue
            ok, missing = rule_satisfied(rule, files)
            if ok:
                continue
        except (KeyError, TypeError) as exc:
            print(
                f"warning: rule '{rule.get('id', '<unknown>')}' is malformed: {exc}; skipping",
                file=sys.stderr,
            )
            continue

        severity = rule.get("severity", "BLOCK")
        prefix = "BLOCK" if severity == "BLOCK" else "WARN "
        print(f"\n[{prefix}] rule '{rule['id']}': {rule['description']}")
        for m in missing:
            print(f"  - {m}")

        if severity == "BLOCK":
            block_violations += 1
        else:
            warn_violations += 1

    print(f"\nspec-requirements: {block_violations} blocking, {warn_violations} warnings")
    return 1 if block_violations else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--diff", required=True, help="Path to unified diff patch file")
    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES),
        help="Path to the spec-requirements YAML (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    rules_path = Path(args.rules)
    diff_path = Path(args.diff)

    if not diff_path.exists():
        print(f"error: patch file not found: {diff_path}", file=sys.stderr)
        return 2
    if not rules_path.exists():
        print(f"error: rules file not found: {rules_path}", file=sys.stderr)
        return 2

    try:
        rules_doc = yaml.safe_load(rules_path.read_text())
    except yaml.YAMLError as exc:
        print(f"error: malformed rules YAML: {exc}", file=sys.stderr)
        return 2
    if not isinstance(rules_doc, dict):
        print(f"error: rules YAML must be a mapping at top-level, got {type(rules_doc).__name__}", file=sys.stderr)
        return 2

    patch_text = diff_path.read_text()
    return run(rules_doc, patch_text)


if __name__ == "__main__":
    sys.exit(main())
