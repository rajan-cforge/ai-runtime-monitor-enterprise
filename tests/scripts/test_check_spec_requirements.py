"""Tests for scripts/check_spec_requirements.py.

Builds synthetic unified diffs in `tmp_path` and feeds them to the
validator. Each test exercises one rule's apply-or-not-apply path
plus a coverage of edge cases (empty diff, malformed YAML, missing
files).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_spec_requirements.py"
DEFAULT_RULES = REPO_ROOT / ".github" / "spec-requirements.yaml"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_spec_requirements", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )


def _make_diff(tmp_path: Path, files: dict[str, str]) -> Path:
    """Construct a synthetic unified diff with the given (path -> added body)."""
    parts: list[str] = []
    for path, body in files.items():
        added_lines = "\n".join(f"+{line}" for line in body.splitlines())
        parts.append(
            f"diff --git a/{path} b/{path}\n"
            f"new file mode 100644\n"
            f"--- /dev/null\n"
            f"+++ b/{path}\n"
            f"@@ -0,0 +1,{len(body.splitlines())} @@\n"
            f"{added_lines}\n"
        )
    out = tmp_path / "test.patch"
    out.write_text("".join(parts))
    return out


def _minimal_rules(tmp_path: Path, rules: list[dict]) -> Path:
    p = tmp_path / "rules.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "rules": rules}))
    return p


# ──────────────────────────────────────────────────────────────────
# Edge cases (always exercised first because they touch CLI surface)
# ──────────────────────────────────────────────────────────────────


def test_empty_diff_passes_vacuously(tmp_path: Path) -> None:
    patch = tmp_path / "empty.patch"
    patch.write_text("")
    result = _run("--diff", str(patch))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "vacuously" in result.stdout


def test_missing_patch_file_exits_2(tmp_path: Path) -> None:
    result = _run("--diff", str(tmp_path / "does-not-exist.patch"))
    assert result.returncode == 2
    assert "patch file not found" in result.stderr


def test_malformed_yaml_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("this: is: not: valid: yaml: [unclosed")
    patch = _make_diff(tmp_path, {"src/x.py": "print(1)"})
    result = _run("--diff", str(patch), "--rules", str(bad))
    assert result.returncode == 2
    assert "malformed rules YAML" in result.stderr


def test_yaml_top_level_must_be_mapping(tmp_path: Path) -> None:
    bad = tmp_path / "list.yaml"
    bad.write_text("- just a list\n- not a mapping\n")
    patch = _make_diff(tmp_path, {"src/x.py": "x = 1"})
    result = _run("--diff", str(patch), "--rules", str(bad))
    assert result.returncode == 2
    assert "must be a mapping" in result.stderr


# ──────────────────────────────────────────────────────────────────
# Rule application
# ──────────────────────────────────────────────────────────────────


def test_block_rule_fires_when_unsatisfied(tmp_path: Path) -> None:
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "test-block",
                "description": "test",
                "when_file_matches": ["src/x.py"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "BLOCK",
            }
        ],
    }
    patch_text = textwrap.dedent("""\
        diff --git a/src/x.py b/src/x.py
        --- a/src/x.py
        +++ b/src/x.py
        @@ -1,1 +1,2 @@
         existing
        +new line
    """)
    rc = mod.run(rules, patch_text)
    assert rc == 1


def test_block_rule_passes_when_doc_updated(tmp_path: Path) -> None:
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "test-block",
                "description": "test",
                "when_file_matches": ["src/x.py"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "BLOCK",
            }
        ],
    }
    patch_text = textwrap.dedent("""\
        diff --git a/src/x.py b/src/x.py
        --- a/src/x.py
        +++ b/src/x.py
        @@ -1,1 +1,2 @@
         existing
        +new line
        diff --git a/docs/required.md b/docs/required.md
        --- a/docs/required.md
        +++ b/docs/required.md
        @@ -1,1 +1,2 @@
         existing
        +new doc content
    """)
    rc = mod.run(rules, patch_text)
    assert rc == 0


def test_warn_rule_does_not_block(tmp_path: Path) -> None:
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "test-warn",
                "description": "test",
                "when_file_matches": ["src/x.py"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "WARN",
            }
        ],
    }
    patch_text = "diff --git a/src/x.py b/src/x.py\n--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\n+x\n"
    rc = mod.run(rules, patch_text)
    assert rc == 0


def test_rule_does_not_fire_when_file_not_touched(tmp_path: Path) -> None:
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "test",
                "description": "test",
                "when_file_matches": ["src/never_touched.py"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "BLOCK",
            }
        ],
    }
    patch_text = "diff --git a/src/other.py b/src/other.py\n--- a/src/other.py\n+++ b/src/other.py\n@@ -1 +1 @@\n+y\n"
    rc = mod.run(rules, patch_text)
    assert rc == 0


def test_when_diff_contains_pattern_filters(tmp_path: Path) -> None:
    """A rule with both file + pattern conditions must require BOTH."""
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "test",
                "description": "test",
                "when_file_matches": ["src/x.py"],
                "when_diff_contains_pattern": ["MAGIC_TOKEN"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "BLOCK",
            }
        ],
    }
    # File matches but pattern doesn't → rule does not apply.
    patch_text = "diff --git a/src/x.py b/src/x.py\n--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\n+something else\n"
    assert mod.run(rules, patch_text) == 0
    # Both match → rule fires; requirement missing → BLOCK exit 1.
    patch_text2 = (
        "diff --git a/src/x.py b/src/x.py\n--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\n+contains MAGIC_TOKEN here\n"
    )
    assert mod.run(rules, patch_text2) == 1


def test_malformed_regex_in_rule_is_skipped_with_warning(tmp_path: Path) -> None:
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "broken",
                "description": "bad regex",
                "when_file_matches": ["src/x.py"],
                "when_diff_contains_pattern": ["[unclosed"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "BLOCK",
            }
        ],
    }
    patch_text = "diff --git a/src/x.py b/src/x.py\n--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\n+y\n"
    # The validator must not crash and must not fail on this malformed rule.
    rc = mod.run(rules, patch_text)
    assert rc == 0


def test_pattern_match_scoped_to_files_satisfying_file_match(tmp_path: Path) -> None:
    """When a rule has both ``when_file_matches`` and a pattern condition,
    the pattern check must be scoped to the files satisfying file_match
    — not the union of all added lines across all touched files.

    Regression: an early version of the validator concatenated every
    file's added lines into one blob and ran the pattern check globally.
    A PR that touched ``src/x.py`` (file_match true) and ``CLAUDE.md``
    (file_match false, but containing the identifier name as
    documentation text) would trip rules intended for source-code
    changes only. PR #40 hit this; the fix is per-file scoping.
    """
    mod = _load_module()
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "scoped-rule",
                "description": "scope test",
                "when_file_matches": ["src/x.py"],
                "when_change_touches_pattern": ["MAGIC_TOKEN"],
                "requires_doc_update": ["docs/required.md"],
                "severity": "BLOCK",
            }
        ],
    }
    # src/x.py is in scope but doesn't contain the pattern; docs/y.md
    # contains the pattern but is out of scope. Rule must NOT fire.
    patch_text = (
        "diff --git a/src/x.py b/src/x.py\n"
        "--- a/src/x.py\n"
        "+++ b/src/x.py\n"
        "@@ -1 +1 @@\n"
        "+something unrelated\n"
        "diff --git a/docs/y.md b/docs/y.md\n"
        "--- a/docs/y.md\n"
        "+++ b/docs/y.md\n"
        "@@ -1 +1 @@\n"
        "+documentation mentions MAGIC_TOKEN here\n"
    )
    assert mod.run(rules, patch_text) == 0, (
        "rule fired on a pattern that only appears in an out-of-scope file"
    )


def test_requires_doc_passes_when_doc_exists_on_disk(tmp_path: Path) -> None:
    """`requires_doc` checks disk OR diff — distinct from `requires_doc_update`."""
    mod = _load_module()
    # The real `dependency-rationale.md` is on disk in this branch (landed in 2a).
    rules = {
        "version": 1,
        "rules": [
            {
                "id": "needs-existing-doc",
                "description": "test",
                "when_file_matches": ["pyproject.toml"],
                "requires_doc": ["docs/spec/dependency-rationale.md"],
                "severity": "BLOCK",
            }
        ],
    }
    patch_text = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1 +1 @@\n"
        "+new = 'dep'\n"
    )
    rc = mod.run(rules, patch_text)
    assert rc == 0


# ──────────────────────────────────────────────────────────────────
# Project spec-requirements.yaml smoke: validator runs against real file
# ──────────────────────────────────────────────────────────────────


def test_real_rules_file_parses() -> None:
    """The committed .github/spec-requirements.yaml must parse without error
    and contain at least one rule. Catches typos / accidental breakage
    during cleanup PRs."""
    doc = yaml.safe_load(DEFAULT_RULES.read_text())
    assert isinstance(doc, dict)
    assert doc.get("version") == 1
    assert isinstance(doc.get("rules"), list)
    assert len(doc["rules"]) >= 1
    # Each rule has the minimum keys.
    for rule in doc["rules"]:
        assert "id" in rule, f"rule missing id: {rule}"
        assert "description" in rule, f"rule missing description: {rule}"
        assert rule.get("severity") in ("BLOCK", "WARN"), f"rule {rule['id']} has invalid severity"


def test_validator_against_empty_diff_with_real_rules(tmp_path: Path) -> None:
    """Vacuous-pass check against the actual rules file."""
    patch = tmp_path / "empty.patch"
    patch.write_text("")
    result = _run("--diff", str(patch), "--rules", str(DEFAULT_RULES))
    assert result.returncode == 0
