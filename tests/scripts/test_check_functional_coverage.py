"""Tests for scripts/check_functional_coverage.py.

This script is warn-only — it always exits 0. The tests verify the
reporting surface, not exit codes for missing tests.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_functional_coverage.py"


def _run(cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _scaffold(root: Path, src_modules: list[str], int_tests: list[str]) -> None:
    (root / "src" / "claude_monitoring").mkdir(parents=True)
    for m in src_modules:
        (root / "src" / "claude_monitoring" / m).write_text("# stub\n")
    (root / "tests" / "integration").mkdir(parents=True)
    for t in int_tests:
        (root / "tests" / "integration" / t).write_text("# stub\n")


def test_pass_when_every_module_has_integration_test(tmp_path):
    _scaffold(
        tmp_path,
        src_modules=["foo.py", "bar.py"],
        int_tests=["test_foo.py", "test_bar.py"],
    )
    result = _run(tmp_path)
    assert result.returncode == 0
    assert "PASS" in result.stdout


def test_warn_when_modules_lack_integration_test(tmp_path):
    _scaffold(
        tmp_path,
        src_modules=["foo.py", "bar.py", "baz.py"],
        int_tests=["test_foo.py"],
    )
    result = _run(tmp_path)
    assert result.returncode == 0  # warn-only
    assert "WARN" in result.stdout
    assert "bar" in result.stdout
    assert "baz" in result.stdout
    assert "foo" not in result.stdout.split("WARN", 1)[1]


def test_excludes_init_and_main(tmp_path):
    """__init__.py and __main__.py never require an integration test."""
    _scaffold(
        tmp_path,
        src_modules=["__init__.py", "__main__.py", "real.py"],
        int_tests=["test_real.py"],
    )
    result = _run(tmp_path)
    assert result.returncode == 0
    assert "PASS" in result.stdout


def test_warn_only_when_src_root_missing(tmp_path):
    """Running outside a repo (no src/) reports PASS, not error."""
    result = _run(tmp_path)
    assert result.returncode == 0
    assert "PASS" in result.stdout
