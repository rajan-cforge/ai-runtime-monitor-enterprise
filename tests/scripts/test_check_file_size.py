"""Tests for scripts/check_file_size.py.

Each test invokes the script as a subprocess for isolation
(process isolation keeps the gate-script's own warnings from
contaminating pytest's session state).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_file_size.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _make_tree(root: Path, files: dict[str, int]) -> None:
    """Create files under *root* with the given line counts."""
    for name, lines in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join("x" for _ in range(lines)) + "\n")


def test_pass_when_all_files_under_threshold(tmp_path):
    _make_tree(tmp_path, {"a.py": 100, "sub/b.py": 200})
    result = _run(str(tmp_path))
    assert result.returncode == 0
    assert "PASS" in result.stdout


def test_fail_when_a_file_exceeds_threshold(tmp_path):
    _make_tree(tmp_path, {"a.py": 100, "huge.py": 6000})
    result = _run(str(tmp_path))
    assert result.returncode == 1
    assert "FAIL" in result.stdout
    assert "huge.py" in result.stdout


def test_lists_only_violators_not_all_files(tmp_path):
    _make_tree(tmp_path, {"ok.py": 50, "also_ok.py": 200, "over.py": 6000})
    result = _run(str(tmp_path))
    assert result.returncode == 1
    assert "over.py" in result.stdout
    # The PASS message should not appear when there are failures
    assert "PASS:" not in result.stdout


def test_recurses_into_subdirectories(tmp_path):
    _make_tree(tmp_path, {"deep/nested/dir/big.py": 6000})
    result = _run(str(tmp_path))
    assert result.returncode == 1
    assert "big.py" in result.stdout


def test_only_counts_dot_py_files(tmp_path):
    """A massive non-.py file should not fail the gate."""
    (tmp_path / "huge.txt").write_text("x\n" * 10000)
    (tmp_path / "ok.py").write_text("x\n" * 50)
    result = _run(str(tmp_path))
    assert result.returncode == 0


def test_missing_path_returns_2(tmp_path):
    """Usage error for non-existent path returns 2."""
    bogus = tmp_path / "does-not-exist"
    result = _run(str(bogus))
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_real_repo_src_passes():
    """The actual src/ tree must pass under the current ceiling (smoke test)."""
    result = _run(str(REPO_ROOT / "src"))
    assert result.returncode == 0, f"src/ exceeds the file-size ceiling: {result.stdout}"
