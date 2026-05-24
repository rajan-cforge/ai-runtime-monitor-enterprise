"""Tests for scripts/check_function_size.py.

Each test invokes the script as a subprocess for isolation.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_function_size.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _write(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)


def test_pass_when_all_functions_short(tmp_path):
    _write(
        tmp_path / "a.py",
        "def small():\n    return 1\n\n\ndef also_small():\n    return 2\n",
    )
    result = _run(str(tmp_path))
    assert result.returncode == 0
    assert "PASS" in result.stdout


def test_fail_when_function_exceeds_threshold(tmp_path):
    body = "    pass\n" * 500  # 500 inner lines pushes def over 400
    _write(tmp_path / "big.py", f"def too_long():\n{body}")
    result = _run(str(tmp_path))
    assert result.returncode == 1
    assert "FAIL" in result.stdout
    assert "too_long" in result.stdout


def test_async_functions_checked(tmp_path):
    body = "    pass\n" * 500
    _write(tmp_path / "a.py", f"async def too_long():\n{body}")
    result = _run(str(tmp_path))
    assert result.returncode == 1
    assert "too_long" in result.stdout


def test_nested_function_independently_checked(tmp_path):
    """An inner function that's long must be flagged even when the outer is short."""
    body = "        pass\n" * 500
    _write(
        tmp_path / "n.py",
        f"def outer():\n    def inner():\n{body}    return inner\n",
    )
    result = _run(str(tmp_path))
    assert result.returncode == 1
    assert "inner" in result.stdout


def test_syntax_error_files_skipped_not_crash(tmp_path):
    """A file that can't be parsed should be skipped, not crash the check."""
    _write(tmp_path / "broken.py", "def oops(\n  this is not valid python\n")
    _write(tmp_path / "ok.py", "def fine():\n    return 1\n")
    result = _run(str(tmp_path))
    assert result.returncode == 0


def test_missing_path_returns_2(tmp_path):
    bogus = tmp_path / "missing"
    result = _run(str(bogus))
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_real_repo_src_passes():
    """The actual src/ tree must pass under the current ceiling."""
    result = _run(str(REPO_ROOT / "src"))
    assert result.returncode == 0, f"src/ exceeds the function-size ceiling: {result.stdout}"
