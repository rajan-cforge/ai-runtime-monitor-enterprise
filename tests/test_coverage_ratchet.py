"""Tests for scripts/coverage_ratchet.py.

Each test invokes the script via ``subprocess.run`` so the script
executes in its own process. See docs/RUNBOOK.md "Test isolation".
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "coverage_ratchet.py"


def _write_cobertura(
    path: Path,
    overall_line: float,
    overall_branch: float | None = None,
    files: dict[str, tuple[float, float | None]] | None = None,
) -> Path:
    """Write a cobertura XML with optional per-file <class> entries.

    ``files`` maps filename -> (line_rate, branch_rate). Both rates are
    decimals (0.0-1.0). branch_rate may be None to omit the attribute.
    """
    if overall_branch is None:
        root_attrs = f'line-rate="{overall_line}"'
    else:
        root_attrs = f'line-rate="{overall_line}" branch-rate="{overall_branch}"'

    classes = ""
    if files:
        for fname, (lr, br) in files.items():
            if br is None:
                cls_attrs = f'name="{fname}" filename="{fname}" line-rate="{lr}"'
            else:
                cls_attrs = f'name="{fname}" filename="{fname}" line-rate="{lr}" branch-rate="{br}"'
            classes += f"<class {cls_attrs}><lines/></class>"

    path.write_text(
        f'<?xml version="1.0" ?>\n<coverage {root_attrs}>'
        f"<packages><package><classes>{classes}</classes></package></packages>"
        f"</coverage>\n"
    )
    return path


def _changed_list(path: Path, files: list[str]) -> Path:
    path.write_text("\n".join(files) + "\n")
    return path


def _run_ratchet(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the ratchet script as a subprocess; return the completed process."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_pass_when_no_changed_files(tmp_path):
    """PR that doesn't modify any src/ file passes regardless of overall delta."""
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.0)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.74, 0.0)  # 1% overall drop
    changed = _changed_list(tmp_path / "changed.txt", [])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 0
    assert "Per-file gate skipped" in result.stdout


def test_fail_overall_drop_above_hard_limit(tmp_path):
    """Catastrophic overall drop fails even with no PR-modified src files."""
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.0)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.65, 0.0)  # 10% drop, > 5% hard limit
    changed = _changed_list(tmp_path / "changed.txt", [])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 1
    assert "hard limit" in result.stdout


def test_pass_when_changed_file_coverage_held(tmp_path):
    """PR-modified file with unchanged coverage passes."""
    files_base = {"src/claude_monitoring/widget.py": (0.80, 0.70)}
    files_pr = {"src/claude_monitoring/widget.py": (0.80, 0.70)}
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.65, files_base)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.74, 0.64, files_pr)
    changed = _changed_list(tmp_path / "changed.txt", ["src/claude_monitoring/widget.py"])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 0
    assert "PASS" in result.stdout


def test_fail_when_changed_file_line_drop_exceeds_tolerance(tmp_path):
    """Per-file line drop above tolerance fails."""
    files_base = {"src/claude_monitoring/widget.py": (0.80, 0.70)}
    files_pr = {"src/claude_monitoring/widget.py": (0.70, 0.70)}  # 10pp drop
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.65, files_base)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.75, 0.65, files_pr)
    changed = _changed_list(tmp_path / "changed.txt", ["src/claude_monitoring/widget.py"])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 1
    assert "FAIL" in result.stdout
    assert "src/claude_monitoring/widget.py" in result.stdout


def test_fail_when_changed_file_branch_drop_exceeds_tolerance(tmp_path):
    """Per-file branch drop above tolerance fails."""
    files_base = {"src/claude_monitoring/widget.py": (0.80, 0.70)}
    files_pr = {"src/claude_monitoring/widget.py": (0.80, 0.60)}  # 10pp branch drop
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.65, files_base)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.75, 0.65, files_pr)
    changed = _changed_list(tmp_path / "changed.txt", ["src/claude_monitoring/widget.py"])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 1
    assert "branch" in result.stdout


def test_pass_when_changed_file_drop_within_tolerance(tmp_path):
    """Small drop on a changed file stays within tolerance."""
    files_base = {"src/claude_monitoring/widget.py": (0.8000, 0.7000)}
    files_pr = {"src/claude_monitoring/widget.py": (0.79995, 0.6970)}  # 0.05/0.3pp
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.65, files_base)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.75, 0.65, files_pr)
    changed = _changed_list(tmp_path / "changed.txt", ["src/claude_monitoring/widget.py"])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 0


def test_unrelated_file_drop_does_not_fail(tmp_path):
    """An unrelated file losing coverage does NOT fail when the PR doesn't touch it.

    This is the core property: deterministic CI quirks that shift coverage on
    modules the PR doesn't modify can no longer fail the gate.
    """
    files_base = {
        "src/claude_monitoring/widget.py": (0.80, 0.70),
        "src/claude_monitoring/wizard.py": (0.80, 0.70),
    }
    files_pr = {
        "src/claude_monitoring/widget.py": (0.80, 0.70),  # unchanged
        "src/claude_monitoring/wizard.py": (0.50, 0.40),  # huge drop, but unrelated
    }
    base = _write_cobertura(tmp_path / "base.xml", 0.75, 0.65, files_base)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.74, 0.63, files_pr)
    changed = _changed_list(tmp_path / "changed.txt", ["src/claude_monitoring/widget.py"])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 0


def test_missing_branch_rate_in_file_ok(tmp_path):
    """Files missing branch-rate attr are treated as 0.0 branch coverage."""
    files_base = {"src/claude_monitoring/widget.py": (0.80, None)}
    files_pr = {"src/claude_monitoring/widget.py": (0.80, None)}
    base = _write_cobertura(tmp_path / "base.xml", 0.75, None, files_base)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.75, None, files_pr)
    changed = _changed_list(tmp_path / "changed.txt", ["src/claude_monitoring/widget.py"])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert result.returncode == 0


def test_summary_prints_overall_delta_with_sign(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.7000, 0.6000)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.5800)
    changed = _changed_list(tmp_path / "changed.txt", [])
    result = _run_ratchet(str(base), str(pr), str(changed))
    assert "+2.00%" in result.stdout
    assert "-2.00%" in result.stdout


def test_cli_wrong_arg_count_returns_2(tmp_path):
    """Usage error returns 2 so CI can distinguish bad invocation from a coverage drop."""
    result = _run_ratchet()
    assert result.returncode == 2
    assert "Usage" in result.stderr
