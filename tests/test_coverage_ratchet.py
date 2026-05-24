"""Tests for scripts/coverage_ratchet.py.

Each test invokes the script via ``subprocess.run`` so the script
executes in its own process. This avoids the classic pytest foot-gun
where importing the script at module-collection time (via
``importlib.exec_module``) mutates ``sys.modules`` / cwd / env and
then perturbs the import resolution of unrelated tests collected
later in the session. The earlier version of this file did exactly
that and caused a deterministic ~0.84% coverage drop on wizard.py
and a handful of other modules.

See docs/RUNBOOK.md "Test isolation" for the discipline.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "coverage_ratchet.py"


def _write_cobertura(path: Path, line_rate: float, branch_rate: float | None = None) -> Path:
    """Write a minimal cobertura XML with just the two rate attrs the ratchet reads."""
    if branch_rate is None:
        attrs = f'line-rate="{line_rate}"'
    else:
        attrs = f'line-rate="{line_rate}" branch-rate="{branch_rate}"'
    path.write_text(f'<?xml version="1.0" ?>\n<coverage {attrs}><packages/></coverage>\n')
    return path


def _run_ratchet(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the ratchet script as a subprocess and return the completed process."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_pass_when_coverage_improves(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.72, 0.65)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.75, 0.70)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 0
    assert "PASS" in result.stdout


def test_pass_when_drop_within_line_tolerance(tmp_path):
    # 0.05% drop, tolerance is 0.1% — should pass
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.65)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.71995, 0.65)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 0


def test_fail_when_line_drops_beyond_tolerance(tmp_path):
    # 0.5% drop, tolerance is 0.1% — should fail
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.65)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7150, 0.65)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 1
    assert "FAIL" in result.stdout
    assert "line coverage dropped" in result.stdout


def test_fail_when_branch_drops_beyond_tolerance(tmp_path):
    # branch drops 1%, tolerance 0.5% — should fail
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.6500)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.6400)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 1
    assert "branch coverage dropped" in result.stdout


def test_pass_when_branch_drops_within_tolerance(tmp_path):
    # branch drops 0.3%, tolerance 0.5% — should pass
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.6500)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.6470)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 0


def test_missing_branch_rate_treated_as_zero(tmp_path):
    """Older coverage configs may omit branch-rate; ratchet must not crash."""
    base = _write_cobertura(tmp_path / "base.xml", 0.72)  # no branch-rate
    pr = _write_cobertura(tmp_path / "pr.xml", 0.72)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 0


def test_summary_prints_deltas_with_sign(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.7000, 0.6000)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.5800)
    result = _run_ratchet(str(base), str(pr))
    assert "+2.00%" in result.stdout  # line delta sign
    assert "-2.00%" in result.stdout  # branch delta sign


def test_cli_wrong_arg_count_returns_2(tmp_path):
    """Usage error returns 2 (not 1) so CI can distinguish bad invocation
    from a real coverage drop."""
    result = _run_ratchet()  # no args
    assert result.returncode == 2
    assert "Usage" in result.stderr


def test_cli_pass_path(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.7, 0.6)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.8, 0.7)
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 0


def test_cli_fail_path(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.7, 0.6)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.5, 0.6)  # huge line drop
    result = _run_ratchet(str(base), str(pr))
    assert result.returncode == 1
