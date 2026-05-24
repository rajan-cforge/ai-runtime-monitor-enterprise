"""Tests for scripts/coverage_ratchet.py.

The ratchet compares cobertura XML reports for base vs PR and fails
when coverage drops beyond tolerance. Tests build small synthetic
XMLs rather than running pytest-cov in a subprocess.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coverage_ratchet.py"

spec = importlib.util.spec_from_file_location("coverage_ratchet", SCRIPT)
ratchet_mod = importlib.util.module_from_spec(spec)
sys.modules["coverage_ratchet"] = ratchet_mod
spec.loader.exec_module(ratchet_mod)


def _write_cobertura(path: Path, line_rate: float, branch_rate: float | None = None) -> Path:
    """Minimal cobertura XML with the two rate attrs the ratchet reads."""
    if branch_rate is None:
        attrs = f'line-rate="{line_rate}"'
    else:
        attrs = f'line-rate="{line_rate}" branch-rate="{branch_rate}"'
    path.write_text(
        f'<?xml version="1.0" ?>\n<coverage {attrs}><packages/></coverage>\n'
    )
    return path


def test_pass_when_coverage_improves(tmp_path, capsys):
    base = _write_cobertura(tmp_path / "base.xml", 0.72, 0.65)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.75, 0.70)
    assert ratchet_mod.ratchet(base, pr) == 0
    assert "PASS" in capsys.readouterr().out


def test_pass_when_drop_within_line_tolerance(tmp_path, capsys):
    # 0.05% drop, tolerance is 0.1% — should pass
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.65)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.71995, 0.65)
    assert ratchet_mod.ratchet(base, pr) == 0


def test_fail_when_line_drops_beyond_tolerance(tmp_path, capsys):
    # 0.5% drop, tolerance is 0.1% — should fail
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.65)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7150, 0.65)
    assert ratchet_mod.ratchet(base, pr) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "line coverage dropped" in out


def test_fail_when_branch_drops_beyond_tolerance(tmp_path, capsys):
    # branch drops 1%, tolerance 0.5% — should fail
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.6500)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.6400)
    assert ratchet_mod.ratchet(base, pr) == 1
    out = capsys.readouterr().out
    assert "branch coverage dropped" in out


def test_pass_when_branch_drops_within_tolerance(tmp_path, capsys):
    # branch drops 0.3%, tolerance 0.5% — should pass
    base = _write_cobertura(tmp_path / "base.xml", 0.7200, 0.6500)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.6470)
    assert ratchet_mod.ratchet(base, pr) == 0


def test_missing_branch_rate_treated_as_zero(tmp_path):
    """Older coverage configs may omit branch-rate; ratchet must not crash."""
    base = _write_cobertura(tmp_path / "base.xml", 0.72)  # no branch-rate
    pr = _write_cobertura(tmp_path / "pr.xml", 0.72)
    assert ratchet_mod.ratchet(base, pr) == 0


def test_summary_prints_deltas_with_sign(tmp_path, capsys):
    base = _write_cobertura(tmp_path / "base.xml", 0.7000, 0.6000)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.7200, 0.5800)
    ratchet_mod.ratchet(base, pr)
    out = capsys.readouterr().out
    assert "+2.00%" in out  # line delta sign
    assert "-2.00%" in out  # branch delta sign


def test_cli_wrong_arg_count_returns_2(tmp_path, capsys):
    """Usage error returns 2 (not 1) so CI can distinguish."""
    assert ratchet_mod.main(["coverage_ratchet.py"]) == 2
    assert "Usage" in capsys.readouterr().err


def test_cli_pass_path(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.7, 0.6)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.8, 0.7)
    assert ratchet_mod.main(["coverage_ratchet.py", str(base), str(pr)]) == 0


def test_cli_fail_path(tmp_path):
    base = _write_cobertura(tmp_path / "base.xml", 0.7, 0.6)
    pr = _write_cobertura(tmp_path / "pr.xml", 0.5, 0.6)  # huge line drop
    assert ratchet_mod.main(["coverage_ratchet.py", str(base), str(pr)]) == 1
