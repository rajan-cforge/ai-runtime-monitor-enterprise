"""Tests for scripts/coverage_ratchet.py — per-file baseline mechanism.

These tests run the script's helper functions directly (no subprocess)
to verify the baseline-overlay logic. The tests do NOT run the script
end-to-end with a real coverage.xml because that's exercised by CI on
every PR; the value here is pinning the failure modes the judge ruling
(2026-06-12) is meant to prevent:

  - auto-pass via missing baseline entry (file not listed → diff gate
    still fires; no silent exemption)
  - a baseline'd file's pr_line_pct dropping below floor still fails
  - manual edits to the baseline file flow through load_baseline
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "coverage_ratchet.py"


def _load_module():
    """Load coverage_ratchet as a module so we can call its functions."""
    spec = importlib.util.spec_from_file_location("coverage_ratchet", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_COBERTURA_TEMPLATE = """<?xml version="1.0" ?>
<coverage line-rate="{overall:.4f}" branch-rate="0.0">
  <packages>
    <package name="x">
      <classes>
{classes}
      </classes>
    </package>
  </packages>
</coverage>
"""


def _make_cobertura(tmp_path: Path, name: str, files: dict[str, float], overall: float) -> Path:
    """Write a minimal cobertura XML with the given per-file rates."""
    cls_xml = "\n".join(
        f'        <class filename="{p}" line-rate="{r / 100:.4f}" branch-rate="0.0"/>' for p, r in files.items()
    )
    xml = _COBERTURA_TEMPLATE.format(overall=overall / 100, classes=cls_xml)
    out = tmp_path / name
    out.write_text(xml)
    return out


def _patch_baseline_path(monkeypatch, mod, tmp_path: Path) -> Path:
    """Redirect the module's BASELINE_PATH to a tmp file."""
    baseline = tmp_path / "baseline.txt"
    monkeypatch.setattr(mod, "BASELINE_PATH", baseline)
    return baseline


def test_load_baseline_empty_when_file_missing(tmp_path, monkeypatch):
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    assert mod.load_baseline() == {}


def test_load_baseline_parses_path_and_pct(tmp_path, monkeypatch):
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("# comment line ignored\n\nsrc/a.py 75.48\nsrc/b.py 69.10\n")
    assert mod.load_baseline() == {"src/a.py": 75.48, "src/b.py": 69.10}


def test_load_baseline_skips_malformed_lines(tmp_path, monkeypatch):
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("src/a.py 75.48\nmalformed line with three tokens\nsrc/b.py notanumber\nsrc/c.py 83.09\n")
    assert mod.load_baseline() == {"src/a.py": 75.48, "src/c.py": 83.09}


def test_write_baseline_round_trip(tmp_path, monkeypatch):
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    mod.write_baseline({"src/b.py": 50.0, "src/a.py": 90.0})
    loaded = mod.load_baseline()
    assert loaded == {"src/a.py": 90.0, "src/b.py": 50.0}


def test_baselined_file_at_floor_passes(tmp_path, monkeypatch, capsys):
    """A baselined file measured at its floor (within tolerance) passes."""
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("src/x.py 69.10\n")
    base = _make_cobertura(tmp_path, "base.xml", {"src/x.py": 75.48}, 82.0)
    pr = _make_cobertura(tmp_path, "pr.xml", {"src/x.py": 69.10}, 82.0)
    rc = mod.ratchet(base, pr, {"src/x.py"})
    out = capsys.readouterr().out
    assert rc == 0
    assert "diff-gate suppressed" in out


def test_baselined_file_below_floor_fails(tmp_path, monkeypatch, capsys):
    """A baselined file dropping below floor (beyond tolerance) fails."""
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("src/x.py 69.10\n")
    base = _make_cobertura(tmp_path, "base.xml", {"src/x.py": 75.48}, 82.0)
    # 68.50% is 0.60% below 69.10% floor, beyond 0.10% tolerance
    pr = _make_cobertura(tmp_path, "pr.xml", {"src/x.py": 68.50}, 81.8)
    rc = mod.ratchet(base, pr, {"src/x.py"})
    out = capsys.readouterr().out
    assert rc == 1
    assert "below baseline floor" in out


def test_baselined_file_diff_gate_does_not_fire(tmp_path, monkeypatch, capsys):
    """The diff gate is SUPPRESSED for baselined files.

    Without the baseline, base=75.48% → pr=69.10% would FAIL the diff
    gate (6.38% drop > 0.10% tolerance). With the baseline, the same
    drop PASSES because the floor was explicitly ratified.
    """
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("src/x.py 69.10\n")
    base = _make_cobertura(tmp_path, "base.xml", {"src/x.py": 75.48}, 82.0)
    pr = _make_cobertura(tmp_path, "pr.xml", {"src/x.py": 69.10}, 82.0)
    rc = mod.ratchet(base, pr, {"src/x.py"})
    assert rc == 0
    # Confirm the FAIL-causing diff line ("drop 6.38%") is NOT printed.
    out = capsys.readouterr().out
    assert "drop 6.38%" not in out


def test_unbaselined_file_diff_gate_still_fires(tmp_path, monkeypatch, capsys):
    """Files NOT in the baseline keep the existing diff-based gate.

    This is the load-bearing inverse: the baseline must not become a
    silent exemption mechanism for files that aren't explicitly listed.
    """
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)  # empty baseline
    base = _make_cobertura(tmp_path, "base.xml", {"src/y.py": 90.0}, 90.0)
    pr = _make_cobertura(tmp_path, "pr.xml", {"src/y.py": 80.0}, 80.0)
    rc = mod.ratchet(base, pr, {"src/y.py"})
    out = capsys.readouterr().out
    assert rc == 1
    assert "drop 10.00%" in out


def test_update_baseline_refreshes_listed_path(tmp_path, monkeypatch, capsys):
    """--update-baseline updates the listed path's floor from coverage.xml."""
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("src/x.py 75.48\nsrc/y.py 50.00\n")
    cov = _make_cobertura(tmp_path, "cov.xml", {"src/x.py": 69.10, "src/y.py": 51.00}, 82.0)
    rc = mod.update_baseline(cov, ["src/x.py"])
    assert rc == 0
    loaded = mod.load_baseline()
    # x.py refreshed to 69.10; y.py left alone at 50.00.
    assert loaded["src/x.py"] == 69.10
    assert loaded["src/y.py"] == 50.00


def test_update_baseline_adds_new_entry(tmp_path, monkeypatch):
    """Listing a path NOT yet in the baseline adds it (judge sees the diff)."""
    mod = _load_module()
    baseline = _patch_baseline_path(monkeypatch, mod, tmp_path)
    baseline.write_text("src/x.py 75.48\n")
    cov = _make_cobertura(tmp_path, "cov.xml", {"src/x.py": 75.48, "src/new.py": 83.09}, 82.0)
    rc = mod.update_baseline(cov, ["src/new.py"])
    assert rc == 0
    loaded = mod.load_baseline()
    assert loaded == {"src/x.py": 75.48, "src/new.py": 83.09}


def test_update_baseline_warns_on_unknown_path(tmp_path, monkeypatch, capsys):
    """A listed path not present in coverage.xml is skipped with a warning."""
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    cov = _make_cobertura(tmp_path, "cov.xml", {"src/x.py": 75.48}, 82.0)
    rc = mod.update_baseline(cov, ["src/x.py", "src/missing.py"])
    out = capsys.readouterr().out
    assert rc == 0  # one path was found, refresh succeeded
    assert "WARN" in out
    assert "src/missing.py" in out


def test_update_baseline_fails_when_no_path_found(tmp_path, monkeypatch, capsys):
    """If NO listed path is in coverage.xml, the refresh fails.

    Guards against silent no-op refreshes from typos in path names.
    """
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    cov = _make_cobertura(tmp_path, "cov.xml", {"src/x.py": 75.48}, 82.0)
    rc = mod.update_baseline(cov, ["src/typo.py"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "ERROR" in out


def test_committed_baseline_loads_two_entries():
    """The committed baseline file in this PR holds the two #118 entries."""
    mod = _load_module()
    floors = mod.load_baseline()
    assert "src/claude_monitoring/monitor.py" in floors
    assert "src/claude_monitoring/dashboard_handler.py" in floors
    assert floors["src/claude_monitoring/monitor.py"] == 69.10
    assert floors["src/claude_monitoring/dashboard_handler.py"] == 83.09


def test_baseline_file_has_documented_refresh_discipline():
    """The header documents the no-auto-pass rule from judge ruling."""
    text = (REPO_ROOT / "scripts" / "coverage_ratchet_baseline.txt").read_text()
    assert "JUDGE-REVIEWED" in text
    assert "Auto-pass mechanisms" in text
    assert "forbidden" in text


def test_baseline_file_documents_transient_floor_rule():
    """Per coverage-ratchet-baseline.a1 fix mandate: floors are transient.

    Entries get DELETED once the split lands on main; leaving them in
    place would silently disable the upward ratchet for those files.
    The rule must be documented in the baseline header AND re-emitted
    by ``write_baseline`` so it survives every ``--update-baseline`` call.
    """
    text = (REPO_ROOT / "scripts" / "coverage_ratchet_baseline.txt").read_text()
    assert "Transient-floor rule" in text
    assert "transition window only" in text
    assert "DELETING the entries" in text


def test_write_baseline_re_emits_transient_floor_rule(tmp_path, monkeypatch):
    """``write_baseline`` must preserve the transient-floor rule in its header.

    Otherwise a future ``--update-baseline`` call could strip the rule from
    the file silently.
    """
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    mod.write_baseline({"src/a.py": 90.0})
    text = (tmp_path / "baseline.txt").read_text()
    assert "Transient-floor rule" in text
    assert "transition window only" in text
    assert "DELETING the entries" in text


def _argv_dispatch(mod, argv: list[str]) -> int:
    """Run main() with the given argv. Captures sys.argv[0] convention."""
    return mod.main(["coverage_ratchet.py"] + argv)


def test_main_update_baseline_usage_error(tmp_path, monkeypatch, capsys):
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    rc = _argv_dispatch(mod, ["--update-baseline"])
    assert rc == 2
    assert "Usage:" in capsys.readouterr().err


def test_main_update_baseline_missing_path_arg(tmp_path, monkeypatch, capsys):
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)
    cov = _make_cobertura(tmp_path, "cov.xml", {"src/x.py": 75.48}, 82.0)
    rc = _argv_dispatch(mod, ["--update-baseline", str(cov)])
    assert rc == 2  # need at least one path argument
    assert "Usage:" in capsys.readouterr().err


def test_main_legacy_two_arg_form_still_works(tmp_path, monkeypatch, capsys):
    """Backward compat: the existing CI calls without --update-baseline keep working."""
    mod = _load_module()
    _patch_baseline_path(monkeypatch, mod, tmp_path)  # no baseline → diff gate
    base = _make_cobertura(tmp_path, "base.xml", {"src/x.py": 80.0}, 82.0)
    pr = _make_cobertura(tmp_path, "pr.xml", {"src/x.py": 80.0}, 82.0)
    # Empty changed list (no changed-files file, will fall back to git diff
    # which returns nothing useful in tests — pass an empty changed.txt).
    changed = tmp_path / "changed.txt"
    changed.write_text("")
    rc = _argv_dispatch(mod, [str(base), str(pr), str(changed)])
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


if __name__ == "__main__":
    sys.exit(0)
