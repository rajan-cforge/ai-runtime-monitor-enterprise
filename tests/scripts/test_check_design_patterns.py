"""Tests for scripts/check_design_patterns.py.

The real-repo smoke test runs the script as a subprocess (per
docs/RUNBOOK.md "Test isolation"). The per-rule detection tests
load the script as a module so the AST helpers can be exercised
directly without scaffolding a fake `src/claude_monitoring/` tree
for every case.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_design_patterns.py"


def _load_module():
    """Load the script as a module (one-shot per test process)."""
    spec = importlib.util.spec_from_file_location("check_design_patterns", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _collect_msgs(src: str) -> list[str]:
    mod = _load_module()
    checker = mod.DesignPatternChecker(Path("dummy.py"))
    checker.visit(ast.parse(src))
    return [m for _, m in checker.violations]


def test_real_repo_passes_with_baseline() -> None:
    """The committed baseline must keep `src/` PASSing today.

    If this fails, either someone added a new design-pattern
    violation (intentional or not), or the baseline drifted from
    the source tree (e.g., a violation was fixed but the baseline
    entry wasn't removed — non-blocking but worth noting).
    """
    result = _run()
    assert result.returncode == 0, (
        f"scripts/check_design_patterns.py against real src/ failed.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_detects_bare_except() -> None:
    """The script must flag `except:` (no exception type)."""
    msgs = _collect_msgs("def f():\n    try:\n        return 1\n    except:\n        return 0\n")
    assert any("bare 'except:'" in m for m in msgs), f"bare except not detected: {msgs}"


def test_detects_empty_except_pass() -> None:
    """Empty `except Exception: pass` must be flagged."""
    msgs = _collect_msgs("def f():\n    try:\n        return 1\n    except Exception:\n        pass\n")
    assert any("silently swallowing" in m for m in msgs), f"empty except pass not detected: {msgs}"


def test_detects_mutable_default_argument() -> None:
    msgs = _collect_msgs("def f(x=[]):\n    return x\n")
    assert any("mutable default" in m for m in msgs), f"mutable default not detected: {msgs}"


def test_detects_subprocess_shell_true() -> None:
    msgs = _collect_msgs("import subprocess\ndef f():\n    subprocess.run('echo x', shell=True)\n")
    assert any("shell=True" in m for m in msgs), f"shell=True not detected: {msgs}"


def test_detects_requests_verify_false() -> None:
    msgs = _collect_msgs("import requests\ndef f():\n    requests.get('https://example.com', verify=False)\n")
    assert any("verify=False" in m for m in msgs), f"verify=False not detected: {msgs}"


def test_public_function_without_docstring_flagged() -> None:
    msgs = _collect_msgs("def public_no_doc():\n    return 1\n")
    assert any("missing docstring" in m for m in msgs)


def test_private_function_without_docstring_not_flagged() -> None:
    """Functions starting with `_` are exempt from the docstring rule."""
    msgs = _collect_msgs("def _private_no_doc():\n    return 1\n")
    assert not any("missing docstring" in m for m in msgs), msgs


def test_update_baseline_flag_writes_file(tmp_path: Path, monkeypatch) -> None:
    """`--update-baseline` rewrites the baseline file with current violations."""
    mod = _load_module()
    baseline_file = tmp_path / "baseline.txt"
    monkeypatch.setattr(mod, "BASELINE_PATH", baseline_file)
    mod.write_baseline(["src/x.py:1: foo", "src/y.py:2: bar"])
    text = baseline_file.read_text()
    assert "src/x.py:1: foo" in text
    assert "src/y.py:2: bar" in text
    assert "#" in text  # header comments present


def test_baseline_comments_and_blanks_ignored(tmp_path: Path, monkeypatch) -> None:
    """Lines starting with `#` or empty in the baseline must be skipped."""
    mod = _load_module()
    baseline_file = tmp_path / "baseline.txt"
    baseline_file.write_text(
        "# header comment\n"
        "\n"
        "src/real.py:1: something\n"
        "  # indented comment-ish should not be treated as a violation\n"
        "src/other.py:2: another\n"
    )
    monkeypatch.setattr(mod, "BASELINE_PATH", baseline_file)
    loaded = mod.load_baseline()
    assert "src/real.py:1: something" in loaded
    assert "src/other.py:2: another" in loaded
    assert "# header comment" not in loaded
