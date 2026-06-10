"""Smoke tests for scripts/antfood-loop.sh.

These don't run the full loop (it polls indefinitely). They verify the
script syntax is valid and that the critical guardrails are present:
proxy-unset, Python version check, state-file rollback, SIGTERM trap.

Smoke-level guardrails only; the loop itself runs out-of-band.
"""

import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "antfood-loop.sh"


def test_script_exists_and_is_executable():
    assert SCRIPT.exists(), f"missing: {SCRIPT}"
    mode = SCRIPT.stat().st_mode
    assert mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), "no exec bit set"


def test_script_syntax_is_valid():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_script_unsets_proxy_vars():
    text = SCRIPT.read_text()
    assert "unset HTTPS_PROXY" in text
    assert "https_proxy" in text and "all_proxy" in text
    # `pip install` appears in comments too; match the actual command form
    # (`pip install -e`) to find the real install call.
    proxy_idx = text.find("unset HTTPS_PROXY")
    pip_idx = text.find("pip install -e")
    assert proxy_idx >= 0 and pip_idx >= 0
    assert proxy_idx < pip_idx, "proxy unset must come before pip install -e"


def test_script_checks_python_version():
    text = SCRIPT.read_text()
    assert "py_minor" in text, "expected a py_minor variable for version check"
    assert "-ge 13" in text or ">= 13" in text, "expected an explicit 3.13+ guard"


def test_script_uses_state_file_for_rollback():
    text = SCRIPT.read_text()
    assert "STATE_FILE" in text, "expected STATE_FILE for last-known-good"
    assert "save_known_good" in text, "expected save_known_good helper"
    assert "get_known_good" in text, "expected get_known_good helper"


def test_state_file_path_is_under_home():
    text = SCRIPT.read_text()
    assert "$HOME/.vigil-antfood-state" in text or "~/.vigil-antfood-state" in text


def test_script_has_signal_trap():
    text = SCRIPT.read_text()
    assert "trap" in text and ("SIGTERM" in text or "SIGINT" in text), (
        "expected a signal trap so the loop exits cleanly without killing the daemon"
    )
