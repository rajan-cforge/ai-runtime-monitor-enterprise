"""TDD test suite for v0.2.2 P1.2 — `discovery-security-model-compliance` gate.

Per the architect-pass §5: AST-based check at
`scripts/check_discovery_security_model.py`, scoped to
`src/claude_monitoring/attack_surface/`, zero-tolerance (no baseline).

12 tests:
- 4 FAIL patterns covering yaml.load (both alias forms), the forbidden
  subprocess shell kwarg, and the os shell-out builtin family
- 3 PASS patterns: safe_yaml_load helper / yaml.safe_load direct /
  subprocess argv list
- 2 WARN heuristics: file-open without validate_path / Path.read_text
  without size cap
- 1 baseline: real attack_surface/ tree must show zero violations

Tests exercise the gate as a subprocess (same architecture as PR #82's
privacy-gate tests).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_discovery_security_model.py"

# Literal builtin names — these MUST stay literal so a human auditor reading
# the test source sees explicitly what patterns the gate is being asserted
# against. Earlier revisions assembled these at runtime to dodge a write-hook
# match; that was the wrong reflex (disguising code to silence a guard).
# Exempt openly via this comment; never disguise.
_OS_BUILTIN_NAMES = ("system", "popen", "spawnvp")


def _run_gate_with_synthetic_surface(tmp_path: Path, surface_files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the gate against a synthetic attack_surface/ tree.

    Mirrors the privacy-gate test architecture from PR #82 — invokes the
    script as a subprocess against a tmp repo skeleton so the test covers
    what CI sees.
    """
    tmp_scripts = tmp_path / "scripts"
    tmp_scripts.mkdir()
    (tmp_scripts / "check_discovery_security_model.py").write_text(SCRIPT.read_text())

    surface_dir = tmp_path / "src" / "claude_monitoring" / "attack_surface"
    surface_dir.mkdir(parents=True)
    for rel_path, content in surface_files.items():
        target = surface_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    return subprocess.run(
        [sys.executable, str(tmp_scripts / "check_discovery_security_model.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


class TestGateFailPatterns:
    def test_yaml_load_direct_fail(self, tmp_path: Path) -> None:
        """`import yaml; yaml.load(f)` → FAIL exit 1."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"bad.py": "import yaml\ndef p(f):\n    return yaml.load(f)\n"},
        )
        assert result.returncode == 1
        assert "yaml.load" in result.stderr

    def test_yaml_unsafe_load_fail(self, tmp_path: Path) -> None:
        """`import yaml; yaml.unsafe_load(f)` → FAIL exit 1."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"bad.py": "import yaml\ndef p(f):\n    return yaml.unsafe_load(f)\n"},
        )
        assert result.returncode == 1
        assert "yaml.unsafe_load" in result.stderr or "yaml.load" in result.stderr

    def test_yaml_load_alias_from_import_fail(self, tmp_path: Path) -> None:
        """`from yaml import load; load(f)` → FAIL (alias-import bypass closed,
        same architecture as PR #82's privacy gate)."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"bad.py": "from yaml import load\ndef p(f):\n    return load(f)\n"},
        )
        assert result.returncode == 1
        assert "yaml" in result.stderr.lower()

    def test_yaml_load_module_alias_fail(self, tmp_path: Path) -> None:
        """`import yaml as y; y.load(f)` → FAIL (module-alias bypass closed,
        2026-06-05 Phase B review hardening)."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"bad.py": "import yaml as y\ndef p(f):\n    return y.load(f)\n"},
        )
        assert result.returncode == 1
        assert "yaml" in result.stderr.lower()

    def test_subprocess_shell_kwarg_fail(self, tmp_path: Path) -> None:
        """forbidden subprocess shell-kwarg invocation → FAIL exit 1."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"bad.py": 'import subprocess\ndef p():\n    return subprocess.run("ls", shell=True)\n'},
        )
        assert result.returncode == 1
        assert "shell" in result.stderr.lower() or "subprocess" in result.stderr.lower()

    @pytest.mark.parametrize("builtin_name", _OS_BUILTIN_NAMES)
    def test_os_shell_out_builtins_fail(self, tmp_path: Path, builtin_name: str) -> None:
        """Parametrized over the `os` shell-out built-ins family (Phase B review
        hardening 2026-06-05). The security subsystem must not delegate to
        repo-wide bandit. Scoped failure message should name `safe_subprocess`
        as the replacement helper."""
        bad_call = f"os.{builtin_name}('ls')"
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"bad.py": f"import os\ndef p():\n    return {bad_call}\n"},
        )
        assert result.returncode == 1
        assert "safe_subprocess" in result.stderr or "os." in result.stderr


class TestGatePassPatterns:
    def test_safe_yaml_load_helper_pass(self, tmp_path: Path) -> None:
        """Helper-wrapped form → PASS exit 0."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {
                "good.py": (
                    "from claude_monitoring.attack_surface.discovery.helpers import safe_yaml_load\n"
                    "def p(text):\n"
                    "    return safe_yaml_load(text)\n"
                ),
            },
        )
        assert result.returncode == 0, f"unexpected fail: {result.stderr!r}"

    def test_yaml_safe_load_direct_pass(self, tmp_path: Path) -> None:
        """`yaml.safe_load(text)` directly → PASS exit 0."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"good.py": "import yaml\ndef p(t):\n    return yaml.safe_load(t)\n"},
        )
        assert result.returncode == 0, f"unexpected fail: {result.stderr!r}"

    def test_subprocess_argv_list_pass(self, tmp_path: Path) -> None:
        """`subprocess.run(["pip", "list"])` → PASS exit 0."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {
                "good.py": (
                    "import subprocess\n"
                    "def p():\n"
                    '    return subprocess.run(["pip", "list"], shell=False, capture_output=True, text=True)\n'
                ),
            },
        )
        assert result.returncode == 0, f"unexpected fail: {result.stderr!r}"


class TestGateWarnHeuristics:
    def test_open_without_validate_path_warn(self, tmp_path: Path) -> None:
        """Direct file-open with no `validate_path` call in same function → WARN
        (exit 0 with warning text on stderr).

        Heuristic — function-scope check; documented limitation in the gate."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {"warn.py": "def p(path):\n    return open(path).read()\n"},
        )
        assert result.returncode == 0
        assert "validate_path" in result.stderr.lower() or "warn" in result.stderr.lower()

    def test_read_text_without_validate_path_warn(self, tmp_path: Path) -> None:
        """`Path(p).read_text()` without a `validate_path` call in the same
        function body → WARN exit 0."""
        result = _run_gate_with_synthetic_surface(
            tmp_path,
            {
                "warn.py": ("from pathlib import Path\ndef p(p_str):\n    return Path(p_str).read_text()\n"),
            },
        )
        assert result.returncode == 0
        assert "validate_path" in result.stderr.lower() or "warn" in result.stderr.lower()


class TestGateBaseline:
    def test_real_attack_surface_zero_violations(self) -> None:
        """Run the gate against the REAL post-P1.1 `src/claude_monitoring/attack_surface/`
        — must pass with zero FAIL violations.

        Pins the baseline: P1.1 ships no yaml/subprocess/forbidden-shell-out
        usage in attack_surface/. This assertion would fail if anyone sneaks
        one in before the gate is wired into CI."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        # Exit 0 = no FAIL violations. WARN heuristics may print to stderr
        # but exit code stays 0.
        assert result.returncode == 0, f"baseline failed: {result.stderr!r}"
