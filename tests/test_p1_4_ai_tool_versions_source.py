"""P1.4-minimal — `AIToolVersionsSource` tests (CLI-binary strategy only).

C2 pure-enumeration source. Per the ratified Phase B test list. Info.plist
and npm package.json strategies are DEFERRED to the C3 batch (they parse
structured input) — this source ships with CLI `--version` probes only.

8 tests covering happy path, not-installed, non-zero exit, regex
mismatch, timeout, per-item isolation, registry shape, and the
empirical real-machine check.
"""

from __future__ import annotations

import shutil
import subprocess
from unittest import mock

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.discovery.sources.ai_tool_versions import (
    KNOWN_TOOLS,
    AIToolVersionsSource,
)


def _cp(argv: list[str], stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr="")


class TestAIToolVersionsSource:
    def test_happy_path_claude_version_parsed(self) -> None:
        """Mock `claude --version` → Asset with version='2.1.165'; raw output stored."""
        src = AIToolVersionsSource(
            known_tools=[
                {"name": "claude", "argv": ["claude", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
            ]
        )
        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.ai_tool_versions.safe_subprocess",
            return_value=_cp(["claude", "--version"], "2.1.165 (Claude Code)\n"),
        ):
            result = src.run_with_safety()
        assert len(result) == 1
        a = result[0]
        assert a.name == "claude"
        assert a.version == "2.1.165"
        assert a.source == "ai-tool-versions"
        assert a.type == "ai_tool"
        assert "raw_version_output" in a.current_state
        assert len(a.current_state["raw_version_output"]) <= 200
        # Cross-cutting
        assert src.name() == "ai-tool-versions"
        assert src.requires_auth() is False
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_tool_not_installed_silent_skip(self, caplog) -> None:
        """`FileNotFoundError` → tool produces no Asset; no WARNING; other tools still probed."""
        src = AIToolVersionsSource(
            known_tools=[
                {"name": "missing", "argv": ["missing", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
                {"name": "claude", "argv": ["claude", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
            ]
        )
        # Mock: first call raises FileNotFoundError, second succeeds
        calls = [0]

        def side_effect(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                raise FileNotFoundError("missing not on PATH")
            return _cp(["claude", "--version"], "2.1.165 (Claude Code)\n")

        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.ai_tool_versions.safe_subprocess",
            side_effect=side_effect,
        ):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_tool_versions"):
                result = src.run_with_safety()
        # Only the 1 found tool produced an asset
        assert len(result) == 1
        assert result[0].name == "claude"
        # No WARNING for the missing tool — silent normal flow
        assert not any("missing" in r.message for r in caplog.records)

    def test_non_zero_exit_warns_and_skips(self, caplog) -> None:
        """Non-zero exit → no Asset for that tool + WARNING; other tools probed."""
        src = AIToolVersionsSource(
            known_tools=[
                {"name": "broken", "argv": ["broken", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
            ]
        )
        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.ai_tool_versions.safe_subprocess",
            return_value=_cp(["broken", "--version"], "error\n", returncode=1),
        ):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_tool_versions"):
                result = src.run_with_safety()
        assert result == []
        assert any("broken" in r.message for r in caplog.records)

    def test_output_does_not_match_regex_warns_and_skips(self, caplog) -> None:
        """Stdout that doesn't match regex → no Asset + WARNING with raw output (≤200 chars)."""
        src = AIToolVersionsSource(
            known_tools=[
                {"name": "weird", "argv": ["weird", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
            ]
        )
        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.ai_tool_versions.safe_subprocess",
            return_value=_cp(["weird", "--version"], "unexpected garbage no version here\n"),
        ):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_tool_versions"):
                result = src.run_with_safety()
        assert result == []
        warns = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warns) >= 1
        # Raw output is in the warning (capped at 200)
        assert any("unexpected garbage" in r.message for r in warns)

    def test_subprocess_timeout_warns_and_skips(self, caplog) -> None:
        """Per-tool TimeoutExpired → that tool skipped + WARNING; outcome stays
        SUCCESS for the source if at least one tool succeeded."""
        src = AIToolVersionsSource(
            known_tools=[
                {"name": "hang", "argv": ["hang", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
                {"name": "ok", "argv": ["ok", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
            ]
        )
        calls = [0]

        def side_effect(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                raise subprocess.TimeoutExpired(["hang"], 30.0)
            return _cp(["ok"], "1.2.3\n")

        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.ai_tool_versions.safe_subprocess",
            side_effect=side_effect,
        ):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_tool_versions"):
                result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "ok"
        assert any("hang" in r.message for r in caplog.records)

    def test_per_item_isolation_one_probe_raises_others_succeed(self, caplog) -> None:
        """**Per-item isolation contract pin.** 5 tools; 1 raises mid-probe →
        4 Assets + 1 WARNING."""
        src = AIToolVersionsSource(
            known_tools=[
                {"name": f"t{i}", "argv": [f"t{i}", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"} for i in range(5)
            ]
        )
        calls = [0]

        def side_effect(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 3:
                raise RuntimeError("unexpected disk error mid-probe")
            return _cp(["t"], f"1.{calls[0]}.0\n")

        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.ai_tool_versions.safe_subprocess",
            side_effect=side_effect,
        ):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_tool_versions"):
                result = src.run_with_safety()
        assert len(result) == 4
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        assert any("t2" in r.message or "disk error" in r.message for r in caplog.records)

    def test_known_tools_registry_shape(self) -> None:
        """`KNOWN_TOOLS` is a list of dicts; each has name + argv + version_regex.
        No `shell=True` hints; no non-CLI strategies (Info.plist / npm DEFERRED)."""
        assert isinstance(KNOWN_TOOLS, list)
        assert len(KNOWN_TOOLS) >= 1
        for entry in KNOWN_TOOLS:
            assert "name" in entry and isinstance(entry["name"], str)
            assert "argv" in entry and isinstance(entry["argv"], list)
            assert all(isinstance(a, str) for a in entry["argv"])
            assert "version_regex" in entry
            # No non-CLI strategy hints
            assert "info_plist" not in entry
            assert "npm_pkg" not in entry
            # No shell-related hints
            assert not any("shell" in a.lower() for a in entry["argv"])

    @pytest.mark.skipif(
        shutil.which("claude") is None and shutil.which("gh") is None and shutil.which("ollama") is None,
        reason="no probeable AI CLI tools on this machine",
    )
    def test_real_tool_empirical(self) -> None:
        """**Empirical baseline (CLAUDE.md §9).** Real CLI probes on this machine
        return ≥1 Asset with non-None semver version."""
        import re

        src = AIToolVersionsSource()  # uses real KNOWN_TOOLS
        result = src.run_with_safety()
        assert len(result) >= 1
        for a in result:
            assert a.version is not None
            assert re.match(r"^\d+\.\d+\.\d+", a.version), f"{a.name}: version {a.version!r} not semver"
