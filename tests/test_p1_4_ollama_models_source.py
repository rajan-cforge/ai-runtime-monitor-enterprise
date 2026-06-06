"""P1.4-minimal — `OllamaModelsSource` tests.

C2 pure-enumeration source. Per the ratified Phase B test list at
`~/Documents/vigil-notes/v022/phase-1/p1.4/phase-b-test-list-minimal.md`.

9 tests covering happy path, empty, not-installed, timeout, non-zero
exit, per-item isolation, tag parsing (with/without `:`), and the
empirical real-machine check.
"""

from __future__ import annotations

import shutil
import subprocess
from unittest import mock

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.discovery.sources.ollama_models import (
    OllamaModelsSource,
)

# Rajan's machine empirical baseline (per Phase A §5.A)
_REAL_OLLAMA_LIST_STDOUT = (
    "NAME                       ID              SIZE      MODIFIED      \n"
    "llama3.3:70b               a6eb4748fd29    42 GB     5 months ago     \n"
    "llama3.2:latest            a80c4f17acd5    2.0 GB    10 months ago    \n"
    "nomic-embed-text:latest    0a109f422b47    274 MB    10 months ago    \n"
    "llama3:latest              365c0bd3c000    4.7 GB    22 months ago    \n"
)


def _mock_subprocess_returning(stdout: str, returncode: int = 0):
    """Build a mock that replaces `safe_subprocess` and returns a fake CompletedProcess."""
    cp = subprocess.CompletedProcess(args=["ollama", "list"], returncode=returncode, stdout=stdout, stderr="")
    return mock.patch(
        "claude_monitoring.attack_surface.discovery.sources.ollama_models.safe_subprocess",
        return_value=cp,
    )


def _mock_subprocess_raising(exc: BaseException):
    return mock.patch(
        "claude_monitoring.attack_surface.discovery.sources.ollama_models.safe_subprocess",
        side_effect=exc,
    )


class TestOllamaModelsSource:
    def test_happy_path_four_rows_yields_four_assets(self) -> None:
        """Rajan's empirical 4 models on the real machine → 4 assets."""
        src = OllamaModelsSource()
        with _mock_subprocess_returning(_REAL_OLLAMA_LIST_STDOUT):
            result = src.run_with_safety()
        assert len(result) == 4
        names = {a.name for a in result}
        assert names == {"llama3.3:70b", "llama3.2:latest", "nomic-embed-text:latest", "llama3:latest"}
        # Cross-cutting contract assertions (light tier — embedded)
        assert src.name() == "ollama-models"
        assert src.requires_auth() is False
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        # Every asset has source + type set per spec
        for a in result:
            assert a.source == "ollama-models"
            assert a.type == "ai_tool"

    def test_empty_header_only_yields_empty_list(self, caplog) -> None:
        """Header-only stdout (no models pulled) → []; no WARNING; SUCCESS."""
        src = OllamaModelsSource()
        with _mock_subprocess_returning("NAME    ID    SIZE    MODIFIED\n"):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ollama_models"):
                result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        assert caplog.records == []

    def test_ollama_not_installed_silent_empty(self, caplog) -> None:
        """`FileNotFoundError` (binary absent) → [] silently; no WARNING; SUCCESS."""
        src = OllamaModelsSource()
        with _mock_subprocess_raising(FileNotFoundError("ollama not on PATH")):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ollama_models"):
                result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        # No WARNING — tool-not-installed is the silent normal flow.
        assert not any(r.name == "ai-runtime-monitor.attack_surface.discovery.ollama_models" for r in caplog.records)

    def test_subprocess_timeout_warns_and_empties(self, caplog) -> None:
        """`TimeoutExpired` → [] + WARNING; outcome=TIMEOUT."""
        src = OllamaModelsSource()
        with _mock_subprocess_raising(subprocess.TimeoutExpired(["ollama", "list"], 30.0)):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ollama_models"):
                result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.TIMEOUT
        assert any("timed out" in r.message.lower() or "timeout" in r.message.lower() for r in caplog.records)

    def test_subprocess_non_zero_exit_warns_and_empties(self, caplog) -> None:
        """Non-zero exit → [] + WARNING with exit code; outcome=ERROR."""
        src = OllamaModelsSource()
        with _mock_subprocess_returning("ollama daemon not running\n", returncode=1):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ollama_models"):
                result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.ERROR
        assert any("exit" in r.message.lower() for r in caplog.records)

    def test_per_item_isolation_one_bad_row_among_four(self, caplog) -> None:
        """**Per-item isolation contract pin.** 4 rows; 1 malformed → 3 assets +
        1 WARNING. One bad row does NOT poison the batch."""
        stdout = (
            "NAME    ID    SIZE    MODIFIED\n"
            "llama3.3:70b    a1    42 GB    5 months ago\n"
            "MALFORMED_ROW_NO_TABS\n"  # bad row
            "llama3.2:latest    a2    2.0 GB    10 months ago\n"
            "nomic-embed-text:latest    a3    274 MB    10 months ago\n"
        )
        src = OllamaModelsSource()
        with _mock_subprocess_returning(stdout):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ollama_models"):
                result = src.run_with_safety()
        assert len(result) == 3
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        warns = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warns) >= 1

    def test_tag_parsing_extracts_version_from_colon_form(self) -> None:
        """`name:tag` → name has tag preserved; version is the tag."""
        stdout = (
            "NAME    ID    SIZE    MODIFIED\n"
            "llama3.3:70b    a1    42 GB    5 months ago\n"
            "llama3.2:latest    a2    2.0 GB    10 months ago\n"
        )
        src = OllamaModelsSource()
        with _mock_subprocess_returning(stdout):
            result = src.run_with_safety()
        by_name = {a.name: a for a in result}
        assert by_name["llama3.3:70b"].version == "70b"
        assert by_name["llama3.2:latest"].version == "latest"

    def test_tagless_row_version_is_none(self) -> None:
        """Row without `:` → version is None (spec §7.1: never fabricate)."""
        stdout = "NAME    ID    SIZE    MODIFIED\nraw_model_no_tag    a1    100 MB    5 months ago\n"
        src = OllamaModelsSource()
        with _mock_subprocess_returning(stdout):
            result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "raw_model_no_tag"
        assert result[0].version is None

    @pytest.mark.skipif(shutil.which("ollama") is None, reason="ollama not installed")
    def test_real_ollama_empirical(self) -> None:
        """**Empirical baseline (CLAUDE.md §9).** Real `ollama list` on this
        machine returns ≥1 model; each has a non-empty name; `:latest`
        tags yield version=='latest'."""
        src = OllamaModelsSource()
        result = src.run_with_safety()
        assert len(result) >= 1
        for a in result:
            assert a.name
            assert a.source == "ollama-models"
            if ":" in a.name:
                tag = a.name.split(":", 1)[1]
                assert a.version == tag
