"""P3.6 — Homebrew AI tools discovery.

Pins the discovery contract: invokes ``brew info --json=v2 --installed``
against the system Homebrew, filters the result for AI-related formulae
and casks via a keyword match against name / full_name / desc.

Tests follow the P3.1 / P3.2 / P3.3 / P3.4 / P3.5 precedent. Helper
tests proactively cover defensive branches (empty result + malformed
entries) to avoid the second-cycle coverage-ratchet fixup that bit
P3.3 and P3.5.

See ``~/Documents/vigil-notes/v022/phase-3/p3.6-phase-a-investigation.md``
for the full investigation that scoped the source.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools import (
    HomebrewAiToolsSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_brew_bin(tmp_path: Path, name: str = "brew") -> Path:
    """Create a synthetic brew binary placeholder."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    brew = bin_dir / name
    brew.write_text("#!/bin/sh\n")
    brew.chmod(0o755)
    return brew


def _formula(
    name: str,
    *,
    desc: str = "Some library",
    version: str = "1.0.0",
    homepage: str | None = None,
    tap: str | None = None,
    deprecated: bool = False,
    dependencies: list[str] | None = None,
) -> dict:
    return {
        "name": name,
        "full_name": tap + "/" + name if tap else name,
        "desc": desc,
        "homepage": homepage or f"https://example.com/{name}",
        "tap": tap or "homebrew/core",
        "deprecated": deprecated,
        "dependencies": dependencies or [],
        "versions": {"stable": version},
        "installed": [{"version": version, "cellar": f"/opt/homebrew/Cellar/{name}"}],
    }


def _cask(
    token: str,
    *,
    desc: str = "Some app",
    version: str = "1.0.0",
    homepage: str | None = None,
    tap: str | None = None,
    deprecated: bool = False,
) -> dict:
    return {
        "token": token,
        "name": [token.capitalize()],
        "desc": desc,
        "homepage": homepage or f"https://example.com/{token}",
        "version": version,
        "tap": tap or "homebrew/cask",
        "deprecated": deprecated,
    }


def _src(
    brew_candidates: list[Path] | None = None,
    ai_keywords: frozenset[str] | None = None,
) -> HomebrewAiToolsSource:
    return HomebrewAiToolsSource(brew_candidates=brew_candidates, ai_keywords=ai_keywords)


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(HomebrewAiToolsSource, DiscoverySource)

    def test_name_is_homebrew_ai_tools(self) -> None:
        assert HomebrewAiToolsSource().name() == "homebrew-ai-tools"

    def test_does_not_require_auth(self) -> None:
        assert HomebrewAiToolsSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        from claude_monitoring.attack_surface.ontology.mapping import REGISTERED_SOURCES

        assert "homebrew-ai-tools" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. Formulae filtering
# ---------------------------------------------------------------------------


class TestFormulaeFiltering:
    def test_single_ai_formula_yields_asset(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("pytorch", desc="Tensors and Dynamic neural networks")],
                "casks": [],
            },
        ):
            assets = _src(brew_candidates=[brew]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.type == "homebrew_ai_tool"
        assert a.source == "homebrew-ai-tools"
        assert a.name == "pytorch"
        assert a.current_state["item_type"] == "formula"
        assert a.current_state["match_reason"]["keyword"] == "pytorch"

    def test_non_ai_formula_filtered_out(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("abseil", desc="C++ Common Libraries")],
                "casks": [],
            },
        ):
            assets = _src(brew_candidates=[brew]).discover()
        assert assets == []

    def test_match_reason_captures_keyword_and_field(self, tmp_path: Path) -> None:
        """Pin the match_reason structure: {keyword, field}."""
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("text-utils", desc="Wraps the HuggingFace API")],
                "casks": [],
            },
        ):
            a = _src(brew_candidates=[brew]).discover()[0]
        assert a.current_state["match_reason"]["keyword"] == "huggingface"
        assert a.current_state["match_reason"]["field"] == "desc"

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("PyTorch", desc="PyTorch tensors")],
                "casks": [],
            },
        ):
            a = _src(brew_candidates=[brew]).discover()[0]
        assert a.name == "PyTorch"  # display preserves casing
        assert a.current_state["name_normalized"] == "pytorch"

    def test_multiple_ai_formulae_each_emit(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [
                    _formula("pytorch"),
                    _formula("openai-whisper"),
                    _formula("onnx"),
                    _formula("abseil", desc="just a library"),  # non-AI
                ],
                "casks": [],
            },
        ):
            names = {a.name for a in _src(brew_candidates=[brew]).discover()}
        assert names == {"pytorch", "openai-whisper", "onnx"}

    def test_custom_ai_keywords_override(self, tmp_path: Path) -> None:
        """Constructor accepts an explicit ai_keywords frozenset; tests
        rely on that for fixtures."""
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("custom-tool", desc="just a thing")],
                "casks": [],
            },
        ):
            assets = _src(
                brew_candidates=[brew],
                ai_keywords=frozenset({"custom-tool"}),
            ).discover()
        assert len(assets) == 1


# ---------------------------------------------------------------------------
# 3. Casks filtering
# ---------------------------------------------------------------------------


class TestCasksFiltering:
    def test_ai_cask_yields_asset(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [],
                "casks": [_cask("ollama", desc="Run LLMs locally")],
            },
        ):
            assets = _src(brew_candidates=[brew]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.current_state["item_type"] == "cask"
        assert a.name == "ollama"

    def test_non_ai_cask_filtered_out(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [],
                "casks": [_cask("firefox", desc="Web browser")],
            },
        ):
            assets = _src(brew_candidates=[brew]).discover()
        assert assets == []

    def test_cask_uses_token_as_identity(self, tmp_path: Path) -> None:
        """Casks have `token` (identity) vs `name` (display list).
        Source uses token for identity."""
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [],
                "casks": [_cask("ollama-server", desc="Ollama server bundle")],
            },
        ):
            a = _src(brew_candidates=[brew]).discover()[0]
        assert a.name == "ollama-server"
        assert a.current_state["name_normalized"] == "ollama-server"


# ---------------------------------------------------------------------------
# 4. Field captures
# ---------------------------------------------------------------------------


class TestFieldCaptures:
    def test_description_truncated_to_500_chars(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [
                    _formula("pytorch", desc="x" * 2000),
                ],
                "casks": [],
            },
        ):
            a = _src(brew_candidates=[brew]).discover()[0]
        assert a.current_state["desc"] is not None
        assert len(a.current_state["desc"]) <= 500

    def test_homepage_tap_deprecated_captured(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [
                    _formula(
                        "pytorch",
                        homepage="https://pytorch.org",
                        tap="homebrew/core",
                        deprecated=True,
                    )
                ],
                "casks": [],
            },
        ):
            a = _src(brew_candidates=[brew]).discover()[0]
        assert a.current_state["homepage"] == "https://pytorch.org"
        assert a.current_state["tap"] == "homebrew/core"
        assert a.current_state["deprecated"] is True

    def test_dependencies_captured_for_formula(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("pytorch", dependencies=["numpy", "protobuf"])],
                "casks": [],
            },
        ):
            a = _src(brew_candidates=[brew]).discover()[0]
        assert a.current_state["dependencies"] == ["numpy", "protobuf"]


# ---------------------------------------------------------------------------
# 5. Per-item isolation
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_subprocess_timeout_yields_no_assets(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            side_effect=subprocess.TimeoutExpired(cmd=["brew"], timeout=60),
        ):
            assert _src(brew_candidates=[brew]).discover() == []

    def test_one_malformed_formula_skipped_others_emit(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [
                    _formula("pytorch"),
                    "this is not a dict",
                    {"no_name_field": True},
                    _formula("onnx"),
                ],
                "casks": [],
            },
        ):
            names = {a.name for a in _src(brew_candidates=[brew]).discover()}
        assert names == {"pytorch", "onnx"}

    def test_absent_brew_binary_yields_no_assets(self, tmp_path: Path) -> None:
        absent = tmp_path / "no-brew"
        assert _src(brew_candidates=[absent]).discover() == []

    def test_malformed_cask_skipped_others_emit(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [],
                "casks": [
                    _cask("ollama"),
                    {"no_token_field": True},
                    _cask("llama-gui", desc="Llama frontend"),
                ],
            },
        ):
            names = {a.name for a in _src(brew_candidates=[brew]).discover()}
        assert names == {"ollama", "llama-gui"}


# ---------------------------------------------------------------------------
# 6. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_no_brew_candidates_returns_empty(self) -> None:
        assert _src(brew_candidates=[]).discover() == []

    def test_no_ai_relevant_items_returns_empty(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("abseil"), _formula("zlib")],
                "casks": [_cask("firefox")],
            },
        ):
            assert _src(brew_candidates=[brew]).discover() == []


# ---------------------------------------------------------------------------
# 7. Asset.id stability
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        payload = {"formulae": [_formula("pytorch")], "casks": []}
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value=payload,
        ):
            a1 = _src(brew_candidates=[brew]).discover()[0]
            a2 = _src(brew_candidates=[brew]).discover()[0]
        assert a1.id == a2.id
        assert a1.id.startswith("brew-ai-")

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={"formulae": [_formula("pytorch")], "casks": []},
        ):
            expected = _src(brew_candidates=[brew]).discover()[0].id

        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from unittest.mock import patch
from claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools import HomebrewAiToolsSource
with patch(
    "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
    return_value={{"formulae": [{{
        "name": "pytorch", "full_name": "pytorch", "desc": "Some library",
        "homepage": "https://example.com/pytorch", "tap": "homebrew/core",
        "deprecated": False, "dependencies": [],
        "versions": {{"stable": "1.0.0"}},
        "installed": [{{"version": "1.0.0", "cellar": "/opt/homebrew/Cellar/pytorch"}}],
    }}], "casks": []}},
):
    src = HomebrewAiToolsSource(brew_candidates=[Path({str(brew)!r})])
    print(src.discover()[0].id)
"""
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = "12345"
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == expected

    def test_version_NOT_in_digest_so_upgrade_upserts(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={"formulae": [_formula("pytorch", version="2.0.0")], "casks": []},
        ):
            a_v1 = _src(brew_candidates=[brew]).discover()[0]
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={"formulae": [_formula("pytorch", version="2.5.0")], "casks": []},
        ):
            a_v2 = _src(brew_candidates=[brew]).discover()[0]
        assert a_v1.id == a_v2.id
        assert a_v1.version != a_v2.version

    def test_case_insensitive_normalization_in_digest(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={"formulae": [_formula("PyTorch")], "casks": []},
        ):
            a_mixed = _src(brew_candidates=[brew]).discover()[0]
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={"formulae": [_formula("pytorch")], "casks": []},
        ):
            a_lower = _src(brew_candidates=[brew]).discover()[0]
        assert a_mixed.id == a_lower.id


# ---------------------------------------------------------------------------
# 8. Binary-trust boundary
# ---------------------------------------------------------------------------


class TestBinaryTrustBoundary:
    def test_default_brew_candidates_only_under_ratified_prefixes(self) -> None:
        from claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools import (
            _default_brew_candidates,
        )

        home = str(Path.home())
        for candidate in _default_brew_candidates():
            s = str(candidate)
            assert s.startswith("/opt/homebrew") or s.startswith("/usr/local") or s.startswith(home), (
                f"brew candidate {s} not under a ratified prefix"
            )


# ---------------------------------------------------------------------------
# 9. Empirical gate
# ---------------------------------------------------------------------------


class TestEmpirical:
    @pytest.mark.skipif(
        not Path("/opt/homebrew/bin/brew").exists() and not Path("/usr/local/bin/brew").exists(),
        reason="no brew on this machine",
    )
    def test_empirical_real_brew_walk(self) -> None:
        """Real `brew info --json=v2 --installed` invocation. On a typical
        AI dev machine, expect at least one match (pytorch, onnx, etc.)."""
        assets = HomebrewAiToolsSource().discover()
        assert isinstance(assets, list)
        if assets:
            a = assets[0]
            assert a.source == "homebrew-ai-tools"
            assert a.id.startswith("brew-ai-")
            assert a.current_state["item_type"] in {"formula", "cask"}


# ---------------------------------------------------------------------------
# 10. Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        from claude_monitoring.attack_surface.ontology import mapping

        assert "homebrew-ai-tools" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import (
            map_homebrew_ai_tool,
        )

        asset = Asset(
            id="brew-ai-test",
            type="homebrew_ai_tool",
            parent_asset_id=None,
            name="pytorch",
            version="2.5.0",
            install_path="/opt/homebrew/Cellar/pytorch",
            source="homebrew-ai-tools",
            current_state={"item_type": "formula", "name_normalized": "pytorch"},
            discovered_at=time.time(),
        )
        assert isinstance(map_homebrew_ai_tool(asset), frozenset)


# ---------------------------------------------------------------------------
# 11. brew_info_json helper (PROACTIVE defensive-branch coverage)
# ---------------------------------------------------------------------------


class TestBrewInfoJsonHelper:
    """Pins the new helpers.brew_info_json contract. Defensive-branch
    coverage written BEFORE first push to avoid the second-cycle
    coverage-ratchet fixup that bit P3.3 and P3.5."""

    def test_helper_is_importable(self) -> None:
        from claude_monitoring.attack_surface.discovery.helpers import brew_info_json

        assert callable(brew_info_json)

    def test_helper_uses_argv_list_not_shell(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        captured: list[list[str]] = []

        class R:
            returncode = 0
            stdout = '{"formulae": [], "casks": []}'
            stderr = ""

        def fake_run(argv, **kw):
            captured.append(argv)
            assert kw.get("shell") is False
            return R()

        with patch.object(helpers.subprocess, "run", side_effect=fake_run):
            result = helpers.brew_info_json(Path("/opt/homebrew/bin/brew"))
        assert captured
        assert captured[0][0] == "/opt/homebrew/bin/brew"
        assert captured[0][1:4] == ["info", "--json=v2", "--installed"]
        assert result == {"formulae": [], "casks": []}

    def test_helper_raises_on_nonzero_returncode(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 1
            stdout = ""
            stderr = "brew: command not found"

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(RuntimeError):
            helpers.brew_info_json(Path("/opt/homebrew/bin/brew"))

    def test_helper_raises_on_malformed_json(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = "{not json"
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(json.JSONDecodeError):
            helpers.brew_info_json(Path("/opt/homebrew/bin/brew"))

    def test_helper_raises_on_non_object_top_level(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = "[1, 2, 3]"
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(TypeError):
            helpers.brew_info_json(Path("/opt/homebrew/bin/brew"))

    def test_helper_returns_empty_shape_when_nothing_installed(self) -> None:
        """Defensive branch: brew on a fresh install returns
        ``{"formulae": [], "casks": []}``; the helper must return that
        verbatim and not raise."""
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = '{"formulae": [], "casks": []}'
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()):
            result = helpers.brew_info_json(Path("/opt/homebrew/bin/brew"))
        assert result == {"formulae": [], "casks": []}


# ---------------------------------------------------------------------------
# 12. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    def test_outcome_success_after_empty_run(self) -> None:
        src = _src(brew_candidates=[])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        brew = _make_brew_bin(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools.brew_info_json",
            return_value={
                "formulae": [_formula("pytorch"), "garbage"],
                "casks": [],
            },
        ):
            src = _src(brew_candidates=[brew])
            src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
