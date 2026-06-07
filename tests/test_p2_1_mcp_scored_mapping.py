"""P2.1 — MCP scored multi-signal mapping (config-only).

**Honest scope (Rajan 2026-06-07 ratification).** This implements the
directive §7.3.2 algorithm SHAPE — weighted signals + cumulative
threshold — over the LOCAL CONFIG fields the P1.4 source captured
(command, args, env), NOT the wire-published `tools[]` array the
directive's original example consumed. The fragility §7.3.2 was
meant to solve (naming-convention drift across MCP server packages)
is only fully solved when wire introspection lands — deferred to
v0.3 issue #89.

These tests pin the scoring contract:

1. The threshold (0.5) is the inclusion cutoff. Signals at or below
   threshold do NOT contribute the tag.
2. High-confidence keywords (exact official-package match) score
   higher than low-confidence keywords (loose substring).
3. Multiple low-confidence hits in the same category can accumulate
   ABOVE threshold.
4. The simple `INTER_TOOL_COMMUNICATION` and `SECRETS_ACCESS` paths
   that already exist in `map_mcp_server_simple` still fire — the
   scored path is additive over the simple baseline, not a
   replacement.
"""

from __future__ import annotations

import time

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.ontology.mapping import (
    MCP_SCORED_THRESHOLD,
    map_mcp_server_scored,
)


def _mcp_asset(
    *,
    name: str = "test-server",
    command: str = "node",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> Asset:
    current_state: dict = {
        "scope": "global",
        "config_path": "/tmp/fake-config.json",
        "command": command,
        "args": args or [],
    }
    if env is not None:
        current_state["env"] = env
    return Asset(
        id=f"mcp-{name}",
        type="mcp_server",
        parent_asset_id=None,
        name=name,
        version=None,
        install_path="/tmp/fake-config.json",
        source="mcp-servers",
        current_state=current_state,
        discovered_at=time.time(),
    )


class TestScoredMappingThreshold:
    """The 0.5 threshold is the inclusion cutoff."""

    def test_threshold_constant_is_half(self) -> None:
        """The directive §7.3.2 magic number. Surfaced as a module constant
        so it's tunable in one place and visible to operators reading the
        score breakdown."""
        assert MCP_SCORED_THRESHOLD == 0.5

    def test_signal_below_threshold_does_not_emit_tag(self) -> None:
        """A single weak (0.4) substring hit does not score above 0.5 — the
        tag must NOT be emitted. This is the property that distinguishes
        the scored map from P2.0's binary one (which would have emitted)."""
        # `mcp-fs` is the weak keyword (0.4) for FILE_SYSTEM_READ
        asset = _mcp_asset(command="node", args=["./vendor/mcp-fs/index.js"])
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ not in tags

    def test_high_confidence_single_signal_emits_tag(self) -> None:
        """Exact official-package match (0.7 weight) clears the 0.5 threshold."""
        asset = _mcp_asset(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in tags
        assert OntologyCategory.FILE_SYSTEM_WRITE in tags

    def test_two_weak_signals_accumulate_above_threshold(self) -> None:
        """Two 0.4-weight hits in the same category sum to 0.8 > 0.5 —
        the tag is emitted. This is the actual upgrade over P2.0: a server
        with multiple LOW-CONFIDENCE keywords correctly clears the bar
        even when no single one is high-confidence enough alone.

        Note both hits must sit at word boundaries (H2 guard) — paths
        like `mcp-fs/v1/filesystem` qualify; `mcp-fs/filesystem-helper`
        does NOT (the `-helper` extends `filesystem`, so it's no longer
        the keyword)."""
        # Both `mcp-fs` and `filesystem` appear at clean boundaries
        # (preceded/followed by `/`); each contributes 0.4 → total 0.8.
        asset = _mcp_asset(command="node", args=["./mcp-fs/v1/filesystem"])
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in tags


class TestScoredMappingSignalSources:
    """Where the signals come from in current_state."""

    def test_command_substring_contributes(self) -> None:
        asset = _mcp_asset(command="/usr/local/bin/server-filesystem", args=[])
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in tags

    def test_args_substring_contributes(self) -> None:
        asset = _mcp_asset(command="npx", args=["@modelcontextprotocol/server-github"])
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED in tags


class TestScoredMappingBaselineTags:
    """Inherited from P2.0 simple map — additive."""

    def test_inter_tool_communication_universal(self) -> None:
        """Every MCP server is `inter_tool_communication` by definition,
        scored or not."""
        asset = _mcp_asset(command="node", args=["/opt/custom.js"])
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in tags

    def test_secrets_access_from_env_key_name(self) -> None:
        """env key with `_TOKEN/_KEY/_SECRET/_PASSWORD/AUTH_` → secrets_access.
        Same path as P2.0 simple map; the scored layer doesn't replace it."""
        asset = _mcp_asset(
            command="node",
            args=[],
            env={"GITHUB_TOKEN": "[REDACTED — token-shaped variable name]"},
        )
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.SECRETS_ACCESS in tags

    def test_auth_substring_anywhere_tags_secrets_access(self) -> None:
        """H1 regression contract from P2.0 — the AUTH_ substring path
        applies under the scored map too."""
        asset = _mcp_asset(
            command="node",
            args=[],
            env={"X_AUTH_HEADER": "[REDACTED]"},
        )
        tags = map_mcp_server_scored(asset)
        assert OntologyCategory.SECRETS_ACCESS in tags


class TestScoredMappingContract:
    """Cross-cutting contract every mapper inherits."""

    def test_return_type_is_frozenset(self) -> None:
        asset = _mcp_asset()
        result = map_mcp_server_scored(asset)
        assert isinstance(result, frozenset)

    def test_never_emits_derived_category(self) -> None:
        """`data_exfiltration_capable` is computed by P2.2, never emitted
        by per-source mappers."""
        asset = _mcp_asset(
            command="npx",
            args=["@modelcontextprotocol/server-filesystem", "/"],
            env={"API_KEY": "[REDACTED]"},
        )
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE not in result

    def test_defensive_missing_current_state_fields(self) -> None:
        """Empty current_state → only the universal INTER_TOOL_COMMUNICATION
        baseline tag, no crash."""
        asset = Asset(
            id="malformed",
            type="mcp_server",
            parent_asset_id=None,
            name="malformed",
            version=None,
            install_path=None,
            source="mcp-servers",
            current_state={},
            discovered_at=time.time(),
        )
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in result


class TestScoredMappingNoFalsePositives:
    """Conservative-bias property — false negatives preferred over false
    positives (the Phase 2 architect-pass principle cited by Rajan in the
    P2.0 review). A user-written custom MCP server with no recognizable
    package fingerprint should ONLY get the universal tag."""

    def test_unknown_custom_server_no_speculative_tags(self) -> None:
        asset = _mcp_asset(
            command="python",
            args=["/Users/x/projects/my-private-mcp/server.py"],
        )
        result = map_mcp_server_scored(asset)
        # Only the universal MCP tag — no speculative file/network/shell.
        assert result == frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION})

    def test_plain_word_path_does_not_accidentally_score(self) -> None:
        """A path component `serving-staff-notes` should NOT score for
        `server-` (the keyword is `server-filesystem`, not `server-`). Pin
        that the keyword list is specific enough to avoid this trap."""
        asset = _mcp_asset(command="node", args=["/opt/serving-staff-notes/index.js"])
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ not in result
        assert OntologyCategory.FILE_SYSTEM_WRITE not in result


class TestWordBoundaryGuard:
    """H2 regression pins (architect-pass 2026-06-07). Substring `in`
    matching across word boundaries would falsely tag unrelated paths.
    The boundary guard requires the keyword to sit between non-name
    characters."""

    def test_server_shell_substring_in_longer_path_does_not_fire(self) -> None:
        """`server-shell-utilities` is NOT `server-shell` — the trailing
        `-utilities` extends the name; SHELL_EXECUTE must NOT emit."""
        asset = _mcp_asset(
            command="python",
            args=["/Users/x/repos/server-shell-utilities/foo.py"],
        )
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.SHELL_EXECUTE not in result

    def test_server_fetch_substring_in_longer_path_does_not_fire(self) -> None:
        """`proxy-server-fetch-tests` is NOT `server-fetch` — both ends
        extended; NETWORK_UNRESTRICTED must NOT emit."""
        asset = _mcp_asset(
            command="node",
            args=["/Users/x/work/proxy-server-fetch-tests/main.js"],
        )
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_server_github_substring_in_longer_path_does_not_fire(self) -> None:
        """`server-github-clone-mirror` is NOT `server-github`."""
        asset = _mcp_asset(
            command="node",
            args=["/home/x/server-github-clone-mirror/run.js"],
        )
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_keyword_at_path_segment_still_fires(self) -> None:
        """The boundary guard must still ACCEPT legitimate references —
        the official package preceded by `/` and followed by string-end
        or whitespace."""
        asset = _mcp_asset(
            command="/usr/local/bin/server-filesystem",
            args=[],
        )
        result = map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in result


class TestThresholdBoundary:
    """H1 regression pin (architect-pass 2026-06-07). Directive §7.3.2
    says ">0.5" — strict greater. Exactly 0.5 does NOT emit. No keyword
    in the current map sums to exactly 0.5, so this test synthesizes one
    via monkeypatch so the strict-greater semantics are pinned even if
    weights later shift."""

    def test_exact_threshold_does_not_emit_tag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from claude_monitoring.attack_surface.ontology import mapping as mapping_mod

        # Replace the keyword map with one whose only entry sums to exactly
        # 0.5 — that's the boundary case. After the swap, a hit must NOT
        # emit the tag.
        synthetic = {
            OntologyCategory.FILE_SYSTEM_READ: {"synthetic-boundary-keyword": 0.5},
        }
        monkeypatch.setattr(mapping_mod, "_MCP_SCORED_KEYWORDS", synthetic)
        asset = _mcp_asset(command="node", args=["/opt/synthetic-boundary-keyword/x.js"])
        result = mapping_mod.map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ not in result

    def test_just_above_threshold_emits_tag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from claude_monitoring.attack_surface.ontology import mapping as mapping_mod

        synthetic = {
            OntologyCategory.FILE_SYSTEM_READ: {"synthetic-above-threshold-kw": 0.51},
        }
        monkeypatch.setattr(mapping_mod, "_MCP_SCORED_KEYWORDS", synthetic)
        asset = _mcp_asset(command="node", args=["/opt/synthetic-above-threshold-kw/x.js"])
        result = mapping_mod.map_mcp_server_scored(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in result


class TestMcpScoredVsSimpleParity:
    """For all the P2.0 simple-map test cases, the scored map produces
    at least the same tags. The scored map is strictly additive — it
    never DROPS a tag the simple map would have emitted."""

    @pytest.mark.parametrize(
        "command,args,expected_must_have",
        [
            # Filesystem server: both simple and scored emit READ + WRITE
            (
                "npx",
                ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                {OntologyCategory.FILE_SYSTEM_READ, OntologyCategory.FILE_SYSTEM_WRITE},
            ),
            # GitHub server: NETWORK_UNRESTRICTED in both
            (
                "npx",
                ["-y", "@modelcontextprotocol/server-github"],
                {OntologyCategory.NETWORK_UNRESTRICTED},
            ),
        ],
    )
    def test_scored_emits_at_least_simple_tags(
        self, command: str, args: list[str], expected_must_have: set[OntologyCategory]
    ) -> None:
        asset = _mcp_asset(command=command, args=args)
        result = map_mcp_server_scored(asset)
        assert expected_must_have.issubset(result)


class TestRegistryWiring:
    """The scored mapper replaces the simple one for the `mcp-servers`
    source. `map_asset(mcp_asset)` now routes through the scored path."""

    def test_dispatcher_routes_mcp_to_scored_mapper(self) -> None:
        from claude_monitoring.attack_surface.ontology.mapping import map_asset

        asset = _mcp_asset(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        result = map_asset(asset)
        # The high-confidence filesystem hits should land via the scored path.
        assert OntologyCategory.FILE_SYSTEM_READ in result
