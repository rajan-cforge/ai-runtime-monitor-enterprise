"""P2.0 — Per-source ontology mapping.

Six mappers (one per merged discovery source) + a `map_asset` dispatcher.
Identity-only sources legitimately return `frozenset()` per the
Q5 structural-completeness ratification (2026-06-06): the mapper
MUST exist, but it MAY return empty. A zero-tag asset ends up at
INFO band per Q1, which is the correct conservative behavior.

The MCP **scored** multi-signal mapper (directive §7.3.2) is
explicitly DEFERRED to P2.1 per Q4. P2.0 ships a simple keyword
map on command/args + secrets-presence-from-env signals.
"""

from __future__ import annotations

import time

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.ontology.mapping import (
    REGISTERED_SOURCES,
    get_mapper,
    map_asset,
    map_mcp_server_simple,
)


def _asset(
    *,
    source: str,
    asset_type: str = "ai_tool",
    name: str = "test-asset",
    current_state: dict | None = None,
) -> Asset:
    return Asset(
        id=f"{source}-{name}",
        type=asset_type,
        parent_asset_id=None,
        name=name,
        version=None,
        install_path=None,
        source=source,
        current_state=current_state or {},
        discovered_at=time.time(),
    )


# ---------------------------------------------------------------------------
# Registry + dispatch
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_all_six_merged_sources_registered(self) -> None:
        """Q5 structural-completeness contract: every registered discovery
        source has a mapping function. P2.0 ships 6: ollama-models,
        ai-tool-versions, ai-apps-info-plist, claude-code-skills,
        openclaw-skills, mcp-servers."""
        expected = {
            "ollama-models",
            "ai-tool-versions",
            "ai-apps-info-plist",
            "claude-code-skills",
            "openclaw-skills",
            "mcp-servers",
        }
        assert expected == REGISTERED_SOURCES

    def test_get_mapper_returns_callable_for_known_source(self) -> None:
        mapper = get_mapper("ollama-models")
        assert callable(mapper)

    def test_get_mapper_returns_none_for_unknown_source(self) -> None:
        assert get_mapper("does-not-exist") is None


class TestMapAssetDispatcher:
    def test_dispatches_to_correct_mapper(self) -> None:
        asset = _asset(source="claude-code-skills", name="test-skill")
        result = map_asset(asset)
        assert OntologyCategory.CODE_EXECUTION in result

    def test_dispatches_to_mcp_mapper(self) -> None:
        """Pin the dispatcher → MCP mapper wiring (the only non-trivial
        mapper). Per architect-pass L2."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={"command": "node", "args": []},
        )
        result = map_asset(asset)
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in result

    def test_unknown_source_returns_empty_frozenset(self) -> None:
        """Fail-closed: an asset from a source without a registered mapper
        gets no tags. The completeness CI gate is the durable defense;
        runtime behavior is conservative."""
        asset = _asset(source="not-a-registered-source")
        result = map_asset(asset)
        assert result == frozenset()

    def test_return_type_is_frozenset(self) -> None:
        """Immutable so a downstream caller cannot mutate the mapper's
        output (which is sometimes a constant)."""
        asset = _asset(source="claude-code-skills")
        result = map_asset(asset)
        assert isinstance(result, frozenset)


# ---------------------------------------------------------------------------
# Identity-only sources (Q5: empty-result is the structural-correct answer)
# ---------------------------------------------------------------------------


class TestIdentityOnlySources:
    """Per Phase A §1: ollama-models / ai-tool-versions / ai-apps-info-plist
    contribute zero ontology tags by themselves. Risk emerges in Phase 3+
    when permissions / CVEs / runtime activity attach."""

    def test_ollama_model_yields_empty(self) -> None:
        asset = _asset(source="ollama-models", name="llama3.2:latest")
        result = map_asset(asset)
        assert result == frozenset()

    def test_ai_tool_version_yields_empty(self) -> None:
        asset = _asset(source="ai-tool-versions", name="claude")
        result = map_asset(asset)
        assert result == frozenset()

    def test_ai_app_info_plist_yields_empty(self) -> None:
        asset = _asset(source="ai-apps-info-plist", name="Claude")
        result = map_asset(asset)
        assert result == frozenset()


# ---------------------------------------------------------------------------
# Skill sources (Claude Code + OpenClaw) — code_execution by design
# ---------------------------------------------------------------------------


class TestSkillSources:
    """Skills are markdown-defined prompts executed in the host process's
    AI agent. The asset class IS code-exec by design."""

    def test_claude_code_skill_tagged_code_execution(self) -> None:
        asset = _asset(source="claude-code-skills", name="my-skill")
        result = map_asset(asset)
        assert result == frozenset({OntologyCategory.CODE_EXECUTION})

    def test_openclaw_skill_tagged_code_execution(self) -> None:
        asset = _asset(source="openclaw-skills", name="clawmemory")
        result = map_asset(asset)
        assert result == frozenset({OntologyCategory.CODE_EXECUTION})


# ---------------------------------------------------------------------------
# MCP simple keyword map (P2.1 will layer the scored multi-signal version)
# ---------------------------------------------------------------------------


class TestMcpServerSimpleMap:
    """Spec §5.5 simple map. Directive §7.3.2 SCORED version lands in P2.1."""

    def test_every_mcp_server_tagged_inter_tool_communication(self) -> None:
        """The MCP protocol IS inter-tool comm by definition. Per Phase A §1."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            name="generic-server",
            current_state={"command": "node", "args": ["/path/server.js"]},
        )
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in result

    def test_env_with_token_key_tags_secrets_access(self) -> None:
        """Post-redaction env still carries the KEY NAME — which is enough
        to know the server handles secrets. Value is REDACTED."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={
                "command": "node",
                "args": [],
                "env": {"TALOSAI_API_KEY": "[REDACTED — token-shaped variable name]"},
            },
        )
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.SECRETS_ACCESS in result

    def test_auth_substring_anywhere_tags_secrets_access(self) -> None:
        """H1 regression pin (architect-pass 2026-06-06): the helpers regex
        matches `AUTH_` ANYWHERE in the key name (e.g., `X_AUTH_HEADER`,
        `BEARER_AUTH_HEADER`). An earlier draft used `startswith("AUTH_")`
        which silently dropped these. Mapper and helpers vocabularies must
        not drift apart."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={
                "command": "node",
                "args": [],
                "env": {"X_AUTH_HEADER": "[REDACTED]"},
            },
        )
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.SECRETS_ACCESS in result

    def test_env_without_token_key_no_secrets_tag(self) -> None:
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={"command": "node", "args": [], "env": {"PORT": "8080"}},
        )
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.SECRETS_ACCESS not in result

    def test_filesystem_server_substring_tags_read_and_write(self) -> None:
        """Well-known `@modelcontextprotocol/server-filesystem` package."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            },
        )
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in result
        assert OntologyCategory.FILE_SYSTEM_WRITE in result

    def test_github_server_substring_tags_network_unrestricted(self) -> None:
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
            },
        )
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_unknown_mcp_server_only_baseline_tag(self) -> None:
        """Unrecognized command/args → only inter_tool_communication
        (the universal MCP tag); no speculative file/network tags."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={"command": "node", "args": ["/opt/custom/server.js"]},
        )
        result = map_mcp_server_simple(asset)
        assert result == frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION})

    def test_missing_current_state_fields_do_not_crash(self) -> None:
        """Defensive: command/args/env may be absent on a malformed asset."""
        asset = _asset(source="mcp-servers", asset_type="mcp_server", current_state={})
        # Should not raise; baseline tag still applies.
        result = map_mcp_server_simple(asset)
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in result


# ---------------------------------------------------------------------------
# Cross-cutting properties
# ---------------------------------------------------------------------------


class TestMapperReturnContract:
    """Every mapper returns a frozenset[OntologyCategory] — never None,
    never a regular set, never a list, never including DERIVED categories."""

    @pytest.mark.parametrize("source", sorted(REGISTERED_SOURCES))
    def test_every_mapper_returns_frozenset(self, source: str) -> None:
        asset = _asset(source=source, current_state={})
        result = map_asset(asset)
        assert isinstance(result, frozenset)

    @pytest.mark.parametrize("source", sorted(REGISTERED_SOURCES))
    def test_no_p2_0_mapper_emits_derived_category(self, source: str) -> None:
        """`data_exfiltration_capable` is DERIVED (computed by P2.2 from
        the base tag set). P2.0 mappers MUST NOT emit it directly."""
        asset = _asset(source=source, current_state={})
        result = map_asset(asset)
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE not in result
