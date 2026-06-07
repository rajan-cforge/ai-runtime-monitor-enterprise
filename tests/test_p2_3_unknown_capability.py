"""P2.3 — Unknown-capability signature + floor.

**Per spec §6.8 (Q1, verdict P2.3.a1) with SIGNATURE FIX:**

The unknown-capability floor lifts an UNRECOGNIZED MCP server (one
whose package signature the P2.1 scored mapper failed to identify)
from the LOW/INFO floor to the BOTTOM OF MEDIUM (score 40), with
``unknown_capability_floor=40.0`` surfaced in the breakdown so the
P7.9 popover renders "Vigil does not recognize this package; v0.3
introspection resolves."

**The signature must use SET DIFFERENCE, not tag count.** The
Phase A investigation's proposed ``len(tags) == 1 AND ITC in tags``
was buggy: a credential-bearing unrecognized MCP gets
``{INTER_TOOL_COMMUNICATION, SECRETS_ACCESS}`` (2 tags), would
have failed the singleton check, and would have escaped the floor
to LOW. That's the exfil shape escaping precisely BY HAVING the
credential — backwards.

Correct signature (set difference):
``(ontology_tags - {INTER_TOOL_COMMUNICATION, SECRETS_ACCESS}) == frozenset()``
fires when NO command/args-derived capability tag landed.
``INTER_TOOL_COMMUNICATION`` is universal-for-MCP;
``SECRETS_ACCESS`` is env-key-name-derived (not command-derived);
neither closes the introspection gap.

Note for P2.4: an unknown-capability asset that ALSO has
``secrets_access`` is the canonical exfil shape and is a candidate
for a stronger rule modifier than the bare unknown floor (memory
``project_exfil_capable_needs_more_than_plus_one.md``).
"""

from __future__ import annotations

import time

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.risk.unknown import (
    UNKNOWN_CAPABILITY_FLOOR,
    is_unknown_capability_mcp,
)


def _mcp_asset(*, name: str = "test", current_state: dict | None = None) -> Asset:
    return Asset(
        id=f"mcp-{name}",
        type="mcp_server",
        parent_asset_id=None,
        name=name,
        version=None,
        install_path="/tmp/x.json",
        source="mcp-servers",
        current_state=current_state or {},
        discovered_at=time.time(),
    )


def _non_mcp_asset(*, source: str = "claude-code-skills") -> Asset:
    return Asset(
        id="x",
        type="ai_tool",
        parent_asset_id=None,
        name="x",
        version=None,
        install_path=None,
        source=source,
        current_state={},
        discovered_at=time.time(),
    )


class TestFloorConstant:
    def test_floor_is_forty(self) -> None:
        """Per spec §6.8 (Q1, verdict P2.3.a1): floor at 40 (bottom of MEDIUM).
        NOT 39 (top of LOW); NOT 41+ (mid-MEDIUM)."""
        assert UNKNOWN_CAPABILITY_FLOOR == 40.0


class TestSignature_BareSingleton:
    """Baseline case: MCP server with ONLY `inter_tool_communication`
    tag. No command-derived capabilities, no secrets. Floor fires."""

    def test_bare_singleton_mcp_triggers_floor(self) -> None:
        asset = _mcp_asset(current_state={"command": "node", "args": []})
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION})
        assert is_unknown_capability_mcp(asset, tags) is True


class TestSignature_ExfilShapeGotcha:
    """**Rajan 2026-06-07 catch.** A credential-bearing unrecognized
    MCP gets `{INTER_TOOL_COMMUNICATION, SECRETS_ACCESS}` — 2 tags.
    With the buggy `len(tags) == 1` signature, this would have FAILED
    the singleton check, escaped the floor, and landed at LOW (~6).
    The exfil shape escaping by having the credential. The set-
    difference signature catches it correctly."""

    def test_singleton_plus_secrets_access_STILL_triggers_floor(self) -> None:
        """The critical regression pin. Credential-bearing unrecognized
        MCP MUST fire the floor — this is the exfil shape."""
        asset = _mcp_asset(
            current_state={
                "command": "node",
                "args": ["/opt/custom/server.js"],
                "env": {"GITHUB_TOKEN": "[REDACTED]"},
            }
        )
        # P2.1 produces INTER_TOOL_COMMUNICATION + SECRETS_ACCESS for this
        # config (env key has _TOKEN suffix; command not in keyword map).
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION, OntologyCategory.SECRETS_ACCESS})
        assert is_unknown_capability_mcp(asset, tags) is True, (
            "REGRESSION: credential-bearing unrecognized MCP (exfil shape) "
            "escaped the unknown-capability floor — the bug Rajan caught "
            "on 2026-06-07 reading P2.3 Phase A."
        )


class TestSignature_RecognizedCommandDoesNotTrigger:
    """If ANY command/args-derived capability tag landed (file_system_*,
    shell_execute, network_unrestricted, etc.), the floor MUST NOT fire —
    the asset has been recognized."""

    def test_filesystem_server_does_not_trigger_floor(self) -> None:
        asset = _mcp_asset(
            current_state={"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]}
        )
        tags = frozenset(
            {
                OntologyCategory.INTER_TOOL_COMMUNICATION,
                OntologyCategory.FILE_SYSTEM_READ,
                OntologyCategory.FILE_SYSTEM_WRITE,
            }
        )
        assert is_unknown_capability_mcp(asset, tags) is False

    def test_github_server_does_not_trigger_floor(self) -> None:
        asset = _mcp_asset(current_state={"command": "npx", "args": ["@modelcontextprotocol/server-github"]})
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION, OntologyCategory.NETWORK_UNRESTRICTED})
        assert is_unknown_capability_mcp(asset, tags) is False

    def test_recognized_plus_secrets_does_not_trigger_floor(self) -> None:
        """Recognized server WITH credentials — the credential is
        complementary information, not the only signal. Floor does NOT fire."""
        asset = _mcp_asset(
            current_state={
                "command": "npx",
                "args": ["@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "[REDACTED]"},
            }
        )
        tags = frozenset(
            {
                OntologyCategory.INTER_TOOL_COMMUNICATION,
                OntologyCategory.NETWORK_UNRESTRICTED,
                OntologyCategory.SECRETS_ACCESS,
            }
        )
        assert is_unknown_capability_mcp(asset, tags) is False


class TestSignature_NonMcpSourcesDoNotTrigger:
    """The unknown-capability floor is MCP-specific. Other sources have
    their own honest zero-tag interpretation (Q1: identity-only sources
    legitimately return frozenset() → INFO band per spec §6.5)."""

    def test_zero_tag_skill_does_not_trigger_floor(self) -> None:
        asset = _non_mcp_asset(source="claude-code-skills")
        tags: frozenset[OntologyCategory] = frozenset()
        assert is_unknown_capability_mcp(asset, tags) is False

    def test_zero_tag_ollama_does_not_trigger_floor(self) -> None:
        asset = _non_mcp_asset(source="ollama-models")
        tags: frozenset[OntologyCategory] = frozenset()
        assert is_unknown_capability_mcp(asset, tags) is False

    def test_zero_tag_ai_app_does_not_trigger_floor(self) -> None:
        asset = _non_mcp_asset(source="ai-apps-info-plist")
        tags: frozenset[OntologyCategory] = frozenset()
        assert is_unknown_capability_mcp(asset, tags) is False


class TestSignature_EmptyTagsMcpEdgeCase:
    """Defensive edge: an MCP asset that somehow has ZERO tags (not even
    the universal `inter_tool_communication`). This is a P2.1 invariant
    violation but the signature should handle it gracefully — the asset
    qualifies as unknown-capability (no command-derived signal)."""

    def test_zero_tag_mcp_triggers_floor(self) -> None:
        """Defense in depth: if `inter_tool_communication` is somehow
        absent from an MCP asset, the floor STILL fires — empty set
        also satisfies `(tags - {ITC, SA}) == empty`."""
        asset = _mcp_asset(current_state={"command": "node", "args": []})
        tags: frozenset[OntologyCategory] = frozenset()
        assert is_unknown_capability_mcp(asset, tags) is True
