"""Per-source ontology mapping — spec §5.5 simple maps.

Phase A: ``~/Documents/vigil-notes/v022/phase-2/phase-a-investigation.md``.

Each merged discovery source has a corresponding mapper that
converts an :class:`Asset` into a ``frozenset[OntologyCategory]``.
The :func:`map_asset` dispatcher routes by ``asset.source``.

**Q5 structural-completeness contract (2026-06-06).** Every
registered :class:`DiscoverySource` MUST appear in :data:`_REGISTRY`,
but the mapper MAY return ``frozenset()`` for identity-only sources
(ollama-models, ai-tool-versions, ai-apps-info-plist). The
``scripts/check_ontology_mapping_completeness.py`` CI gate is
structural ("a mapper exists"), not functional ("the mapper
produces tags"). Q1 ratification confirms a zero-tag asset lands
at INFO band, which is the correct conservative result for these
identity-only sources today; richer tags emerge in Phase 3+ as
permission/CVE/activity signals attach.

**Q4 split (2026-06-06).** The MCP **scored** multi-signal mapper
(directive §7.3.2) is DEFERRED to P2.1. This module ships only the
simple keyword map on command/args + secrets-presence-from-env
signals.

**Derived-tag prohibition.** Per-source mappers MUST NOT emit
``OntologyCategory.DATA_EXFILTRATION_CAPABLE`` directly — that tag
is computed in :mod:`derived` (P2.2) from the base tag set. The
P2.0 mapper-contract tests pin this property across every mapper.
"""

from __future__ import annotations

from collections.abc import Callable

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory

# ---------------------------------------------------------------------------
# Identity-only sources — empty result is the structurally-correct answer
# ---------------------------------------------------------------------------


def map_ollama_model(asset: Asset) -> frozenset[OntologyCategory]:
    """Ollama models are identity-only — local LLM weights.

    Returns empty. Risk emerges from CVE feeds (Phase 4) and runtime
    activity correlation (Phase 4 P4.3), not from native permissions.
    """
    del asset
    return frozenset()


def map_ai_tool_version(asset: Asset) -> frozenset[OntologyCategory]:
    """CLI tools (``claude``, ``cursor``, etc.) are identity-only.

    The actual permissions are declared by extensions / MCP servers /
    integrations attached to the tool, not the tool binary itself.
    """
    del asset
    return frozenset()


def map_ai_app_info_plist(asset: Asset) -> frozenset[OntologyCategory]:
    """macOS ``.app`` bundles via Info.plist — identity-only at this tier.

    ``LSEnvironment`` + ``CFBundleURLTypes`` + UTI handler analysis is
    Phase 3 expansion.
    """
    del asset
    return frozenset()


# ---------------------------------------------------------------------------
# Skill sources — code_execution by design
# ---------------------------------------------------------------------------


_SKILL_TAGS: frozenset[OntologyCategory] = frozenset({OntologyCategory.CODE_EXECUTION})


def map_claude_code_skill(asset: Asset) -> frozenset[OntologyCategory]:
    """Claude Code skills execute markdown-defined prompts in Claude's
    process context. The asset class IS ``code_execution`` by design."""
    del asset
    return _SKILL_TAGS


def map_openclaw_skill(asset: Asset) -> frozenset[OntologyCategory]:
    """OpenClaw skills are the same protocol shape as Claude Code skills."""
    del asset
    return _SKILL_TAGS


# ---------------------------------------------------------------------------
# MCP simple keyword map (P2.1 layers the scored multi-signal version)
# ---------------------------------------------------------------------------


_SECRETS_KEY_SUFFIXES: tuple[str, ...] = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")
"""Suffix half of the helpers :data:`TOKEN_VAR_NAMES` vocabulary. The
AUTH_ arm of that regex is checked separately as a substring (not
prefix) match — see :data:`_AUTH_SUBSTRING`. Single source of truth
for secret-key-name detection lives in helpers; this set is a small
duplicate to avoid the mapping module importing the helpers redaction
infrastructure."""


_AUTH_SUBSTRING: str = "AUTH_"
"""Substring marker matching the helpers regex ``r".*AUTH_.*"`` arm.
Anywhere in the key name, NOT just at position 0 — ``X_AUTH_HEADER``
matches the helpers regex and must match here too."""


_MCP_COMMAND_KEYWORDS: dict[OntologyCategory, tuple[str, ...]] = {
    OntologyCategory.FILE_SYSTEM_READ: ("server-filesystem", "fs-mcp", "filesystem-server"),
    OntologyCategory.FILE_SYSTEM_WRITE: ("server-filesystem", "fs-mcp", "filesystem-server"),
    OntologyCategory.SHELL_EXECUTE: ("server-shell", "shell-mcp", "bash-mcp", "server-bash"),
    OntologyCategory.NETWORK_UNRESTRICTED: (
        "server-fetch",
        "http-mcp",
        "server-github",
        "server-puppeteer",
        "server-brave-search",
    ),
}
"""Conservative substring map on lowercased ``command + args``. Hand-curated
from the official Anthropic MCP server catalog. The scored multi-signal
version in P2.1 reads server-published tool definitions (richer signal,
but requires the MCP protocol handshake; outside P1 scope).

Mis-tuning here under-tags assets (silently lower risk score), so the
list is intentionally narrow — false negatives are preferable to
false positives that erode operator trust in the score."""


def map_mcp_server_simple(asset: Asset) -> frozenset[OntologyCategory]:
    """Spec §5.5 simple MCP map. Three signal sources:

    1. **Universal:** every MCP server gets ``inter_tool_communication``
       (the MCP protocol is itself this category by definition).
    2. **env:** any key matching the ``_TOKEN/_KEY/_SECRET/_PASSWORD/
       AUTH_*`` suffix pattern → ``secrets_access`` (the value is
       post-redaction; we tag on key-name presence only).
    3. **command + args substring:** known well-known MCP server
       packages tag ``file_system_*``, ``shell_execute``, or
       ``network_unrestricted`` per :data:`_MCP_COMMAND_KEYWORDS`.

    Defensive against malformed ``current_state``: missing fields
    default to empty (the universal ``inter_tool_communication`` tag
    still applies, which is the honest minimum for an MCP asset).
    """
    tags: set[OntologyCategory] = {OntologyCategory.INTER_TOOL_COMMUNICATION}

    # env → secrets_access (post-redaction key-name presence)
    env = asset.current_state.get("env") or {}
    if isinstance(env, dict):
        for key in env:
            upper_key = str(key).upper()
            if _AUTH_SUBSTRING in upper_key or any(upper_key.endswith(s) for s in _SECRETS_KEY_SUFFIXES):
                tags.add(OntologyCategory.SECRETS_ACCESS)
                break

    # command + args → known-package substring map
    command = asset.current_state.get("command") or ""
    args = asset.current_state.get("args") or []
    if isinstance(args, list):
        args_str = " ".join(str(a) for a in args)
    else:
        args_str = ""
    cmd_blob = f"{command} {args_str}".lower()
    for category, keywords in _MCP_COMMAND_KEYWORDS.items():
        if any(kw in cmd_blob for kw in keywords):
            tags.add(category)

    return frozenset(tags)


# ---------------------------------------------------------------------------
# Registry + dispatcher
# ---------------------------------------------------------------------------


_REGISTRY: dict[str, Callable[[Asset], frozenset[OntologyCategory]]] = {
    "ollama-models": map_ollama_model,
    "ai-tool-versions": map_ai_tool_version,
    "ai-apps-info-plist": map_ai_app_info_plist,
    "claude-code-skills": map_claude_code_skill,
    "openclaw-skills": map_openclaw_skill,
    "mcp-servers": map_mcp_server_simple,
}
"""Per-source mapping registry. Adding a new source REQUIRES adding
an entry here — the structural completeness CI gate enforces this."""


REGISTERED_SOURCES: frozenset[str] = frozenset(_REGISTRY)
"""Public view of registered source names. Tests + the CI gate
script consume this."""


def get_mapper(source_name: str) -> Callable[[Asset], frozenset[OntologyCategory]] | None:
    """Return the mapping function for ``source_name``, or ``None`` when
    the source is not registered."""
    return _REGISTRY.get(source_name)


def map_asset(asset: Asset) -> frozenset[OntologyCategory]:
    """Dispatch by ``asset.source``. Returns ``frozenset()`` for sources
    without a registered mapper (fail-closed default; the CI gate is
    the durable defense against forgotten registrations).
    """
    mapper = _REGISTRY.get(asset.source)
    if mapper is None:
        return frozenset()
    return mapper(asset)


__all__ = [
    "REGISTERED_SOURCES",
    "get_mapper",
    "map_ai_app_info_plist",
    "map_ai_tool_version",
    "map_asset",
    "map_claude_code_skill",
    "map_mcp_server_simple",
    "map_ollama_model",
    "map_openclaw_skill",
]
