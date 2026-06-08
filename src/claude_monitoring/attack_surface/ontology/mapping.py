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


def map_vscode_extension(asset: Asset) -> frozenset[OntologyCategory]:
    """P3.1 placeholder per Q5 ratification (2026-06-06): STRUCTURAL completeness
    only. P3.8 wires the real rules across all Phase 3 sources at once
    (e.g., ``contributes.debuggers`` → ``shell_execute``, ``extensionKind``
    ``["workspace"]`` → ``file_system_read`` + ``file_system_write``, ``main``
    non-null → ``code_execution``). Until then this mapper returns
    ``frozenset()`` and the asset lands at INFO band per spec §6.5 Q1.

    The mapper EXISTS so the P2.2-gate CI gate
    (``check_ontology_mapping_completeness``) passes — a registered
    DiscoverySource without a registry entry would fail the build."""
    del asset
    return frozenset()


# ---------------------------------------------------------------------------
# MCP — simple keyword map + P2.1 scored config-only multi-signal layer
# ---------------------------------------------------------------------------
#
# Ratification trail (Rajan 2026-06-07): P2.1 implements the directive
# §7.3.2 algorithm SHAPE — weighted signals + cumulative threshold — over
# the LOCAL CONFIG fields the P1.4 source captured (command, args, env),
# NOT the wire-published `tools[]` array the directive's original example
# consumed. The fragility §7.3.2 was meant to solve (naming-convention
# drift across MCP server packages) is only fully solved when wire
# introspection lands. That work is deferred to v0.3 issue #89, which
# carries the egress-and-execution design decision (spawning discovered
# possibly-hostile servers as subprocesses) on its own.
#
# Honest framing: this is a marginal upgrade over the simple map. The
# accumulator + threshold scaffold pays off downstream — P2.3's risk
# scoring + P2.4's rules engine compose over scored tags. The actual
# robustness §7.3.2 promised arrives with introspection in v0.3.


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
# P2.1 scored config-only multi-signal map
# ---------------------------------------------------------------------------


MCP_SCORED_THRESHOLD: float = 0.5
"""Inclusion threshold for the scored map (directive §7.3.2 magic number).

Surfaced as a module constant for two reasons:

1. Tunable in one place if empirical data later justifies adjustment.
2. Visible to operators reading the score breakdown — the threshold
   is part of the contract, not buried in a function literal.
"""


_HIGH_CONFIDENCE_WEIGHT: float = 0.7
"""Score contributed by an exact official-package keyword match. Matches
the directive §7.3.2 `name` signal weight — the strongest signal in the
original wire-input formulation."""


_LOW_CONFIDENCE_WEIGHT: float = 0.4
"""Score contributed by a loose substring keyword (vendor fork, internal
naming variant). Two loose hits in the same category accumulate to 0.8
> :data:`MCP_SCORED_THRESHOLD`, the property that distinguishes the
scored map from the binary simple map."""


_NAME_CHARS: frozenset[str] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")
"""Characters that constitute a package-name token. A keyword match is
only counted when both sides of the match are NOT in this set (i.e., the
match sits at a word boundary). Prevents substring-anywhere traps like
``server-shell-utilities`` falsely matching the ``server-shell`` keyword
(architect-pass H2, 2026-06-07)."""


def _keyword_at_boundary(blob: str, keyword: str) -> bool:
    """True iff ``keyword`` appears in ``blob`` at a word boundary on both
    sides (preceded and followed by either string-start/end OR a character
    outside :data:`_NAME_CHARS`).

    Real false-positive cases this catches (from architect-pass empirical
    probes):

    - ``server-shell-utilities`` — ``server-shell`` keyword would not match
      because the trailing ``-`` is a name char.
    - ``proxy-server-fetch-tests`` — ``server-fetch`` keyword would not
      match because the preceding ``-`` is a name char.
    - ``server-github-clone-mirror`` — same shape.

    True-positive cases still match:

    - ``/usr/local/bin/server-filesystem`` (preceded by ``/``, trailed by
      string-end).
    - ``npx @modelcontextprotocol/server-filesystem /tmp`` (preceded by
      ``/``, trailed by `` ``).
    """
    idx = 0
    klen = len(keyword)
    while True:
        pos = blob.find(keyword, idx)
        if pos == -1:
            return False
        left_ok = pos == 0 or blob[pos - 1] not in _NAME_CHARS
        end_pos = pos + klen
        right_ok = end_pos == len(blob) or blob[end_pos] not in _NAME_CHARS
        if left_ok and right_ok:
            return True
        idx = pos + 1


_MCP_SCORED_KEYWORDS: dict[OntologyCategory, dict[str, float]] = {
    OntologyCategory.FILE_SYSTEM_READ: {
        # High confidence — exact official package names
        "@modelcontextprotocol/server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        "server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        # Low confidence — loose substring patterns
        "mcp-fs": _LOW_CONFIDENCE_WEIGHT,
        "filesystem": _LOW_CONFIDENCE_WEIGHT,
    },
    OntologyCategory.FILE_SYSTEM_WRITE: {
        "@modelcontextprotocol/server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        "server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        "mcp-fs": _LOW_CONFIDENCE_WEIGHT,
        "filesystem": _LOW_CONFIDENCE_WEIGHT,
    },
    OntologyCategory.SHELL_EXECUTE: {
        "server-shell": _HIGH_CONFIDENCE_WEIGHT,
        "server-bash": _HIGH_CONFIDENCE_WEIGHT,
        "shell-mcp": _LOW_CONFIDENCE_WEIGHT,
        "bash-mcp": _LOW_CONFIDENCE_WEIGHT,
    },
    OntologyCategory.NETWORK_UNRESTRICTED: {
        "@modelcontextprotocol/server-fetch": _HIGH_CONFIDENCE_WEIGHT,
        "@modelcontextprotocol/server-github": _HIGH_CONFIDENCE_WEIGHT,
        "@modelcontextprotocol/server-puppeteer": _HIGH_CONFIDENCE_WEIGHT,
        "@modelcontextprotocol/server-brave-search": _HIGH_CONFIDENCE_WEIGHT,
        "server-fetch": _HIGH_CONFIDENCE_WEIGHT,
        "server-github": _HIGH_CONFIDENCE_WEIGHT,
        "server-puppeteer": _HIGH_CONFIDENCE_WEIGHT,
        "server-brave-search": _HIGH_CONFIDENCE_WEIGHT,
        "http-mcp": _LOW_CONFIDENCE_WEIGHT,
    },
}
"""Weighted keyword map. Each (category, keyword) pair contributes its
weight to the category's score when the keyword appears in lowercased
``command + args``. Per-category scores accumulate; tags clearing
:data:`MCP_SCORED_THRESHOLD` are emitted.

Mis-tuning here under-tags assets (silently lower risk score), so the
keyword list stays conservative — false negatives are preferable to
false positives that erode operator trust in the score. The high
weight (0.7) is reserved for exact official Anthropic catalog package
names; the low weight (0.4) for community fork patterns.
"""


def map_mcp_server_scored(asset: Asset) -> frozenset[OntologyCategory]:
    """Scored multi-signal MCP map — config-only (P2.1, Rajan 2026-06-07).

    Implements the directive §7.3.2 algorithm SHAPE (weighted signals,
    cumulative threshold) over the local config fields the P1.4 source
    captured (command, args, env). Does NOT read wire-published
    ``tools[]`` definitions — that requires spawning discovered servers
    as subprocesses, an egress-and-execution decision deferred to v0.3
    issue #89.

    Signal sources (config-only adaptation):

    1. **Baseline** (universal): every MCP server gets
       ``inter_tool_communication``. Identical to :func:`map_mcp_server_simple`.
    2. **Secrets**: env key matching the token-suffix vocabulary or
       containing ``AUTH_`` → ``secrets_access``. Identical to simple.
    3. **Scored command/args**: keywords accumulate weighted scores per
       category; categories clearing :data:`MCP_SCORED_THRESHOLD` are
       emitted. Strict upgrade over the simple binary substring path —
       a server with multiple loose indicators correctly clears the
       bar; a single weak signal correctly does not.

    Returns the union of all triggered tags.
    """
    tags: set[OntologyCategory] = {OntologyCategory.INTER_TOOL_COMMUNICATION}

    # env → secrets_access (identical to simple map; same vocabulary)
    env = asset.current_state.get("env") or {}
    if isinstance(env, dict):
        for key in env:
            upper_key = str(key).upper()
            if _AUTH_SUBSTRING in upper_key or any(upper_key.endswith(s) for s in _SECRETS_KEY_SUFFIXES):
                tags.add(OntologyCategory.SECRETS_ACCESS)
                break

    # Build the searchable blob
    command = asset.current_state.get("command") or ""
    args = asset.current_state.get("args") or []
    args_str = " ".join(str(a) for a in args) if isinstance(args, list) else ""
    cmd_blob = f"{command} {args_str}".lower()

    # Accumulate weighted scores per category. Keyword matches use a
    # word-boundary check (`_keyword_at_boundary`) to prevent substring
    # traps like `server-shell-utilities` matching `server-shell`.
    for category, weighted in _MCP_SCORED_KEYWORDS.items():
        score = sum(weight for kw, weight in weighted.items() if _keyword_at_boundary(cmd_blob, kw))
        # Strict greater per directive §7.3.2 "only include tags with
        # cumulative score >0.5". Exactly 0.5 does NOT emit.
        if score > MCP_SCORED_THRESHOLD:
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
    "mcp-servers": map_mcp_server_scored,
    "vscode-extensions": map_vscode_extension,
}
"""Per-source mapping registry. Adding a new source REQUIRES adding
an entry here — the structural completeness CI gate enforces this.

The ``mcp-servers`` entry routes to the P2.1 scored mapper. The simple
keyword map (:func:`map_mcp_server_simple`) is retained as the floor
the scored layer composes over and is still publicly exported for
direct callers + tests; the dispatcher uses the scored version."""


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
    "MCP_SCORED_THRESHOLD",
    "REGISTERED_SOURCES",
    "get_mapper",
    "map_ai_app_info_plist",
    "map_ai_tool_version",
    "map_asset",
    "map_claude_code_skill",
    "map_mcp_server_scored",
    "map_mcp_server_simple",
    "map_ollama_model",
    "map_openclaw_skill",
    "map_vscode_extension",
]
