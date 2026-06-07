"""Unknown-capability signature + floor.

**Q1 ratification (Rajan 2026-06-07).** An MCP server asset whose
package signature is not recognized by the P2.1 scored mapper gets
its score FLOORED at 40 → MEDIUM band. The intent: an unrecognized
MCP is NOT low-risk; it's an INSPECTION BLIND SPOT, and the honest
distinction is carried by:

1. The score floor → MEDIUM band sort key (NOT INFO / LOW)
2. The ``unknown_capability_floor`` line in the breakdown popover (P7.9)
3. The "Unknown capability" UI badge (P7.4 / P7.6 — separate PRs)

**The signature uses SET DIFFERENCE, not tag count.** Rajan caught
the Phase A's proposed ``len(tags) == 1 AND ITC in tags`` as buggy:
a credential-bearing unrecognized MCP gets two tags
(``INTER_TOOL_COMMUNICATION`` + ``SECRETS_ACCESS``), would have
failed the singleton check, and would have escaped the floor to
LOW — the exfil shape escaping precisely BY HAVING the credential.

Correct signature: trigger when ``ontology_tags`` contains NO
command-or-args-derived capability tag. The two "non-recognition"
tags are:

- ``INTER_TOOL_COMMUNICATION`` — universal-for-MCP (every MCP gets it)
- ``SECRETS_ACCESS`` — env-key-name-derived (NOT command-derived)

Neither closes the introspection blind spot, so the floor fires when
``(ontology_tags - {INTER_TOOL_COMMUNICATION, SECRETS_ACCESS})`` is
empty.

**Note for P2.4:** an unknown-capability asset that ALSO has
``secrets_access`` is the canonical exfil shape and is a candidate
for a stronger rule modifier than the bare unknown floor
(memory ``project_exfil_capable_needs_more_than_plus_one.md``).
"""

from __future__ import annotations

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory

UNKNOWN_CAPABILITY_FLOOR: float = 40.0
"""Score floor for unrecognized MCP servers — bottom of MEDIUM band
per Q1 ratification (Rajan 2026-06-07). Selected to:

- Sort above the LOW/INFO clutter that Phase 2 produces by default.
- Stay inside the spec §6.3 5-band model (no 6th UNKNOWN band).
- Carry the honest distinction via the UI badge + breakdown line."""


_NON_RECOGNITION_TAGS: frozenset[OntologyCategory] = frozenset(
    {OntologyCategory.INTER_TOOL_COMMUNICATION, OntologyCategory.SECRETS_ACCESS}
)
"""Tags that do NOT count as "Vigil recognized this asset's capabilities."

- ``INTER_TOOL_COMMUNICATION``: universal for MCP servers by definition.
- ``SECRETS_ACCESS``: env-key-name-derived (the P2.1 mapper tags this
  whenever an env key matches the token-suffix vocabulary), but env
  presence tells you the server HANDLES a credential, not what its
  command DOES.

Phase 3 extension: when Chrome extension / VSCode extension / etc.
sources land, this set may expand (e.g., a "host_permissions=*"
fallback that's similarly indicative of breadth without command
recognition). For now, MCP-only."""


_UNKNOWN_CAPABILITY_SOURCES: frozenset[str] = frozenset({"mcp-servers"})
"""Sources whose mappers have a recognition layer that can MISS (i.e.,
return only non-recognition tags). Extensible: Phase 3 sources can join
this set per source-by-source ratification.

Identity-only sources (ollama-models, ai-tool-versions,
ai-apps-info-plist) are NOT in this set — their mappers honestly return
``frozenset()`` for ALL assets per Q1 (zero-tag → INFO band). They're
not "unrecognized," they're "no permissions declared."

Skill sources (claude-code-skills, openclaw-skills) are NOT in this set
either — they always tag ``CODE_EXECUTION`` deterministically; there's
no recognition layer that can fail."""


def is_unknown_capability_mcp(
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
) -> bool:
    """True iff the asset qualifies for the unknown-capability floor.

    Args:
        asset: The asset being scored. ``asset.source`` is checked
            against the unknown-capable source allowlist.
        ontology_tags: The asset's full ontology tag set (after
            ``apply_derived``).

    Returns:
        ``True`` when the asset's source is on the unknown-capable
        list AND the tag set contains NO command/args-derived capability
        tag (set-difference signature). Empty tag set qualifies too —
        defense in depth against a missing ``INTER_TOOL_COMMUNICATION``
        invariant.
    """
    if asset.source not in _UNKNOWN_CAPABILITY_SOURCES:
        return False
    # Set-difference signature: if removing the non-recognition tags
    # leaves the set empty, no command-derived tag was present.
    recognized_tags = ontology_tags - _NON_RECOGNITION_TAGS
    return len(recognized_tags) == 0


__all__ = [
    "UNKNOWN_CAPABILITY_FLOOR",
    "is_unknown_capability_mcp",
]
