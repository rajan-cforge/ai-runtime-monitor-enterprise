"""The `Asset` dataclass — the unit of discovery.

Spec source: ``~/Documents/vigil-notes/v022-attack-surface-feature-spec-v1-LOCKED.md`` §7.1
Architect-pass ratification: ``~/Documents/vigil-notes/v022/phase-1/p1.1/architect-pass.md``

An ``Asset`` is what a :class:`DiscoverySource` produces. The orchestrator
(P1.3) reads ``Asset`` instances from sources, runs ontology mapping
(Phase 2), correlates with CVE data (Phase 4), and persists into the
``assets`` table (P0.2 schema).

Contract — locked at P1.1:

1. ``current_state`` is a required ``dict`` (no default). Empty dict is
   permitted (some discovery types may produce an asset without inspectable
   state) but ``None`` is not. JSON-serializable arbitrary nested
   structures are supported. Persistence (P1.3) will ``json.dumps`` on
   write; ``json.loads`` on read.

2. ``source`` is a required non-empty ``str`` (no default). At the
   application boundary this is enforced by ``__post_init__``; at the DB
   boundary the persistence layer (P1.3) enforces non-empty before INSERT
   to defend against drift 1 (the ``assets.source`` column is nullable in
   P0.2 schema; future tightening to ``NOT NULL`` does not enforce
   non-empty, so this dataclass guard is permanent).

3. ``is_vigil_component`` defaults to ``False``. Set ``True`` when the
   asset is a Vigil-internal component (e.g., the Vigil daemon itself,
   the Chrome extension, the dashboard); these are de-prioritized in
   risk scoring and hidden in the default UI view.

4. Persistence-layer drift handling (locked in P1.1 architect-pass §3,
   implemented in P1.3):
   - Drift 2: insert-time values lock — first insert sets
     ``first_seen = last_seen = last_scanned = scan_time``. Re-observation
     preserves ``first_seen`` (via upsert ``ON CONFLICT``); updates only
     ``last_seen`` and ``last_scanned``.
   - Drift 4: ``bool ↔ INTEGER 0/1`` adapter applied at write/read time.

5. The four orchestrator-owned columns (``ontology_tags``, ``risk_score``,
   ``risk_band``, ``risk_factors``) are never populated by sources — they
   are filled in by Phase 2 (ontology engine + risk scoring).

Type annotations use ``str | None`` (PEP 604, modernized from spec §7.1's
``Optional[str]``) to match the codebase ruff convention (UP045). Semantically
identical; ``from __future__ import annotations`` keeps the declarations
string-evaluated regardless.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Asset:
    """A discovered asset (AI tool, extension, MCP server, integration, dependency).

    Field order matches spec §7.1 verbatim. Fields without defaults must
    be supplied explicitly by the caller; the four ``str | None`` fields
    have no implicit ``None`` default — the discovery source must pass
    ``None`` explicitly (or a real value), forcing the source author to
    decide rather than silently accepting missing data.
    """

    id: str
    """Stable hash of ``(type, install_path, name)``. Per-install salt
    keeps the hash deterministic but non-correlatable across installs."""

    type: str
    """One of ``'ai_tool'``, ``'extension'``, ``'mcp_server'``,
    ``'integration'``, ``'dependency'``."""

    parent_asset_id: str | None
    """For hierarchical relationships (e.g., an extension belongs to a
    browser tool). ``None`` at the root of a tool tree."""

    name: str
    """Human-readable name (e.g., ``'Claude Desktop'``, ``'gh CLI'``)."""

    version: str | None
    """Version string as the source observed it. ``None`` if unresolvable
    (e.g., git-pinned package, file:// install). Sources must NOT
    fabricate ``"unknown"`` strings — pass ``None`` to signal "the source
    couldn't determine."""

    install_path: str | None
    """Filesystem path where the asset is installed. ``None`` for assets
    that aren't filesystem-localized (e.g., cloud integrations)."""

    source: str
    """Which :class:`DiscoverySource` produced this asset. Must be
    non-empty after strip — empty source is a discovery-source bug.
    Mirrors the source's ``name()`` output."""

    current_state: dict
    """JSON-serializable snapshot of the asset's current state:
    permissions, scope, native config excerpt. Empty dict allowed.
    ``None`` rejected. Persistence ``json.dumps`` on write."""

    discovered_at: float
    """Unix-epoch timestamp (``time.time()`` float) when this
    ``DiscoverySource`` produced the asset. NOT the first time the asset
    was ever seen — that's ``first_seen`` in the DB row, populated by the
    orchestrator from ``discovered_at`` on insert and preserved on
    re-observation."""

    is_vigil_component: bool = False
    """Set ``True`` if this asset is part of Vigil itself (daemon,
    extension, dashboard). Used for de-prioritizing in risk scoring and
    hiding from the default UI view."""

    def __post_init__(self) -> None:
        # Enforce non-empty source at the application boundary.
        # The DB-boundary enforcement lands in P1.3 (drift 1 disposition).
        if not self.source or not self.source.strip():
            raise ValueError(
                "Asset.source must be a non-empty string identifying the DiscoverySource that produced this asset"
            )
        # Enforce current_state ≠ None at the application boundary.
        # Without this guard, None propagates silently to the P1.3 persistence
        # adapter and crashes inside json.dumps far from the construction
        # site. Empty dict {} is the correct "no inspectable state" signal.
        if self.current_state is None:
            raise ValueError("Asset.current_state must be a dict (empty dict {} allowed); None is not permitted")
