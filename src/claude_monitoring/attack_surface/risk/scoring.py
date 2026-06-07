"""Risk scoring engine — 4-factor formula per spec §6.1 + directive §7.4.

**The formula:**

    final_risk = min(100,
        max_cve_severity         * 0.35   # CVSS max × 10, scaled 0-100
      + permission_breadth       * 0.30   # len(tags) / 10 * 100
      + integration_sensitivity  * 0.20   # table-driven per spec §6.1
      + activity_recency         * 0.15   # 0/30/60/80/100 by age bucket
    )

**Phase 2 input availability (memory ``project_phase2_demo_positioning.md``):**

- ``max_cve_severity = 0`` until P4.1 (CVE feed) ships.
- ``integration_sensitivity = 0`` until P3.7 (Claude Desktop OAuth
  integrations) lands.
- ``activity_recency = 0`` until P4.3 (runtime correlation) ships.

Only ``permission_breadth`` actively contributes in Phase 2; max
achievable formula score is **30 (LOW band)**. The unknown-capability
floor (40 → MEDIUM) is the genuinely meaningful band signal until the
other factors wire in.

**Ratifications applied (verdict P2.3.a1; Q1 in spec §6.8):**

- **Q1 (spec §6.8):** unknown-capability floor at 40 → MEDIUM; signature
  uses set difference (NOT tag count) so credential-bearing unrecognized
  MCPs do not escape via ``secrets_access``.
- **Q2 (verdict P2.3.a1):** :class:`RiskBand` is a ``(str, enum.Enum)``
  mixin.
- **Q3 (verdict P2.3.a1):** weights snapshotted onto each
  :class:`RiskScoreResult` at compute time from
  :data:`weights.FACTOR_WEIGHTS` (single source of truth + audit-stable
  persistence).
- **Q4 (verdict P2.3.a1):** orphan ``DATA_EXFILTRATION_CAPABLE`` tag
  raises via explicit ``if orphan: raise`` (NOT ``assert`` — strippable
  under ``python -O``; memory
  ``feedback_assert_strippable_use_if_raise.md``). Strict at this unit;
  the orchestrator wraps per-asset scoring with try/except so one orphan
  quarantines that asset and the scan continues.

**Out of scope (deferred):**

- Rule modifiers → P2.4 (curated rules engine)
- Curated rule set → P2.5
- Source reputation factor → P2.6 (egress-design PR, NOT folded here)
- CVE feed input → P4.1
- Runtime correlation input → P4.3
- UI breakdown popover → P7.9
"""

from __future__ import annotations

from dataclasses import dataclass, field

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.risk.bands import RiskBand, score_to_band
from claude_monitoring.attack_surface.risk.unknown import (
    UNKNOWN_CAPABILITY_FLOOR,
    is_unknown_capability_mcp,
)
from claude_monitoring.attack_surface.risk.weights import FACTOR_WEIGHTS


@dataclass(frozen=True)
class RiskFactors:
    """The four base-formula factor inputs (all 0-100 scaled)."""

    max_cve_severity: float
    permission_breadth: float
    integration_sensitivity: float
    activity_recency: float


@dataclass
class RiskScoreResult:
    """The full output of :func:`compute_risk_score`.

    Carries everything P7.9's breakdown popover needs to render the
    asset's score with no external state lookups:

    - ``final_score``: the integer band-determining score, post-clamp
      and post-floor.
    - ``band``: the :class:`RiskBand` from :func:`score_to_band`.
    - ``factors``: the four raw factor inputs.
    - ``contributions``: per-factor weighted contributions + any
      floor adjustment. Named keys the popover reads.
    - ``weights``: snapshot of :data:`weights.FACTOR_WEIGHTS` at
      compute time (Q3). NOT the live module constant — an independent
      copy so mutating the result does not affect future scoring or
      persisted historical results.
    """

    final_score: int
    band: RiskBand
    factors: RiskFactors
    contributions: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)


def _compute_permission_breadth(ontology_tags: frozenset[OntologyCategory]) -> float:
    """Spec §6.1: `len(tags) / 10 * 100`, clamped at 100 (10 categories).

    Spec §6.5: the derived ``data_exfiltration_capable`` tag IS counted
    in breadth — that property falls out of using ``len()`` on the
    union-including-derived tag set the orchestrator passes in.
    """
    return min(100.0, (len(ontology_tags) / 10.0) * 100.0)


def _compute_max_cve_severity(cves: list[dict] | None) -> float:
    """Spec §6.1: highest CVSS v3 score × 10; 0 if no CVE data.

    In Phase 2 this is always 0 (P4.1 not shipped). Tests pin this.
    """
    if not cves:
        return 0.0
    highest = max((float(cve.get("cvss", 0)) for cve in cves), default=0.0)
    return min(100.0, highest * 10.0)


def _compute_activity_recency(runtime_activity: dict | None) -> float:
    """Spec §6.1: 100 / 80 / 60 / 30 / 0 by recency bucket. The actual
    bucketing is the orchestrator's job (it knows clock); this function
    accepts a pre-computed ``recency_score`` field for Phase 2 testing.

    In Phase 2 this is always 0 (P4.3 not shipped). The capability-
    ladder doc (memory ``project_v022_capability_ladder.md``) is
    explicit: "no idleness inference from empty runtime_activity" —
    that's the UI's job (P7.5), NOT the scorer's.
    """
    if not runtime_activity:
        return 0.0
    return float(runtime_activity.get("recency_score", 0))


def _check_orphan_derived_tag(ontology_tags: frozenset[OntologyCategory]) -> None:
    """Q4 per verdict P2.3.a1: if ``DATA_EXFILTRATION_CAPABLE``
    appears in ``ontology_tags`` without the spec §5.4 preconditions,
    raise loudly. Indicates an upstream invariant violation
    (``apply_derived`` bug, hand-constructed test fixture, etc.).

    Uses explicit ``if ... : raise``, NOT ``assert`` — the latter is
    stripped under ``python -O`` and a correctness invariant must not
    be removable by an optimization flag (memory
    ``feedback_assert_strippable_use_if_raise.md``).

    **Spec §5.4 source of truth lives in**
    :func:`ontology.derived.derive_data_exfiltration_capable`. This
    duplicate-encodes the predicate intentionally — the scoring module
    must not depend on the derivation module's predicate to validate
    its own input contract. If spec §5.4 evolves, BOTH sites update.
    """
    if OntologyCategory.DATA_EXFILTRATION_CAPABLE not in ontology_tags:
        return
    has_secret_source = (
        OntologyCategory.SECRETS_ACCESS in ontology_tags or OntologyCategory.FILE_SYSTEM_READ in ontology_tags
    )
    has_network_exit = (
        OntologyCategory.NETWORK_UNRESTRICTED in ontology_tags or OntologyCategory.NETWORK_SCOPED in ontology_tags
    )
    if not (has_secret_source and has_network_exit):
        raise ValueError(
            "data_exfiltration_capable tag present in ontology_tags but spec §5.4 "
            "preconditions not met — upstream invariant violated (apply_derived "
            "bug or orphan-tagged fixture). Tags: "
            f"{sorted(t.value for t in ontology_tags)}"
        )


def compute_risk_score(
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
    *,
    cves: list[dict] | None = None,
    runtime_activity: dict | None = None,
    integration_sensitivity_score: float = 0.0,
) -> RiskScoreResult:
    """Score an asset against the spec §6.1 4-factor formula.

    Args:
        asset: The :class:`Asset` being scored. ``asset.source`` is
            inspected for the unknown-capability path.
        ontology_tags: The asset's full ontology tag set after
            ``apply_derived`` has run (orchestrator passes the union).
        cves: Optional CVE rows (each with ``cvss`` field). Phase 2
            production always passes ``None`` or ``[]`` — P4.1 wires
            real input.
        runtime_activity: Optional runtime activity dict (with
            ``recency_score`` field). Phase 2 production passes
            ``None`` or ``{}`` — P4.3 wires real input.
        integration_sensitivity_score: Pre-computed integration
            sensitivity factor (0-100). Phase 2 production passes 0
            — P3.7 wires real input.

    Returns:
        A :class:`RiskScoreResult` carrying final score, band, raw
        factors, named contributions, and snapshot weights.

    Raises:
        ValueError: When ``DATA_EXFILTRATION_CAPABLE`` is in
            ``ontology_tags`` but the spec §5.4 preconditions are not
            met (Q4 strict guard; orchestrator catches per-asset).
    """
    _check_orphan_derived_tag(ontology_tags)

    factors = RiskFactors(
        max_cve_severity=_compute_max_cve_severity(cves),
        permission_breadth=_compute_permission_breadth(ontology_tags),
        integration_sensitivity=max(0.0, min(100.0, integration_sensitivity_score)),
        activity_recency=_compute_activity_recency(runtime_activity),
    )

    # Each factor × its weight = its contribution to the base risk.
    contributions: dict[str, float] = {
        "max_cve_severity": factors.max_cve_severity * FACTOR_WEIGHTS["max_cve_severity"],
        "permission_breadth": factors.permission_breadth * FACTOR_WEIGHTS["permission_breadth"],
        "integration_sensitivity": factors.integration_sensitivity * FACTOR_WEIGHTS["integration_sensitivity"],
        "activity_recency": factors.activity_recency * FACTOR_WEIGHTS["activity_recency"],
    }
    base_risk = sum(contributions.values())

    # Q1 unknown-capability floor: an unrecognized MCP gets lifted to
    # the bottom of MEDIUM. Surfaced as a named breakdown line so
    # P7.9 can render "Vigil does not recognize this package; v0.3
    # introspection resolves."
    #
    # NOTE for popover readers: ``contributions["unknown_capability_floor"]``
    # is a REPLACEMENT signal, not additive. When it appears,
    # ``sum(contributions.values()) != final_score`` — the floor
    # supersedes the base formula rather than summing with it. Read
    # ``final_score`` directly; use ``contributions`` for the
    # breakdown rendering, not as a partition.
    if is_unknown_capability_mcp(asset, ontology_tags):
        floor = UNKNOWN_CAPABILITY_FLOOR
        if floor > base_risk:
            base_risk = floor
            contributions["unknown_capability_floor"] = floor

    # Clamp at 100 per spec §6.1.
    final_clamped = min(100.0, base_risk)
    final_score = round(final_clamped)
    band = score_to_band(final_score)

    return RiskScoreResult(
        final_score=final_score,
        band=band,
        factors=factors,
        contributions=contributions,
        # Q3: SNAPSHOT the weights — independent copy (dict(...)), NOT
        # an alias to the live module constant. Mutating the result's
        # weights dict must not affect FACTOR_WEIGHTS.
        weights=dict(FACTOR_WEIGHTS),
    )


__all__ = [
    "RiskFactors",
    "RiskScoreResult",
    "compute_risk_score",
]
