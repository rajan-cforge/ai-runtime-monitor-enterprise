"""Score composition with reputation — option B (Rajan ratification item 2).

Composition (locked):

.. code-block::

    final = clamp[0, 100](base + best_rule_modifier + best_reputation_modifier)
    final = max(UNKNOWN_CAPABILITY_FLOOR, final)  # if applicable

Two independent layers, each picks its own max-wins winner, the two
layers ADD. The floor (spec §6.9) re-asserts AFTER composition.

**This contract is copy-forward** — P4.1 (CVE) and any future scoring
layer must inherit the same shape: per-layer max-wins, layers add,
floor re-assert last.

Hard requirement #2: the reputation layer's ``reason`` (rate_limited /
budget_exceeded / lookup_failed / dormant) is preserved as one entry
in ``RiskScoreResult.applied_reputation`` so the popover renders
distinctly from "checked clean." Silence is never all-clear.
"""

from __future__ import annotations

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.reputation.dispatcher import (
    ReputationDispatcher,
    reputation_modifier_for,
)
from claude_monitoring.attack_surface.reputation.types import ReputationResult
from claude_monitoring.attack_surface.risk.bands import score_to_band
from claude_monitoring.attack_surface.risk.rules import Rule, apply_curated_rules
from claude_monitoring.attack_surface.risk.scoring import RiskScoreResult, compute_risk_score
from claude_monitoring.attack_surface.risk.unknown import (
    UNKNOWN_CAPABILITY_FLOOR,
    is_unknown_capability_mcp,
)


def score_asset_with_rules_and_reputation(
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
    rules: list[Rule],
    dispatcher: ReputationDispatcher,
    *,
    cves: list[dict] | None = None,
    runtime_activity: dict | None = None,
    integration_sensitivity_score: float = 0.0,
) -> RiskScoreResult:
    """The P2.6 composition contract. Option B (Rajan ratification 2026-06-08).

    Pipeline:

    1. ``base = compute_risk_score(...)`` — the 4-factor formula.
    2. ``max_rule_mod, applied_rules = apply_curated_rules(...)`` — rules
       max-wins layer.
    3. ``rep_result = dispatcher.lookup(asset)`` — single reputation
       signal (at most one per asset.source).
    4. ``rep_mod = reputation_modifier_for(rep_result)`` — 0 for
       present True / unavailable / dormant; only ``present is False``
       fires the table value.
    5. ``candidate = base.final_score + max_rule_mod + rep_mod``.
    6. ``final = min(100, max(0, candidate))`` — crash-guard.
    7. If unknown-cap MCP: ``final = max(UNKNOWN_CAPABILITY_FLOOR, final)``.
    8. ``applied_reputation`` always carries the reputation entry when
       ``rep_result is not None`` — INCLUDING unavailable cases — so
       the popover renders the reason. Empty list only if the asset
       doesn't participate in reputation at all.
    """
    base = compute_risk_score(
        asset,
        ontology_tags=ontology_tags,
        cves=cves,
        runtime_activity=runtime_activity,
        integration_sensitivity_score=integration_sensitivity_score,
    )
    max_rule_mod, applied_rules = apply_curated_rules(asset, ontology_tags, rules)
    rep_result = dispatcher.lookup(asset)
    rep_mod = reputation_modifier_for(rep_result)

    no_modifier_applied = max_rule_mod == 0 and rep_mod == 0
    no_attribution = not applied_rules and rep_result is None
    if no_modifier_applied and no_attribution:
        return base

    candidate = base.final_score + max_rule_mod + rep_mod
    final_clamped = min(100.0, max(0.0, candidate))
    if is_unknown_capability_mcp(asset, ontology_tags):
        final_clamped = max(UNKNOWN_CAPABILITY_FLOOR, final_clamped)
    final_score = round(final_clamped)

    base.final_score = final_score
    base.band = score_to_band(final_score)
    base.applied_rules = applied_rules
    base.applied_reputation = (
        [_reputation_to_dict(rep_result, rep_mod)] if rep_result is not None else []
    )
    return base


def _reputation_to_dict(result: ReputationResult, modifier_applied: int) -> dict:
    """Serialize a ``ReputationResult`` for the popover (P7.9).

    Hard requirement #2: ``reason`` is preserved so unavailable cases
    render distinctly. Schema:

    .. code-block::

        {
          "signal": "npm_low_downloads" | "pip_low_downloads" | ...,
          "modifier_applied": 0 | 10 | 15 | 20,
          "present": true | false | null,
          "downloads": int | null,
          "reason": null | "rate_limited" | "budget_exceeded" | "lookup_failed" | "dormant"
        }
    """
    return {
        "signal": result.signal.value,
        "modifier_applied": modifier_applied,
        "present": result.present,
        "downloads": result.downloads,
        "reason": result.reason.value if result.reason is not None else None,
    }


__all__ = ["score_asset_with_rules_and_reputation"]
