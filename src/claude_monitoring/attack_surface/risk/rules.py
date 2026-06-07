"""Curated rules engine — spec §6.2.

Loads rules from ``config/risk-rules.yaml``, evaluates patterns against
an asset + ontology tags, applies a max-wins modifier per spec §6.2:

    final_risk = min(100, base_risk + max(rule_modifiers))

**Locked refs (CONTRACT §1):** spec §6.2 (schema + max-wins), §6.4
(breakdown popover contract), §6.6 (adversarial considerations);
directive §3 P2.4, §7.4 (modifier cap), §11.2 (schema gate), §16.5
(config file location).

**Ratifications (Phase A 2026-06-07 + Rajan ratification 2026-06-07
work-log/2026-06-07-P2.4-ratification.md):**

- **Composition (Phase A §2):** ship :func:`apply_curated_rules` as a
  downstream function (separate from :func:`compute_risk_score`).
  Keeps P2.3's contract pure.
- **Predicates live in Phase 2 (Q-A ratified):** :data:`LIVE_PREDICATES`
  = ``{has_tags, source_in, unknown_capability}``. Forward-compat
  predicates (``cve_severity``, ``integration_sensitivity``,
  ``package_in_malicious_list``) are documented in
  :data:`FORWARD_COMPAT_PREDICATES` with their wiring PR — but a
  rule using one is **gate-rejected, not shippable**. The prior
  silent ``_predicate_noop → False`` path was removed.
- **Whole-file fail-closed (Phase A §4):** unparseable file → empty
  rule list, base scorer stands, log CRITICAL.
- **Per-rule isolation (Phase A §5):** one bad rule does not zero
  out the rest; per-rule try/except.
- **Max-wins (spec §6.2):** ``max(rule_modifiers)`` not ``sum(...)``;
  one rule's modifier wins, never stacking. BOTH winning and
  suppressed rules surface in ``applied_rules`` for the popover.
- **Modifier range (spec §6.2 + directive §7.4):** ``[-10, +30]``.
  Out-of-range at load time → skip the rule + WARN.
- **Q-B floor re-assertion (spec §6.9):** in
  :func:`score_asset_with_rules`, ``final = min(100, max(0, base +
  max_modifier))``; then for unknown-capability MCPs,
  ``final = max(UNKNOWN_CAPABILITY_FLOOR, final)``. A negative
  modifier can never lower a score below an applicable floor. The
  ``max(0, …)`` crash-guard prevents low-base + negative-modifier
  from tripping the ``score_to_band`` ``[0, 100]`` invariant.

**Out of scope (deferred):**

- The curated rule set itself → P2.5 (with NIST CSF / MITRE
  ATT&CK citations).
- The exfil-capable ``unknown_capability AND has_tags:[secrets_access]``
  rule is **NEEDS-RAJAN per CONTRACT §7** (named product judgment);
  the engine supports the predicate, but the rule itself ships in
  P2.5 only after Rajan rules on it.
- Source reputation factor → P2.6 (its own egress-design PR,
  memory ``project_reputation_egress_not_a_rule.md``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.helpers import safe_yaml_load, validate_path
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.risk.bands import score_to_band
from claude_monitoring.attack_surface.risk.scoring import (
    RiskScoreResult,
    compute_risk_score,
)
from claude_monitoring.attack_surface.risk.unknown import (
    UNKNOWN_CAPABILITY_FLOOR,
    is_unknown_capability_mcp,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.risk.rules")


DEFAULT_RULES_PATH: Path = Path(__file__).resolve().parents[4] / "config" / "risk-rules.yaml"
"""Spec §16.5: shipped read-only ``config/risk-rules.yaml``. Admin
override at ``~/.vigil/risk-rules.local.yaml`` is judge-decidable
Phase A Q2 — both load via :func:`safe_yaml_load`."""


MODIFIER_MIN: int = -10
MODIFIER_MAX: int = 30
"""Spec §6.2: modifier range ``[-10, +30]``. Spec §6.2 explicit on the
lower bound; directive §7.4 silent on the lower bound. Spec wins per
CONTRACT §1."""


_REQUIRED_FIELDS: tuple[str, ...] = ("id", "pattern", "modifier", "explanation", "framework_ref")


LIVE_PREDICATES: frozenset[str] = frozenset({"has_tags", "source_in", "unknown_capability"})
"""Predicates actually dispatched in Phase 2. **A rule may only ship if every
predicate in its pattern is in this set.** Per Rajan ratification 2026-06-07
(work-log/2026-06-07-P2.4-ratification.md) Q-A: gate-reject any rule referencing
a predicate outside this set. Catastrophic case (`package_in_malicious_list`
inert so a known-malicious package scores clean) must be impossible to ship,
not merely logged."""


FORWARD_COMPAT_PREDICATES: dict[str, str] = {
    "cve_severity": "P4.1 (OSV.dev CVE feed)",
    "integration_sensitivity": "P3.7 (Claude Desktop OAuth integrations)",
    "package_in_malicious_list": "Phase 3 (when the list source lands)",
}
"""Predicates the spec mentions but Phase 2 cannot dispatch. Documented here so
the schema gate can produce a precise error ('predicate X is wired by PR Y;
cannot ship a rule using it yet'). NEVER added to `_PREDICATE_DISPATCH` —
adding them would silently lower the bar Rajan set in Q-A."""


_KNOWN_FRAMEWORKS: frozenset[str] = frozenset({"nist_csf", "cis_controls", "mitre_attack"})


@dataclass
class Rule:
    """A single curated risk rule per spec §6.2 schema."""

    id: str
    pattern: dict[str, Any]
    modifier: int
    explanation: str
    framework_ref: dict[str, str]


# ---------------------------------------------------------------------------
# Loader — safe_yaml_load + per-rule validation
# ---------------------------------------------------------------------------


def load_curated_rules(path: Path) -> list[Rule]:
    """Load + validate the rule set from ``path``.

    Fail-closed contract:

    - File missing / unreadable → return ``[]`` (base scorer stands).
    - YAML bomb / oversize / unparseable → CRITICAL log + return ``[]``.
    - Top-level not a list → CRITICAL log + return ``[]``.
    - Individual rule fails validation → WARNING log + skip + continue
      (other rules still load).

    Per Phase A §4 + memory ``project_v022_per_item_isolation.md``.
    """
    # Third structured-input parsing surface (after P1.4's SKILL.md +
    # MCP configs). Same safe-helpers contract: validate_path bounds
    # the file size before read (10 MiB cap), same posture as P1.4.
    try:
        validate_path(path, root=path.parent, check_size=True, max_size_mb=10.0)
    except FileNotFoundError:
        return []
    except (ValueError, OSError) as exc:
        logger.critical("risk-rules.yaml validate_path failed: %s; running with no curated rules", exc)
        return []
    try:
        raw = path.read_text(errors="replace")
    except OSError as exc:
        logger.critical("risk-rules.yaml read failed: %s; running with no curated rules", exc)
        return []

    try:
        payload = safe_yaml_load(raw)
    except Exception as exc:
        logger.critical(
            "risk-rules.yaml unparseable (%s); running with no curated rules until next reload",
            exc,
        )
        return []

    if not isinstance(payload, list):
        logger.critical(
            "risk-rules.yaml top-level is not a list (got %s); running with no curated rules",
            type(payload).__name__,
        )
        return []

    rules: list[Rule] = []
    for entry in payload:
        rule = _validate_rule(entry)
        if rule is not None:
            rules.append(rule)
    return rules


def _validate_rule(entry: Any) -> Rule | None:
    """Validate one rule entry. Returns the Rule on success; logs WARNING
    and returns None on any failure."""
    if not isinstance(entry, dict):
        logger.warning("skipping rule entry: not a dict (got %s)", type(entry).__name__)
        return None
    missing = [f for f in _REQUIRED_FIELDS if f not in entry]
    if missing:
        logger.warning("skipping rule %s: missing required fields %s", entry.get("id"), missing)
        return None
    rid = entry["id"]
    if not isinstance(rid, str) or not rid.strip():
        logger.warning("skipping rule: id must be a non-empty string")
        return None
    pattern = entry["pattern"]
    if not isinstance(pattern, dict) or not pattern:
        logger.warning("skipping rule %s: pattern must be a non-empty dict", rid)
        return None
    modifier = entry["modifier"]
    if not isinstance(modifier, int) or isinstance(modifier, bool):
        logger.warning("skipping rule %s: modifier must be int (got %s)", rid, type(modifier).__name__)
        return None
    if not (MODIFIER_MIN <= modifier <= MODIFIER_MAX):
        logger.warning(
            "skipping rule %s: modifier %d outside spec §6.2 range [%d, %d]",
            rid,
            modifier,
            MODIFIER_MIN,
            MODIFIER_MAX,
        )
        return None
    framework_ref = entry["framework_ref"]
    if not isinstance(framework_ref, dict) or not framework_ref:
        logger.warning("skipping rule %s: framework_ref must be a non-empty dict", rid)
        return None
    explanation = entry["explanation"]
    if not isinstance(explanation, str):
        logger.warning("skipping rule %s: explanation must be a string", rid)
        return None
    return Rule(
        id=rid,
        pattern=dict(pattern),
        modifier=modifier,
        explanation=explanation,
        framework_ref=dict(framework_ref),
    )


# ---------------------------------------------------------------------------
# Predicate dispatch
# ---------------------------------------------------------------------------


def _predicate_has_tags(
    pattern_value: Any,
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
) -> bool:
    """ALL-OF semantics per spec §6.2 example (Phase A Q3)."""
    if not isinstance(pattern_value, list):
        raise TypeError(f"has_tags must be a list, got {type(pattern_value).__name__}")
    required = {str(t) for t in pattern_value}
    present = {t.value for t in ontology_tags}
    return required.issubset(present)


def _predicate_source_in(
    pattern_value: Any,
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
) -> bool:
    if not isinstance(pattern_value, list):
        raise TypeError(f"source_in must be a list, got {type(pattern_value).__name__}")
    return asset.source in {str(s) for s in pattern_value}


def _predicate_unknown_capability(
    pattern_value: Any,
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
) -> bool:
    """Re-evaluates :func:`is_unknown_capability_mcp` — no coupling to
    the RiskScoreResult's contributions."""
    if not isinstance(pattern_value, bool):
        raise TypeError(f"unknown_capability must be a bool, got {type(pattern_value).__name__}")
    if pattern_value is False:
        return not is_unknown_capability_mcp(asset, ontology_tags)
    return is_unknown_capability_mcp(asset, ontology_tags)


_PREDICATE_DISPATCH: dict[str, Any] = {
    "has_tags": _predicate_has_tags,
    "source_in": _predicate_source_in,
    "unknown_capability": _predicate_unknown_capability,
}
"""Phase-2 live dispatch. **No forward-compat entries** — per Rajan ratification
2026-06-07 Q-A, the schema gate is the choke point. If a rule somehow reaches
runtime with a non-live predicate (gate bypass, hand-loaded fixture, etc.)
:func:`_rule_matches` logs WARN and the predicate evaluates False as a defense-
in-depth — but the rule cannot ship through the gate in the first place."""


def _rule_matches(
    rule: Rule,
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
) -> bool:
    """A rule matches when EVERY predicate in its pattern evaluates True.

    Multi-predicate patterns are AND-ed.

    Defense-in-depth (Rajan ratification 2026-06-07 Q-A): predicates outside
    :data:`LIVE_PREDICATES` are NOT in :data:`_PREDICATE_DISPATCH`. If one is
    encountered at runtime (gate bypass / hand-loaded fixture), we log WARN
    naming the rule + the unwired predicate + the PR that will wire it, and
    the rule does NOT match. Returning ``False`` here is a runtime guardrail,
    NOT a contract — the gate FAILs blocking on this case so production never
    sees it.
    """
    for key, value in rule.pattern.items():
        predicate = _PREDICATE_DISPATCH.get(key)
        if predicate is None:
            if key in FORWARD_COMPAT_PREDICATES:
                logger.warning(
                    "rule %s references forward-compat predicate %r (wired by %s); "
                    "this rule SHOULD have been gate-rejected — skipping per defense-in-depth",
                    rule.id,
                    key,
                    FORWARD_COMPAT_PREDICATES[key],
                )
            else:
                logger.warning(
                    "rule %s references unknown predicate %r; skipping per defense-in-depth",
                    rule.id,
                    key,
                )
            return False
        if not predicate(value, asset, ontology_tags):
            return False
    return True


# ---------------------------------------------------------------------------
# apply_curated_rules — per-rule isolation + max-wins
# ---------------------------------------------------------------------------


def apply_curated_rules(
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
    rules: list[Rule],
) -> tuple[int, list[dict]]:
    """Evaluate ``rules`` against ``asset`` + ``ontology_tags``.

    Returns ``(max_modifier, applied_rules_list)``:

    - ``max_modifier``: spec §6.2 ``max(rule_modifiers)`` across rules
      that matched (0 when none match).
    - ``applied_rules_list``: every matched rule's
      ``{id, modifier_applied, explanation, framework_ref}`` — winning
      AND suppressed-by-max-wins alike, for P7.9 popover attribution.

    Per-rule isolation: one bad rule (malformed pattern, predicate
    raises, etc.) is logged WARNING and skipped; the other rules are
    unaffected. Per memory ``project_v022_per_item_isolation.md``.
    """
    matched: list[dict] = []
    for rule in rules:
        try:
            if _rule_matches(rule, asset, ontology_tags):
                matched.append(
                    {
                        "id": rule.id,
                        "modifier_applied": rule.modifier,
                        "explanation": rule.explanation,
                        "framework_ref": dict(rule.framework_ref),
                    }
                )
        except Exception as exc:
            logger.warning("skipping rule %s during match: %s", rule.id, exc)
            continue
    if not matched:
        return 0, []
    max_modifier = max(r["modifier_applied"] for r in matched)
    return max_modifier, matched


# ---------------------------------------------------------------------------
# Composition: score_asset_with_rules
# ---------------------------------------------------------------------------


def score_asset_with_rules(
    asset: Asset,
    ontology_tags: frozenset[OntologyCategory],
    rules: list[Rule],
    *,
    cves: list[dict] | None = None,
    runtime_activity: dict | None = None,
    integration_sensitivity_score: float = 0.0,
) -> RiskScoreResult:
    """Compose base scorer + rules engine per spec §6.2.

    Calls :func:`compute_risk_score` for the base risk + unknown-capability
    floor, then :func:`apply_curated_rules` for the modifier, then
    applies ``min(100, base + max_modifier)`` and rederives the band.

    The result's ``applied_rules`` field carries the per-rule attribution
    P7.9 reads. The base scorer's ``contributions`` (including
    ``unknown_capability_floor`` when it fired) are preserved unchanged.
    """
    base_result = compute_risk_score(
        asset,
        ontology_tags=ontology_tags,
        cves=cves,
        runtime_activity=runtime_activity,
        integration_sensitivity_score=integration_sensitivity_score,
    )
    max_modifier, applied_rules = apply_curated_rules(asset, ontology_tags, rules)
    if max_modifier == 0 and not applied_rules:
        return base_result

    # Crash-guard (Q-B mandatory) + floor preservation (Q-B ratified): clamp
    # the modifier-adjusted score to [0, 100] FIRST so a negative max_modifier
    # can never produce a negative score (would crash score_to_band). THEN
    # re-assert any applicable capability floor (spec §6.8 unknown-capability
    # floor) — a curated negative modifier must never breach a floor that
    # exists to protect the asset class. Positive modifiers still compose
    # above the floor (e.g., a future exfil +20 → 60).
    candidate = base_result.final_score + max_modifier
    final_clamped = min(100.0, max(0.0, candidate))
    if is_unknown_capability_mcp(asset, ontology_tags):
        final_clamped = max(UNKNOWN_CAPABILITY_FLOOR, final_clamped)
    final_score = round(final_clamped)
    band = score_to_band(final_score)

    base_result.final_score = final_score
    base_result.band = band
    base_result.applied_rules = applied_rules
    return base_result


__all__ = [
    "DEFAULT_RULES_PATH",
    "MODIFIER_MAX",
    "MODIFIER_MIN",
    "Rule",
    "apply_curated_rules",
    "load_curated_rules",
    "score_asset_with_rules",
]
