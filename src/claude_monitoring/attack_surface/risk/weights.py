"""4-factor weight constants — spec §6.1.

**Q3 per verdict P2.3.a1.** Weights are defined ONCE here and
**snapshotted onto each ``RiskScoreResult`` at compute time**, NOT
referenced live from the result object. Two reasons:

1. The breakdown popover (P7.9) renders from a single self-contained
   result with no external state — no module lookup needed.
2. A persisted historical result records the exact weights that
   produced its score. If the formula is later retuned, the
   historical score stays explainable.

Self-contained for UI, audit-stable for persistence, single source of
truth here.
"""

from __future__ import annotations

FACTOR_WEIGHTS: dict[str, float] = {
    "max_cve_severity": 0.35,
    "permission_breadth": 0.30,
    "integration_sensitivity": 0.20,
    "activity_recency": 0.15,
}
"""Spec §6.1 weights table. Sum to 1.0 by construction — the formula
produces a 0-100 result when each factor is in [0, 100]."""


# Module-load invariant: weights must sum to 1.0 (within float tolerance).
# Per memory ``feedback_assert_strippable_use_if_raise.md``, use explicit
# ``if x: raise``, NOT ``assert`` — invariants stripped under ``-O`` are
# not invariants.
_weight_sum = sum(FACTOR_WEIGHTS.values())
if abs(_weight_sum - 1.0) > 1e-9:
    raise RuntimeError(
        f"FACTOR_WEIGHTS sum is {_weight_sum}, expected 1.0; spec §6.1 formula "
        "produces 0-100 only when weights sum to 1.0. Fix the constants."
    )


__all__ = ["FACTOR_WEIGHTS"]
