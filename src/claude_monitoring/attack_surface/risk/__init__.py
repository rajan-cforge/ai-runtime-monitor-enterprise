"""Risk scoring — 4-factor formula + bands + unknown-capability floor.

P2.3 ships:

- :mod:`weights` — single source of truth for the 4 factor weights.
- :mod:`bands` — :class:`RiskBand` enum + score→band assignment.
- :mod:`unknown` — unknown-capability signature + floor constant.
- :mod:`scoring` — :func:`compute_risk_score` + dataclasses.

Phase 2 follow-ups (NOT in P2.3):

- **P2.4** — curated rules engine (band-bumping modifiers, max-wins).
- **P2.5** — initial curated rule set with NIST CSF + MITRE citations.
- **P2.6** — source reputation factor (its own egress PR per memory
  ``project_reputation_egress_not_a_rule.md``).
- **P4.1** — CVE feed input.
- **P4.3** — runtime activity correlation input.
- **P7.9** — UI breakdown popover.
"""

from __future__ import annotations
