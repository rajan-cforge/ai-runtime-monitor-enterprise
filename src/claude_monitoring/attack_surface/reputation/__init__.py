"""Source reputation factor — P2.6.

Vigil's FIRST live outbound network call. Composes a reputation modifier
into the per-asset risk score per spec §6.6.3 + the §10.3 transmission
list amendment.

**Locked refs:** spec §6.6.3 (signals + thresholds), §10.1 (privacy
guarantee), §10.3 (transmission list); directive §3 P2.6, §11.2
(privacy-no-telemetry-check gate), §16.3 (empirical ratchet); CONTRACT
§1a (privacy invariant — these are validation calls, not telemetry).

**Ratifications (Rajan 2026-06-08;**
``work-log/2026-06-08-P2.6-ratification.md``**):**

- Four signals from spec §6.6.3 — npm/pip < 100/week +15; MCP-author
  unverified (curator-list miss) +10; Chrome/VSCode not-in-store +20.
  Chrome/VSCode ship DORMANT (``reputation.chrome_vscode_enabled`` flag
  defaulting to False); flipped ON only by the PR that lands
  managed-install detection (P3.1/P3.2).
- Composition option B: ``final = clamp[0,100](base + best_rule + best_reputation)``
  then re-assert any applicable floor (spec §6.9). Layers max-wins
  independently; layers add.
- Empirical-recon-driven (``work-log/2026-06-08-P2.6-empirical-recon.md``):
  pypistats per-scan budget cap = 25; backoff 5/15/60 min after 429.
- Three-state result discipline: ``checked_present`` / ``checked_absent``
  / unavailable-with-reason (``rate_limited``, ``budget_exceeded``,
  ``lookup_failed``). Silence MUST NOT render as all-clear.
- Inversion fix (judge): lookup-failed / unreachable / managed-install
  NEVER fires the modifier. Fail-open posture universal.
- Criticality C4 (first live egress).

**Public exports** are the dispatcher entry point + the result types.
Per-registry clients live in submodules but are not part of the public
surface — they exist to be unit-tested individually.
"""

from __future__ import annotations

from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

__all__ = [
    "ReputationResult",
    "ReputationSignal",
    "UnavailableReason",
]
