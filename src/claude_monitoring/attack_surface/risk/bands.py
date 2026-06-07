"""Risk bands — spec §6.3.

Five bands, `>=` semantics on lower bounds (80 is CRITICAL not HIGH;
60 is HIGH not MEDIUM, etc.).

**Q2 ratification (2026-06-07):** ``RiskBand(str, enum.Enum)`` matches
the ``LastRunOutcome`` / ``OntologyCategory`` / ``Severity`` str-mixin
precedent. ``json.dumps`` emits the value string directly. Read
discipline: use ``member.value``, never ``str(member)`` (the latter
returns enum-repr on Python 3.10/3.11 and value on 3.12+).
"""

from __future__ import annotations

import enum


class RiskBand(str, enum.Enum):
    """Spec §6.3 — five risk bands by score range.

    Score ranges (inclusive on both ends):

    | Range | Band |
    |---|---|
    | 80–100 | CRITICAL |
    | 60–79 | HIGH |
    | 40–59 | MEDIUM |
    | 20–39 | LOW |
    | 0–19 | INFO |
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def score_to_band(score: float) -> RiskBand:
    """Map a 0-100 risk score to its band per spec §6.3.

    Uses ``int(round(score))`` per Phase A §1 — float intermediate
    scores from the formula get rounded to the nearest int, then
    looked up against the boundaries. ``>=`` semantics on lower bounds.

    Args:
        score: 0-100 float or int. Negative or >100 raises ValueError
            (programming error — the formula clamps via ``min(100, ...)``
            so values outside [0, 100] reaching here indicate an
            upstream bug).

    Returns:
        The :class:`RiskBand` whose range contains the rounded score.
    """
    if not (0 <= score <= 100):
        raise ValueError(f"score_to_band: score must be in [0, 100], got {score}")
    rounded = round(score)
    if rounded >= 80:
        return RiskBand.CRITICAL
    if rounded >= 60:
        return RiskBand.HIGH
    if rounded >= 40:
        return RiskBand.MEDIUM
    if rounded >= 20:
        return RiskBand.LOW
    return RiskBand.INFO


__all__ = ["RiskBand", "score_to_band"]
