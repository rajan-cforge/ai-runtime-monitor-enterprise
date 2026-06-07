"""P2.3 — `RiskBand` enum + score→band assignment.

**Spec §6.3:** 5 bands with these ranges (lower-bound inclusive,
upper-bound inclusive at 100):

| Score range | Band |
|---|---|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| 0–19 | INFO |

**Q2 ratification (2026-06-07):** ``RiskBand(str, enum.Enum)`` —
str-mixin precedent matches ``LastRunOutcome`` / ``OntologyCategory``
/ ``Severity``. Serialize via ``.value``; never ``str(member)``.
"""

from __future__ import annotations

import enum
import json

import pytest

from claude_monitoring.attack_surface.risk.bands import (
    RiskBand,
    score_to_band,
)


class TestRiskBandEnum:
    def test_exactly_five_bands_per_spec_6_3(self) -> None:
        assert len(RiskBand) == 5

    def test_band_values_locked(self) -> None:
        assert RiskBand.CRITICAL.value == "critical"
        assert RiskBand.HIGH.value == "high"
        assert RiskBand.MEDIUM.value == "medium"
        assert RiskBand.LOW.value == "low"
        assert RiskBand.INFO.value == "info"

    def test_str_mixin_inheritance(self) -> None:
        assert issubclass(RiskBand, str)
        assert issubclass(RiskBand, enum.Enum)

    def test_json_serialization(self) -> None:
        """Q2: `RiskBand(str, enum.Enum)` — `json.dumps(member)` emits
        the value directly (version-stable, str-mixin path)."""
        assert json.dumps(RiskBand.MEDIUM) == '"medium"'


class TestScoreToBandBoundaries:
    """Spec §6.3 boundary semantics: `>=` lower-bound, inclusive upper.

    The Phase A investigation confirmed: 80 is CRITICAL not HIGH, 60 is
    HIGH not MEDIUM, etc. Test the boundaries explicitly.
    """

    @pytest.mark.parametrize(
        "score,expected_band",
        [
            (0, RiskBand.INFO),
            (1, RiskBand.INFO),
            (19, RiskBand.INFO),
            (20, RiskBand.LOW),
            (21, RiskBand.LOW),
            (39, RiskBand.LOW),
            (40, RiskBand.MEDIUM),
            (41, RiskBand.MEDIUM),
            (59, RiskBand.MEDIUM),
            (60, RiskBand.HIGH),
            (61, RiskBand.HIGH),
            (79, RiskBand.HIGH),
            (80, RiskBand.CRITICAL),
            (81, RiskBand.CRITICAL),
            (100, RiskBand.CRITICAL),
        ],
    )
    def test_score_maps_to_correct_band(self, score: int, expected_band: RiskBand) -> None:
        assert score_to_band(score) == expected_band

    def test_negative_score_raises(self) -> None:
        """Score is bounded [0, 100] — negative is a programming error,
        not a quiet underflow."""
        with pytest.raises(ValueError, match="must be in"):
            score_to_band(-1)

    def test_score_above_100_raises(self) -> None:
        """Score is bounded [0, 100]. The 4-factor formula clamps via
        `min(100, ...)`, so >100 reaching here is a programming error."""
        with pytest.raises(ValueError, match="must be in"):
            score_to_band(101)

    def test_float_score_accepted(self) -> None:
        """Spec §6.4 examples use float intermediate scores
        (e.g., 28.7 + 30.0 + 0 + 0 = 58.7). Final band is from the
        rounded int per §6.3 ranges, but the function accepts float."""
        # 28.7 floor-rounded to 28 is LOW; ceil to 29 still LOW; round-half-even
        # to 29 → LOW. We pin: the function applies int(round(...)) per Phase
        # A §1 — 28.5 → 28 → LOW, 28.7 → 29 → LOW, 39.5 → 40 → MEDIUM.
        assert score_to_band(28.7) == RiskBand.LOW
        assert score_to_band(39.5) == RiskBand.MEDIUM
        assert score_to_band(59.5) == RiskBand.HIGH
