"""P2.6 reputation types — three-state contract + PyPI sentinel ban.

Pins the load-bearing invariants of ``ReputationResult``:

1. Three states are EXHAUSTIVE — present True / present False / present None.
2. ``present is None`` REQUIRES ``reason`` (no silent unavailability).
3. ``present is not None`` REQUIRES ``reason is None`` (no contradictory state).
4. Negative download counts are rejected at construction (PyPI ``-1`` sentinel
   must never reach the threshold comparison — Rajan ratification hard
   requirement #1, 2026-06-08).
5. The str-mixin enum precedent (``ReputationSignal``, ``UnavailableReason``)
   serializes via ``.value`` cross-version-safely.

Per ``feedback_assert_strippable_use_if_raise.md``: production invariants use
``if ... raise``, NOT ``assert``. Tested by `python -O` resistance — the
guards must fire even with assertions disabled.
"""

from __future__ import annotations

import json

import pytest

from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)


class TestThreeStateContractIsExhaustive:
    """The (present, reason) field combination must be one of exactly
    three valid shapes; everything else raises."""

    def test_present_true_with_no_reason_is_valid(self) -> None:
        r = ReputationResult(
            signal=ReputationSignal.NPM_LOW_DOWNLOADS,
            present=True,
            downloads=1_246_297,
            reason=None,
        )
        assert r.present is True
        assert r.reason is None

    def test_present_false_with_no_reason_is_valid(self) -> None:
        r = ReputationResult(
            signal=ReputationSignal.NPM_LOW_DOWNLOADS,
            present=False,
            downloads=50,
            reason=None,
        )
        assert r.present is False
        assert r.reason is None

    def test_present_none_with_reason_is_valid(self) -> None:
        r = ReputationResult(
            signal=ReputationSignal.PIP_LOW_DOWNLOADS,
            present=None,
            downloads=None,
            reason=UnavailableReason.RATE_LIMITED,
        )
        assert r.present is None
        assert r.reason is UnavailableReason.RATE_LIMITED


class TestSilenceIsNeverAllClear:
    """Hard requirement #2 (Rajan 2026-06-08): silence must never render
    as all-clear. ``present=None`` without ``reason`` is the
    silence-equals-all-clear state and MUST be rejected at construction."""

    def test_present_none_without_reason_raises(self) -> None:
        with pytest.raises(ValueError, match=r"present=None but no reason"):
            ReputationResult(
                signal=ReputationSignal.PIP_LOW_DOWNLOADS,
                present=None,
                downloads=None,
                reason=None,
            )

    def test_present_true_with_reason_raises(self) -> None:
        """A 'present' result with a reason is contradictory — reason
        is only meaningful when present is None."""
        with pytest.raises(ValueError, match=r"reason is only set when present is None"):
            ReputationResult(
                signal=ReputationSignal.NPM_LOW_DOWNLOADS,
                present=True,
                downloads=100,
                reason=UnavailableReason.RATE_LIMITED,
            )

    def test_present_false_with_reason_raises(self) -> None:
        with pytest.raises(ValueError, match=r"reason is only set when present is None"):
            ReputationResult(
                signal=ReputationSignal.NPM_LOW_DOWNLOADS,
                present=False,
                downloads=50,
                reason=UnavailableReason.LOOKUP_FAILED,
            )


class TestPyPISentinelBan:
    """Hard requirement #1 (Rajan 2026-06-08): PyPI ``info.downloads = -1``
    sentinel must NEVER reach the threshold comparison. The per-registry
    pypi client is responsible for translating ``-1`` to ``None``; this
    test pins the floor invariant that ``ReputationResult`` REJECTS
    any negative downloads at construction so the bug cannot land
    silently."""

    def test_negative_one_downloads_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match=r"downloads=-1"):
            ReputationResult(
                signal=ReputationSignal.PIP_LOW_DOWNLOADS,
                present=False,
                downloads=-1,
                reason=None,
            )

    def test_arbitrary_negative_downloads_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"downloads=-42"):
            ReputationResult(
                signal=ReputationSignal.PIP_LOW_DOWNLOADS,
                present=False,
                downloads=-42,
                reason=None,
            )

    def test_zero_downloads_is_valid(self) -> None:
        """A package with literally 0 weekly downloads is a real value
        (often a new package or a removed package). Must be accepted —
        it's distinct from the unavailable case."""
        r = ReputationResult(
            signal=ReputationSignal.PIP_LOW_DOWNLOADS,
            present=False,
            downloads=0,
            reason=None,
        )
        assert r.downloads == 0


class TestEnumStrMixinPrecedent:
    """Both enums inherit from str so ``json.dumps`` serializes via
    the lowercase value (cross-version-safe vs ``str(member)``)."""

    def test_reputation_signal_serializes_to_value(self) -> None:
        assert json.dumps(ReputationSignal.NPM_LOW_DOWNLOADS) == '"npm_low_downloads"'

    def test_unavailable_reason_serializes_to_value(self) -> None:
        assert json.dumps(UnavailableReason.RATE_LIMITED) == '"rate_limited"'

    def test_all_signals_have_lowercase_underscore_values(self) -> None:
        for s in ReputationSignal:
            assert s.value == s.value.lower()
            assert " " not in s.value

    def test_all_reasons_have_lowercase_underscore_values(self) -> None:
        for r in UnavailableReason:
            assert r.value == r.value.lower()
            assert " " not in r.value


class TestSignalCoverage:
    """The four spec §6.6.3 signals + the MCP-author signal must all
    have enum entries. If a future signal is added (e.g., GitHub-API
    online MCP-author check), this test reminds the author to update
    the modifier-weight table too."""

    def test_signal_set_matches_ratified_four(self) -> None:
        # Per ratification §1: npm/pip is ONE spec signal applied to TWO
        # languages, so the enum has 5 entries (npm/pip split) but the
        # spec lists 4 distinct signal types.
        expected = {
            "npm_low_downloads",
            "pip_low_downloads",
            "chrome_not_in_store",
            "vscode_not_in_marketplace",
            "mcp_author_unverified",
        }
        actual = {s.value for s in ReputationSignal}
        assert actual == expected

    def test_unavailable_reason_set_matches_ratified_four(self) -> None:
        expected = {
            "rate_limited",
            "budget_exceeded",
            "lookup_failed",
            "dormant",
        }
        actual = {r.value for r in UnavailableReason}
        assert actual == expected
