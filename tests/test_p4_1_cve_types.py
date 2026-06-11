"""TDD red-phase tests for P4.1 CVE feed types.

Phase B test surface for `attack_surface/cves/types.py`. These tests
pin the dataclass contract before any implementation lands.

Phase A doc: ~/Documents/vigil-notes/v022/phase-4-prep/p4.1-osv-cve-feed-phase-a.md
"""

from __future__ import annotations

import pytest


class TestCVEResultDataclass:
    """`CVEResult` is the per-asset CVE lookup result. The scoring formula
    (`compute_risk_score`'s `cves` param) already expects a list of
    `{"cvss": float}` dicts; this dataclass wraps the result so dispatcher
    + cache layers can pass typed objects internally."""

    def test_result_has_cves_list_attribute(self):
        from claude_monitoring.attack_surface.cves.types import CVEResult

        r = CVEResult(cves=[{"cvss": 7.5}])
        assert r.cves == [{"cvss": 7.5}]

    def test_result_none_signals_did_not_look_up(self):
        """Phase A §5: `cves=None` means "did not look up" (kill switch,
        air-gapped, detail-fetch cap hit). DIFFERENT from `cves=[]` which
        means "looked up, no known vulns." Downstream UI distinguishes."""
        from claude_monitoring.attack_surface.cves.types import CVEResult

        r = CVEResult(cves=None)
        assert r.cves is None

    def test_empty_list_means_no_vulns_found(self):
        from claude_monitoring.attack_surface.cves.types import CVEResult

        r = CVEResult(cves=[])
        assert r.cves == []

    def test_frozen_dataclass(self):
        """Frozen so result objects are safe to share across the
        dispatcher's per-item-isolation boundary without surprise mutation."""
        from claude_monitoring.attack_surface.cves.types import CVEResult

        r = CVEResult(cves=[{"cvss": 9.0}])
        with pytest.raises((AttributeError, TypeError, Exception)):
            r.cves = [{"cvss": 0.0}]  # type: ignore[misc]


class TestCVEResultUnavailableReason:
    """Optional `reason` field for telemetry — mirrors the
    `reputation.UnavailableReason` pattern."""

    def test_reason_defaults_to_none(self):
        from claude_monitoring.attack_surface.cves.types import CVEResult

        r = CVEResult(cves=None)
        assert r.reason is None

    def test_reason_captured_when_cves_is_none(self):
        """When the lookup failed for a known reason, the dispatcher
        records it for the dashboard's per-asset display."""
        from claude_monitoring.attack_surface.cves.types import (
            CVEResult,
            UnavailableReason,
        )

        r = CVEResult(cves=None, reason=UnavailableReason.RATE_LIMITED)
        assert r.reason == UnavailableReason.RATE_LIMITED

    def test_unavailable_reason_enum_has_documented_states(self):
        """Phase A §5 + the kill-switch scheme require these failure modes."""
        from claude_monitoring.attack_surface.cves.types import UnavailableReason

        # Required members per Phase A:
        assert UnavailableReason.KILL_SWITCH
        assert UnavailableReason.NO_NETWORK
        assert UnavailableReason.RATE_LIMITED
        assert UnavailableReason.BUDGET_EXHAUSTED
        assert UnavailableReason.NETWORK_ERROR
        assert UnavailableReason.PARSE_ERROR
