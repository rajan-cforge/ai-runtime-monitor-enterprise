"""Tests for the C-rider render-rules layer.

Per Rajan C rider (2026-06-11) + verdict scan-scoring-callsite.a1
Finding 3: each `cve_status` state has a defined render rule that the
dashboard MUST honour. The rules are codified here (in pure Python)
so the future dashboard PR has one load-bearing call site per state.
"""

from __future__ import annotations

from claude_monitoring.attack_surface.cves.types import UnavailableReason
from claude_monitoring.attack_surface.rendering import cve_status_hint, risk_score_hint


class TestNotApplicableRendersNeutrally:
    """C rider: `not_applicable` renders neutrally (no badge or a quiet 'n/a').
    Amendment C data-truthfulness: must NEVER share a label with `unavailable`."""

    def test_not_applicable_returns_dash_label(self):
        hint = cve_status_hint("not_applicable", cves=None, cve_unavailable_reason=None)
        assert hint.label == "—"
        assert hint.severity == "neutral"

    def test_not_applicable_label_distinct_from_unavailable(self):
        not_app = cve_status_hint("not_applicable", None, None)
        unavail = cve_status_hint("unavailable", None, "rate_limited")
        assert not_app.label != unavail.label, (
            "Amendment C data-truthfulness: 'doesn't apply' and 'failed' must never share a label"
        )


class TestUnavailableRendersWithReason:
    """C rider: `unavailable` renders as a visible warning with the reason.
    Each `UnavailableReason` carries a distinct operator-facing label."""

    def test_rate_limited_renders_with_reason(self):
        hint = cve_status_hint("unavailable", None, UnavailableReason.RATE_LIMITED.value)
        assert "rate-limited" in hint.label.lower()
        assert hint.severity == "warn-low"

    def test_kill_switch_renders_with_reason(self):
        hint = cve_status_hint("unavailable", None, UnavailableReason.KILL_SWITCH.value)
        assert "disabled" in hint.label.lower()

    def test_no_network_renders_with_reason(self):
        hint = cve_status_hint("unavailable", None, UnavailableReason.NO_NETWORK.value)
        assert "offline" in hint.label.lower() or "no_network" in hint.label.lower()

    def test_budget_exhausted_renders_with_reason(self):
        hint = cve_status_hint("unavailable", None, UnavailableReason.BUDGET_EXHAUSTED.value)
        assert "budget" in hint.label.lower()

    def test_network_error_renders_with_reason(self):
        hint = cve_status_hint("unavailable", None, UnavailableReason.NETWORK_ERROR.value)
        assert "network" in hint.label.lower()

    def test_parse_error_renders_with_reason(self):
        hint = cve_status_hint("unavailable", None, UnavailableReason.PARSE_ERROR.value)
        assert "parse" in hint.label.lower()

    def test_unknown_reason_falls_back_gracefully(self):
        """Forward-compat: a future UnavailableReason enum value must not
        crash the renderer."""
        hint = cve_status_hint("unavailable", None, "future_unknown_reason")
        assert hint.severity == "warn-low"
        assert hint.label  # non-empty


class TestOkEmptyListRendersAsNoKnownVulns:
    """C rider: `ok + []` renders as 'no known vulns'. The clean-lookup
    case is distinct from `not_applicable` — operator must see 'we asked
    and it was clean' vs 'we didn't ask'."""

    def test_ok_empty_renders_as_no_known_vulns(self):
        hint = cve_status_hint("ok", cves=[], cve_unavailable_reason=None)
        assert "no known" in hint.label.lower()
        assert hint.severity == "info"

    def test_ok_empty_distinct_from_not_applicable(self):
        ok_clean = cve_status_hint("ok", [], None)
        not_app = cve_status_hint("not_applicable", None, None)
        assert ok_clean.label != not_app.label


class TestOkWithVulnsRendersCount:
    def test_one_vuln_uses_singular(self):
        hint = cve_status_hint("ok", cves=[{"id": "GHSA-x", "cvss": 7.5}], cve_unavailable_reason=None)
        assert "1 known vuln" in hint.label
        assert "vulns" not in hint.label, "singular: no plural s"

    def test_multiple_vulns_use_plural(self):
        cves = [{"id": f"GHSA-{i}", "cvss": 5.0} for i in range(5)]
        hint = cve_status_hint("ok", cves=cves, cve_unavailable_reason=None)
        assert "5 known vulns" in hint.label

    def test_warn_high_severity(self):
        cves = [{"id": "GHSA-x", "cvss": 9.1}]
        hint = cve_status_hint("ok", cves=cves, cve_unavailable_reason=None)
        assert hint.severity == "warn-high"


class TestUnknownStatusFailsClosed:
    """Defensive: an unknown `cve_status` (would only happen if the
    persisted schema is corrupted) renders a visible-but-quiet hint
    rather than crashing."""

    def test_unknown_status_returns_safe_hint(self):
        hint = cve_status_hint("garbage", None, None)
        assert hint.severity == "warn-low"
        assert "garbage" in hint.label


class TestRiskScoreHint:
    """C rider NULL-risk_score case: 'not yet scored' renders distinctly
    from `risk_score=0` ('we computed it, it's zero')."""

    def test_null_score_renders_not_yet_scored(self):
        hint = risk_score_hint(None)
        assert hint is not None
        assert "not yet scored" in hint.label.lower()
        assert hint.severity == "neutral"

    def test_zero_score_returns_none(self):
        """An integer score (including 0) yields None — the row's own
        risk-score badge renders the number. The hint layer only fills
        in for the NULL case."""
        assert risk_score_hint(0) is None

    def test_high_score_returns_none(self):
        assert risk_score_hint(85) is None
