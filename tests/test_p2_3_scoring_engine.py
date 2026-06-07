"""P2.3 — Risk scoring engine: 4-factor formula + RiskScoreResult.

Spec §6.1 base formula:

    final_risk = min(100,
        max_cve_severity      * 0.35   # CVSS × 10
      + permission_breadth    * 0.30   # len(tags) / 10 * 100
      + integration_sensitivity * 0.20 # table-driven
      + activity_recency      * 0.15   # 0/30/60/80/100 per spec §6.1
    )

Q3 per verdict P2.3.a1: weights snapshot onto each
``RiskScoreResult`` at compute time from a single-source constants
module (``risk.weights``). Self-contained for popover rendering;
audit-stable for persistence.

Q4 per verdict P2.3.a1: orphan ``data_exfiltration_capable``
tag in ``ontology_tags`` without the formula preconditions raises
explicitly (``if orphan: raise``, NOT ``assert`` — strippable
under ``-O``).
"""

from __future__ import annotations

import time

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.risk.bands import RiskBand
from claude_monitoring.attack_surface.risk.scoring import (
    RiskFactors,
    RiskScoreResult,
    compute_risk_score,
)
from claude_monitoring.attack_surface.risk.weights import FACTOR_WEIGHTS


def _asset(*, source: str = "mcp-servers", current_state: dict | None = None) -> Asset:
    return Asset(
        id="x",
        type="mcp_server" if source == "mcp-servers" else "ai_tool",
        parent_asset_id=None,
        name="x",
        version=None,
        install_path="/tmp/x.json",
        source=source,
        current_state=current_state or {},
        discovered_at=time.time(),
    )


# ---------------------------------------------------------------------------
# Factor weights — locked constants
# ---------------------------------------------------------------------------


class TestFactorWeights:
    def test_weights_match_spec_6_1(self) -> None:
        """Spec §6.1: CVE=0.35, breadth=0.30, integration=0.20, activity=0.15."""
        assert FACTOR_WEIGHTS["max_cve_severity"] == 0.35
        assert FACTOR_WEIGHTS["permission_breadth"] == 0.30
        assert FACTOR_WEIGHTS["integration_sensitivity"] == 0.20
        assert FACTOR_WEIGHTS["activity_recency"] == 0.15

    def test_weights_sum_to_one(self) -> None:
        """Sanity: weights must sum to 1.0 for the formula to produce
        a 0-100 result when factors are 0-100."""
        assert abs(sum(FACTOR_WEIGHTS.values()) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Phase 2 input availability — only permission_breadth contributes
# ---------------------------------------------------------------------------


class TestPhase2InputAvailability:
    """Spec/directive: in Phase 2, CVE list = [], runtime_activity = {},
    integration_sensitivity = 0 (no integration sources shipped).
    Only `permission_breadth` actively contributes. Max score = 30 (LOW)
    unless the unknown-capability floor applies."""

    def test_zero_tags_zero_inputs_lands_at_info(self) -> None:
        asset = _asset(source="ollama-models")
        result = compute_risk_score(asset, ontology_tags=frozenset())
        assert result.final_score == 0
        assert result.band == RiskBand.INFO

    def test_one_tag_recognized_lands_at_info(self) -> None:
        """1 tag → permission_breadth = 10 → factor contribution = 3.0 →
        INFO band (0-19). Skill source → no unknown-capability path.
        Pinning the formula honestly: a single declared permission with
        no CVE/integration/activity inputs is a 3-point asset."""
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(asset, ontology_tags=frozenset({OntologyCategory.CODE_EXECUTION}))
        assert result.final_score == 3
        assert result.band == RiskBand.INFO

    def test_seven_tags_lands_at_low(self) -> None:
        """7 tags → permission_breadth = 70 → contribution = 21 → LOW band
        (20-39). Confirms the LOW threshold is reachable by breadth alone."""
        asset = _asset(source="claude-code-skills")
        tags = frozenset(list(OntologyCategory)[:7])
        result = compute_risk_score(asset, ontology_tags=tags)
        assert result.final_score == 21
        assert result.band == RiskBand.LOW

    def test_all_ten_tags_lands_at_low(self) -> None:
        """Phase 2 ceiling: even with all 10 ontology categories tagged,
        permission_breadth = 100 → 30 contribution → still LOW band.
        This is why memory `project_phase2_demo_positioning.md` says
        don't demo risk scores in Phase 2."""
        asset = _asset(source="claude-code-skills")
        tags = frozenset(OntologyCategory)
        result = compute_risk_score(asset, ontology_tags=tags)
        assert result.final_score == 30
        assert result.band == RiskBand.LOW


# ---------------------------------------------------------------------------
# Unknown-capability floor integration (Q1 with signature fix)
# ---------------------------------------------------------------------------


class TestUnknownCapabilityFloor:
    """Unrecognized MCP server (no command-derived tags) gets floored
    at 40 → MEDIUM band, with breakdown line `unknown_capability_floor`."""

    def test_singleton_mcp_floors_at_medium(self) -> None:
        asset = _asset(source="mcp-servers", current_state={"command": "node", "args": []})
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION})
        result = compute_risk_score(asset, ontology_tags=tags)
        # base_risk would be 0.3 * 10 = 3 (1/10 * 100 = 10 * 0.3 = 3); floor 40 wins
        assert result.final_score == 40
        assert result.band == RiskBand.MEDIUM
        assert "unknown_capability_floor" in result.contributions
        assert result.contributions["unknown_capability_floor"] == 40.0

    def test_exfil_shape_unrecognized_mcp_still_floors(self) -> None:
        """**The Rajan 2026-06-07 regression pin.** A credential-bearing
        unrecognized MCP must NOT escape the floor by having secrets_access.
        Tag count is 2 but command-derived tag count is 0."""
        asset = _asset(
            source="mcp-servers",
            current_state={
                "command": "node",
                "args": ["/opt/my-custom/server.js"],
                "env": {"GITHUB_TOKEN": "[REDACTED]"},
            },
        )
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION, OntologyCategory.SECRETS_ACCESS})
        result = compute_risk_score(asset, ontology_tags=tags)
        assert result.final_score == 40
        assert result.band == RiskBand.MEDIUM, (
            "REGRESSION: credential-bearing unrecognized MCP escaped the floor — "
            "exfil shape sliding to LOW via secrets_access tag"
        )
        assert "unknown_capability_floor" in result.contributions

    def test_recognized_mcp_does_not_floor(self) -> None:
        """A recognized MCP (filesystem-server) computes its honest formula
        score, no floor. With 3 tags (ITC + FS_READ + FS_WRITE),
        permission_breadth = 30 → contribution = 9 → INFO band (0-19).
        The honest Phase 2 reality: even a recognized server with three
        capabilities scores below LOW until CVE/runtime wire in. That's
        what memory `project_phase2_demo_positioning.md` says — don't
        demo risk scores against Phase 2 data."""
        asset = _asset(
            source="mcp-servers",
            current_state={"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
        )
        tags = frozenset(
            {
                OntologyCategory.INTER_TOOL_COMMUNICATION,
                OntologyCategory.FILE_SYSTEM_READ,
                OntologyCategory.FILE_SYSTEM_WRITE,
            }
        )
        result = compute_risk_score(asset, ontology_tags=tags)
        assert result.final_score == 9
        assert result.band == RiskBand.INFO
        # The load-bearing assertion: NO floor applied for a recognized MCP
        assert "unknown_capability_floor" not in result.contributions


# ---------------------------------------------------------------------------
# Q4: orphan derived tag raises (explicit, not assert)
# ---------------------------------------------------------------------------


class TestOrphanDerivedTagRaises:
    """Q4 per verdict P2.3.a1: if `DATA_EXFILTRATION_CAPABLE` is in
    ontology_tags but the formula preconditions are not met, raise
    explicitly. Uses `if orphan: raise` (NOT `assert` — strippable under
    `python -O`)."""

    def test_orphan_derived_tag_without_preconditions_raises(self) -> None:
        """Set contains DATA_EXFILTRATION_CAPABLE but neither
        (secrets_access OR file_system_read) nor (network_unrestricted OR
        network_scoped) — derivation invariant violated upstream."""
        asset = _asset(source="claude-code-skills")
        bad_tags = frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.DATA_EXFILTRATION_CAPABLE})
        with pytest.raises(ValueError, match=r"orphan|data_exfiltration_capable"):
            compute_risk_score(asset, ontology_tags=bad_tags)

    def test_orphan_check_uses_if_raise_not_assert(self) -> None:
        """Read the source: the orphan check must use `if ... raise`,
        NOT `assert`. The latter is stripped under `python -O` and a
        correctness invariant must not be removable by an optimization
        flag (memory `feedback_assert_strippable_use_if_raise.md`)."""
        from pathlib import Path

        from claude_monitoring.attack_surface.risk import scoring as scoring_mod

        source = Path(scoring_mod.__file__).read_text()
        # Negative: there must NOT be a bare assert guarding the orphan check
        assert "assert orphan" not in source
        assert "assert _has_orphan" not in source
        # Positive: the explicit if-raise form must be present
        assert "raise ValueError" in source

    def test_valid_derived_tag_does_not_raise(self) -> None:
        """`DATA_EXFILTRATION_CAPABLE` accompanied by satisfying preconditions
        is the normal case — no raise."""
        asset = _asset(source="mcp-servers", current_state={"command": "x"})
        good_tags = frozenset(
            {
                OntologyCategory.INTER_TOOL_COMMUNICATION,
                OntologyCategory.SECRETS_ACCESS,
                OntologyCategory.NETWORK_UNRESTRICTED,
                OntologyCategory.DATA_EXFILTRATION_CAPABLE,
            }
        )
        # Should not raise
        result = compute_risk_score(asset, ontology_tags=good_tags)
        assert isinstance(result, RiskScoreResult)


# ---------------------------------------------------------------------------
# Q3: weights snapshot on RiskScoreResult
# ---------------------------------------------------------------------------


class TestWeightsSnapshotOnResult:
    """Q3 per verdict P2.3.a1: weights are defined once in
    `risk.weights.FACTOR_WEIGHTS` and SNAPSHOTTED onto each
    `RiskScoreResult` at compute time. Self-contained for popover
    rendering; audit-stable for persistence (a historical result records
    the exact weights that produced its score)."""

    def test_result_carries_weights(self) -> None:
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(asset, ontology_tags=frozenset({OntologyCategory.CODE_EXECUTION}))
        assert result.weights == FACTOR_WEIGHTS

    def test_weights_snapshot_is_independent_copy(self) -> None:
        """The result's weights dict must NOT be the live module constant
        — otherwise mutating one would mutate all historical results.
        Test by mutating the result's dict and confirming the module
        constant is unchanged."""
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(asset, ontology_tags=frozenset())
        original_cve_weight = FACTOR_WEIGHTS["max_cve_severity"]
        # Mutate the result's dict
        result.weights["max_cve_severity"] = 0.99
        # Module constant must be unchanged
        assert FACTOR_WEIGHTS["max_cve_severity"] == original_cve_weight

    def test_contributions_dict_renders_breakdown_structure(self) -> None:
        """The contributions dict has named keys the popover (P7.9) reads."""
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(asset, ontology_tags=frozenset({OntologyCategory.CODE_EXECUTION}))
        # Each factor contributes a named line
        assert "permission_breadth" in result.contributions
        # CVE / integration / activity contribute 0 in Phase 2 but the
        # breakdown still names them (popover shows "0 — CVE data
        # unavailable until P4.1")
        assert "max_cve_severity" in result.contributions
        assert "integration_sensitivity" in result.contributions
        assert "activity_recency" in result.contributions


# ---------------------------------------------------------------------------
# RiskFactors / RiskScoreResult dataclass shape
# ---------------------------------------------------------------------------


class TestResultShape:
    def test_result_has_final_score_and_band(self) -> None:
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(asset, ontology_tags=frozenset())
        assert isinstance(result.final_score, int)
        assert isinstance(result.band, RiskBand)

    def test_result_has_factors(self) -> None:
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(asset, ontology_tags=frozenset())
        assert isinstance(result.factors, RiskFactors)

    def test_score_is_clamped_at_100(self) -> None:
        """Defensive: even with maxed inputs, score never exceeds 100."""
        asset = _asset(source="claude-code-skills")
        result = compute_risk_score(
            asset,
            ontology_tags=frozenset(OntologyCategory),
            cves=[{"cvss": 10.0}, {"cvss": 10.0}],  # cap at max
            runtime_activity={"recency_score": 100},
            integration_sensitivity_score=100,
        )
        assert result.final_score <= 100
