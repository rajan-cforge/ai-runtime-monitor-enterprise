"""TDD red-phase tests for scan-scoring-callsite.

Phase B test surface for the orchestrator-level wiring that turns
all of P2.3/P2.6/P4.1 scoring on. Until this PR lands, no live caller
computes risk_score; `assets.risk_score` is written by nothing.

Architect-pass: ~/Documents/vigil-notes/v022/phase-4-prep/scan-scoring-callsite-architect-pass.md
Phase A doc:   ~/Documents/vigil-notes/v022/phase-4-prep/scan-scoring-callsite-phase-a.md

Pins:
  * Q1 — floor preservation against negative modifiers (spec §6.9)
  * Q11 — three blocking conditions: 100-cap, NULL-on-scored, negative severity
  * Amendment C — three-state cve_status: ok / unavailable / not_applicable
  * Amendment D — risk_factors carries weights + schema_version: 1
  * Drift §3 reversal — UPSERT writes ontology_tags + risk_score + risk_band + risk_factors
  * Per-item isolation — exception on one asset → NULL on its row; siblings still scored
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.orchestrator import DiscoveryOrchestrator, ScanLock

# `_score_assets` returns `dict[asset.id -> (RiskScoreResult, CVEResult | None,
# frozenset[OntologyCategory])]` since the code-reviewer 2026-06-11 fix that
# threads the tags through (avoiding a double `map_asset` call at persistence).
# Tests that don't care about the persisted ontology_tags pass an empty
# frozenset; tests that DO care pass a deterministic set.
_NO_TAGS: frozenset[OntologyCategory] = frozenset()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_asset(name: str, source: str = "python-packages", **extra_state) -> Asset:
    state: dict = {"package": name, "version": "1.0.0", "ecosystem": "PyPI"}
    state.update(extra_state)
    return Asset(
        id=f"{source}:{name}",
        type="ai_tool",
        parent_asset_id=None,
        name=name,
        version="1.0.0",
        install_path=None,
        source=source,
        current_state=state,
        discovered_at=0.0,
    )


class _PackageSource(DiscoverySource):
    def __init__(self, assets: list[Asset], src_name: str = "python-packages"):
        self._assets = assets
        self._name = src_name

    def name(self) -> str:
        return self._name

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        return list(self._assets)


def _setup_assets_db(tmp_path: Path) -> sqlite3.Connection:
    from claude_monitoring.persistence.migrations import apply_migrations

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    apply_migrations(conn)
    return conn


# ---------------------------------------------------------------------------
# Q1 — Floor preservation (architect §4)
# ---------------------------------------------------------------------------


class TestFloorPreservation:
    """`UNKNOWN_CAPABILITY_FLOOR` (40) cannot be breached by a negative
    rules modifier per spec §6.9. Pinned at the orchestrator-level test
    file because that's where the wiring-PR contract lives — the
    composition function is downstream of `_score_assets`, but the
    callsite contract is what the dashboard reads."""

    def test_negative_modifier_cannot_breach_unknown_capability_floor(self):
        from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
        from claude_monitoring.attack_surface.reputation.composition import (
            score_asset_with_rules_and_reputation,
        )
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.rules import Rule

        asset = _make_asset("inert-mcp", source="mcp-servers")
        # Only INTER_TOOL_COMMUNICATION → is_unknown_capability_mcp fires
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION})
        # Hand-craft a rule with negative modifier targeting this source
        rule = Rule(
            id="test_negative_for_floor",
            modifier=-10,
            pattern={"source_in": ["mcp-servers"]},
            framework_ref={},
            explanation="test: negative modifier must not breach floor",
        )
        rep_dispatcher = MagicMock()
        rep_dispatcher.lookup.return_value = None
        result = score_asset_with_rules_and_reputation(asset, tags, [rule], rep_dispatcher, cves=None)
        assert result.final_score >= 40, "floor §6.9: negative modifier must not breach UNKNOWN_CAPABILITY_FLOOR"
        assert result.final_score >= 0, "scoring is never negative"
        assert result.band in (RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL)


# ---------------------------------------------------------------------------
# Q11 — blocking-set instrumentation (architect §5)
# ---------------------------------------------------------------------------


class TestRiskScoreCapGuard:
    """`_persist_assets` raises if any final_score > 100 — last-line-of-
    defense against a future scorer change that drops the clamp."""

    def test_score_above_100_raises_at_persistence_boundary(self, tmp_path):
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        conn = _setup_assets_db(tmp_path)
        lock = ScanLock(lock_path=tmp_path / ".lock")
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([_make_asset("evil", "python-packages")])],
            lock=lock,
            persistence_connection=conn,
        )
        evil_result = RiskScoreResult(
            final_score=101,  # the violation
            band=RiskBand.CRITICAL,
            factors=RiskFactors(0.0, 0.0, 0.0, 0.0),
            contributions={},
            weights={},
            applied_rules=[],
            applied_reputation=[],
        )
        # Force the orchestrator to produce the bad result
        with patch.object(
            orch,
            "_score_assets",
            return_value={"python-packages:evil": (evil_result, None, _NO_TAGS)},
        ):
            with pytest.raises(ValueError, match="risk_score"):
                orch.scan(trigger="on_demand")


# ---------------------------------------------------------------------------
# NULL-on-scored — db queries distinguish "scored OK" from "scored failed"
# ---------------------------------------------------------------------------


class TestNullOnScoredAsset:
    """Per-item isolation: scored assets have non-NULL risk_score in the
    DB; assets where scoring threw have NULL risk_score. Never collapsed."""

    def test_scored_asset_has_nonnull_risk_score_in_db(self, tmp_path):
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        conn = _setup_assets_db(tmp_path)
        lock = ScanLock(lock_path=tmp_path / ".lock")
        asset = _make_asset("scored-ok", "python-packages")
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=lock,
            persistence_connection=conn,
        )
        good_result = RiskScoreResult(
            final_score=30,
            band=RiskBand.LOW,
            factors=RiskFactors(0.0, 9.0, 0.0, 0.0),
            contributions={"permission_breadth": 9.0},
            weights={"permission_breadth": 0.30},
            applied_rules=[],
            applied_reputation=[],
        )
        with patch.object(orch, "_score_assets", return_value={asset.id: (good_result, None, _NO_TAGS)}):
            orch.scan(trigger="on_demand")
        row = conn.execute("SELECT risk_score, risk_band FROM assets WHERE id = ?", (asset.id,)).fetchone()
        assert row is not None
        assert row[0] is not None and row[0] == 30
        assert row[1] == RiskBand.LOW.value

    def test_scoring_exception_produces_null_risk_score_in_db(self, tmp_path):
        """When _score_assets returns nothing for an asset (because the
        composition call raised + was caught), the asset row's
        risk_score column stays NULL — distinguishing "not yet scored"
        from "score = 0"."""
        conn = _setup_assets_db(tmp_path)
        lock = ScanLock(lock_path=tmp_path / ".lock")
        asset = _make_asset("exception-asset", "python-packages")
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=lock,
            persistence_connection=conn,
        )
        # Empty score_results → no scoring data for this asset
        with patch.object(orch, "_score_assets", return_value={}):
            orch.scan(trigger="on_demand")
        row = conn.execute(
            "SELECT risk_score, risk_band, risk_factors FROM assets WHERE id = ?", (asset.id,)
        ).fetchone()
        assert row is not None
        assert row[0] is None, "exception → risk_score MUST be NULL (not 0)"
        assert row[1] is None
        assert row[2] is None


# ---------------------------------------------------------------------------
# Amendment C — three-state cve_status
# ---------------------------------------------------------------------------


class TestCveStatusTriState:
    """The `risk_factors.cve_status` field carries three distinct states.
    `None+reason=None` (not_applicable) and `[]` (ok with empty list) are
    NOT collapsed — operator must distinguish "feed doesn't apply" from
    "feed succeeded, no known vulns." Architect Amendment C, Rajan C rider."""

    def _make_orch_with_result(self, tmp_path, asset, score_result, cve_result):
        conn = _setup_assets_db(tmp_path)
        lock = ScanLock(lock_path=tmp_path / ".lock")
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=lock,
            persistence_connection=conn,
        )
        with patch.object(
            orch,
            "_score_assets",
            return_value={asset.id: (score_result, cve_result, _NO_TAGS)},
        ):
            orch.scan(trigger="on_demand")
        row = conn.execute("SELECT risk_factors FROM assets WHERE id = ?", (asset.id,)).fetchone()
        return json.loads(row[0])

    def _good_result(self):
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        return RiskScoreResult(
            final_score=10,
            band=RiskBand.LOW,
            factors=RiskFactors(0.0, 0.0, 0.0, 0.0),
            contributions={},
            weights={},
            applied_rules=[],
            applied_reputation=[],
        )

    def test_cves_with_vulns_serializes_as_ok_with_list(self, tmp_path):
        from claude_monitoring.attack_surface.cves.types import CVEResult

        cve = CVEResult(cves=[{"id": "GHSA-x", "cvss": 7.5}])
        asset = _make_asset("pkg-with-vulns", "python-packages")
        factors = self._make_orch_with_result(tmp_path, asset, self._good_result(), cve)
        assert factors["cve_status"] == "ok"
        assert factors["cve_unavailable_reason"] is None
        assert factors["cves"] == [{"id": "GHSA-x", "cvss": 7.5}]

    def test_cves_empty_list_serializes_as_ok_with_empty_list(self, tmp_path):
        from claude_monitoring.attack_surface.cves.types import CVEResult

        cve = CVEResult(cves=[])  # successful negative lookup
        asset = _make_asset("clean-pkg", "python-packages")
        factors = self._make_orch_with_result(tmp_path, asset, self._good_result(), cve)
        assert factors["cve_status"] == "ok"
        assert factors["cve_unavailable_reason"] is None
        assert factors["cves"] == []  # JSON empty array, NOT null

    def test_cves_none_with_reason_serializes_as_unavailable(self, tmp_path):
        from claude_monitoring.attack_surface.cves.types import CVEResult, UnavailableReason

        cve = CVEResult(cves=None, reason=UnavailableReason.RATE_LIMITED)
        asset = _make_asset("rate-limited-pkg", "python-packages")
        factors = self._make_orch_with_result(tmp_path, asset, self._good_result(), cve)
        assert factors["cve_status"] == "unavailable"
        assert factors["cve_unavailable_reason"] == "rate_limited"
        assert factors["cves"] is None  # JSON null

    def test_cves_none_with_no_reason_serializes_as_not_applicable(self, tmp_path):
        """Non-PyPI/non-npm source → CVEResult(cves=None, reason=None).
        Must serialize as not_applicable, NEVER as unavailable. Ollama
        models / MCP servers / homebrew formulas must never look like a
        feed outage in the dashboard."""
        from claude_monitoring.attack_surface.cves.types import CVEResult

        cve = CVEResult(cves=None, reason=None)
        asset = _make_asset("ollama-model", "ollama-models", package=None, version=None, ecosystem=None)
        factors = self._make_orch_with_result(tmp_path, asset, self._good_result(), cve)
        assert factors["cve_status"] == "not_applicable"
        assert factors["cve_unavailable_reason"] is None
        assert factors["cves"] is None

    def test_no_cve_result_at_all_also_not_applicable(self, tmp_path):
        """When CVE dispatcher wasn't called for an asset at all (e.g.,
        the dispatcher returns nothing for skipped sources), persistence
        still has to serialize a defined cve_status. not_applicable is
        the floor."""
        asset = _make_asset("no-cve-pass", "homebrew-ai-tools", package=None, version=None, ecosystem=None)
        factors = self._make_orch_with_result(tmp_path, asset, self._good_result(), None)
        assert factors["cve_status"] == "not_applicable"
        assert factors["cves"] is None


# ---------------------------------------------------------------------------
# Amendment D — weights + schema_version
# ---------------------------------------------------------------------------


class TestRiskFactorsSchema:
    """JSON schema for `risk_factors` matches the spec §10 amendment
    text verbatim. Amendment D + Rajan D rider."""

    def test_risk_factors_carries_weights(self, tmp_path):
        from claude_monitoring.attack_surface.cves.types import CVEResult
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        result = RiskScoreResult(
            final_score=20,
            band=RiskBand.LOW,
            factors=RiskFactors(0.0, 9.0, 0.0, 0.0),
            contributions={"permission_breadth": 9.0},
            weights={"max_cve_severity": 0.35, "permission_breadth": 0.30},
            applied_rules=[],
            applied_reputation=[],
        )
        cve = CVEResult(cves=[])
        asset = _make_asset("with-weights", "python-packages")
        conn = _setup_assets_db(tmp_path)
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        with patch.object(orch, "_score_assets", return_value={asset.id: (result, cve, _NO_TAGS)}):
            orch.scan(trigger="on_demand")
        row = conn.execute("SELECT risk_factors FROM assets WHERE id = ?", (asset.id,)).fetchone()
        factors = json.loads(row[0])
        assert "weights" in factors
        assert factors["weights"]["max_cve_severity"] == 0.35
        assert factors["weights"]["permission_breadth"] == 0.30

    def test_risk_factors_carries_schema_version_1(self, tmp_path):
        from claude_monitoring.attack_surface.cves.types import CVEResult
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        result = RiskScoreResult(
            final_score=10,
            band=RiskBand.LOW,
            factors=RiskFactors(0.0, 0.0, 0.0, 0.0),
            contributions={},
            weights={},
            applied_rules=[],
            applied_reputation=[],
        )
        cve = CVEResult(cves=[])
        asset = _make_asset("v1-schema", "python-packages")
        conn = _setup_assets_db(tmp_path)
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        with patch.object(orch, "_score_assets", return_value={asset.id: (result, cve, _NO_TAGS)}):
            orch.scan(trigger="on_demand")
        row = conn.execute("SELECT risk_factors FROM assets WHERE id = ?", (asset.id,)).fetchone()
        factors = json.loads(row[0])
        assert factors["schema_version"] == 1

    def test_risk_factors_has_all_required_top_level_keys(self, tmp_path):
        """The spec §10 schema fixes these keys at v1. Future schema_version
        bumps may add/remove; this test pins v1."""
        from claude_monitoring.attack_surface.cves.types import CVEResult
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        result = RiskScoreResult(
            final_score=10,
            band=RiskBand.LOW,
            factors=RiskFactors(0.0, 0.0, 0.0, 0.0),
            contributions={},
            weights={},
            applied_rules=[],
            applied_reputation=[],
        )
        cve = CVEResult(cves=[])
        asset = _make_asset("schema-keys", "python-packages")
        conn = _setup_assets_db(tmp_path)
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        with patch.object(orch, "_score_assets", return_value={asset.id: (result, cve, _NO_TAGS)}):
            orch.scan(trigger="on_demand")
        row = conn.execute("SELECT risk_factors FROM assets WHERE id = ?", (asset.id,)).fetchone()
        factors = json.loads(row[0])
        for key in (
            "schema_version",
            "contributions",
            "weights",
            "applied_rules",
            "applied_reputation",
            "cves",
            "cve_status",
            "cve_unavailable_reason",
        ):
            assert key in factors, f"spec §10 v1 schema requires `{key}`"


# ---------------------------------------------------------------------------
# Drift §3 reversal — UPSERT now writes the four orchestrator-owned columns
# ---------------------------------------------------------------------------


class TestPersistAssetsWritesScoringColumns:
    """`_persist_assets` writes risk_score + risk_band + risk_factors +
    ontology_tags. Reverses the drift §3 docstring on orchestrator.py:360."""

    def test_ontology_tags_column_is_populated(self, tmp_path):
        from claude_monitoring.attack_surface.cves.types import CVEResult
        from claude_monitoring.attack_surface.risk.bands import RiskBand
        from claude_monitoring.attack_surface.risk.scoring import (
            RiskFactors,
            RiskScoreResult,
        )

        result = RiskScoreResult(
            final_score=10,
            band=RiskBand.LOW,
            factors=RiskFactors(0.0, 0.0, 0.0, 0.0),
            contributions={},
            weights={},
            applied_rules=[],
            applied_reputation=[],
        )
        cve = CVEResult(cves=[])
        asset = _make_asset("ontology-pop", "python-packages")
        conn = _setup_assets_db(tmp_path)
        orch = DiscoveryOrchestrator(
            sources=[_PackageSource([asset])],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        # Tags flow through `_score_assets`'s third tuple element after the
        # 2026-06-11 code-reviewer fix — persistence no longer calls
        # `map_asset` itself, so passing the desired tag set here is enough.
        tags = frozenset({OntologyCategory.NETWORK_UNRESTRICTED})
        with patch.object(orch, "_score_assets", return_value={asset.id: (result, cve, tags)}):
            orch.scan(trigger="on_demand")
        row = conn.execute("SELECT ontology_tags FROM assets WHERE id = ?", (asset.id,)).fetchone()
        assert row is not None
        assert row[0] is not None
        tags_list = json.loads(row[0])
        assert OntologyCategory.NETWORK_UNRESTRICTED.value in tags_list
