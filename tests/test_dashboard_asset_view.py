"""TDD red-phase tests for the dashboard-asset-view PR.

Pins the contract Rajan ratified 2026-06-11:
  * `/api/assets` — limit/offset pagination (default 200/0)
  * Sort: `risk_score DESC NULLS LAST, last_scanned DESC`
  * Filters: `risk_band`, `source`
  * Header carries `unscored_count` (the NULLS LAST rider — operators
    must see how many assets sit below page-one's score-sorted tail)
  * Server-side `cve_status_hint` rendering — dashboard JS NEVER
    re-derives the per-state mapping
  * `/api/asset/<id>` — detail view with parsed `risk_factors` JSON
  * Auth gate inherited from `_check_auth` (covered separately by
    test_security_hardening); this file uses `DISABLE_DASHBOARD_AUTH=1`
    same as other API tests.
"""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import urlopen

import pytest

from claude_monitoring.db import init_db

# ---------------------------------------------------------------------------
# Fixtures — assets table populated with all render states
# ---------------------------------------------------------------------------


def _setup_asset_db(tmp_path):
    """Build a temp DB with assets covering every state the renderer cares
    about: each risk_band, each cve_status, NULL risk_score (scored-fail),
    multiple sources for the filter test."""
    db_path = tmp_path / "test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    conn = init_db(db_path)

    rows = [
        # (id, name, source, version, score, band, cve_status, cves, reason, scanned)
        (
            "a1-critical-vulns",
            "evil-pkg",
            "python-packages",
            "1.0.0",
            95,
            "critical",
            "ok",
            [{"id": "GHSA-x", "cvss": 9.8}],
            None,
            1000.0,
        ),
        ("a2-high-exfil", "talosai", "mcp-servers", None, 70, "high", "not_applicable", None, None, 999.0),
        (
            "a3-medium-unavail",
            "rate-limited-pkg",
            "python-packages",
            "2.0.0",
            45,
            "medium",
            "unavailable",
            None,
            "rate_limited",
            998.0,
        ),
        ("a4-low-clean", "clean-pkg", "node-packages", "3.0.0", 25, "low", "ok", [], None, 997.0),
        ("a5-info-no-perms", "llama3", "ollama-models", "8b", 0, "info", "not_applicable", None, None, 996.0),
        ("a6-unscored", "scoring-failed", "python-packages", "1.5.0", None, None, None, None, None, 995.0),
    ]

    for aid, name, source, version, score, band, cve_status, cves, reason, scanned in rows:
        risk_factors = None
        if cve_status is not None:
            risk_factors = json.dumps(
                {
                    "schema_version": 1,
                    "contributions": {
                        "max_cve_severity": float(score or 0),
                        "permission_breadth": 0.0,
                        "integration_sensitivity": 0.0,
                        "activity_recency": 0.0,
                    },
                    "weights": {
                        "max_cve_severity": 0.35,
                        "permission_breadth": 0.30,
                        "integration_sensitivity": 0.20,
                        "activity_recency": 0.15,
                    },
                    "applied_rules": [],
                    "applied_reputation": [],
                    "cves": cves,
                    "cve_status": cve_status,
                    "cve_unavailable_reason": reason,
                }
            )
        conn.execute(
            """INSERT INTO assets (id, type, name, version, source, first_seen, last_seen,
                                   last_scanned, current_state, ontology_tags,
                                   risk_score, risk_band, risk_factors)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                aid,
                "ai_tool",
                name,
                version,
                source,
                scanned,
                scanned,
                scanned,
                json.dumps({"package_name": name}),
                json.dumps(["secrets_access"]) if band in ("high", "critical") else json.dumps([]),
                score,
                band,
                risk_factors,
            ),
        )
    conn.commit()
    conn.close()
    return db_path, output_dir


@pytest.fixture()
def api_server(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path, output_dir = _setup_asset_db(tmp_path)
    with (
        patch("claude_monitoring.monitor.DB_PATH", db_path),
        patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
        patch("claude_monitoring.config.get_db_path", return_value=db_path),
        patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
        patch("claude_monitoring.db.get_db_path", return_value=db_path),
        patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
    ):
        from claude_monitoring.monitor import DashboardHandler

        server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{port}"
        server.shutdown()


# ---------------------------------------------------------------------------
# List endpoint contract
# ---------------------------------------------------------------------------


class TestAssetsListEndpoint:
    def test_route_exists_and_returns_json(self, api_server):
        resp = urlopen(f"{api_server}/api/assets")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "rows" in data
        assert isinstance(data["rows"], list)

    def test_envelope_shape(self, api_server):
        resp = urlopen(f"{api_server}/api/assets")
        data = json.loads(resp.read())
        for key in ("rows", "total", "limit", "offset", "unscored_count"):
            assert key in data, f"asset list envelope must carry `{key}`"

    def test_unscored_count_reports_null_risk_score_assets(self, api_server):
        """Sort rider (Rajan 2026-06-11): operators must see how many
        assets sit in the NULL-risk_score tail that `NULLS LAST` hides."""
        resp = urlopen(f"{api_server}/api/assets")
        data = json.loads(resp.read())
        assert data["unscored_count"] == 1, "fixture has exactly 1 NULL-risk_score asset"

    def test_default_sort_is_risk_score_desc_nulls_last(self, api_server):
        resp = urlopen(f"{api_server}/api/assets")
        data = json.loads(resp.read())
        scores = [r.get("risk_score") for r in data["rows"]]
        # Scored rows first, descending; NULL last.
        scored = [s for s in scores if s is not None]
        assert scored == sorted(scored, reverse=True), "scored rows must sort risk_score DESC"
        if None in scores:
            assert scores.index(None) >= len(scored), "NULL rows must come after all scored rows"

    def test_default_limit_is_200(self, api_server):
        resp = urlopen(f"{api_server}/api/assets")
        data = json.loads(resp.read())
        assert data["limit"] == 200

    def test_explicit_limit_respected(self, api_server):
        resp = urlopen(f"{api_server}/api/assets?limit=2")
        data = json.loads(resp.read())
        assert data["limit"] == 2
        assert len(data["rows"]) == 2

    def test_explicit_offset_respected(self, api_server):
        resp = urlopen(f"{api_server}/api/assets?limit=2&offset=2")
        data = json.loads(resp.read())
        assert data["offset"] == 2
        # Should be the 3rd + 4th by score: a3-medium-unavail (45), a4-low-clean (25)
        ids = [r["id"] for r in data["rows"]]
        assert ids == ["a3-medium-unavail", "a4-low-clean"]

    def test_filter_by_risk_band(self, api_server):
        resp = urlopen(f"{api_server}/api/assets?risk_band=high")
        data = json.loads(resp.read())
        ids = [r["id"] for r in data["rows"]]
        assert ids == ["a2-high-exfil"], "risk_band filter must narrow to single band"

    def test_filter_by_source(self, api_server):
        resp = urlopen(f"{api_server}/api/assets?source=python-packages")
        data = json.loads(resp.read())
        sources = {r["source"] for r in data["rows"]}
        assert sources == {"python-packages"}
        # Includes the NULL-score one too — source filter is independent of scoring state.
        ids = {r["id"] for r in data["rows"]}
        assert ids == {"a1-critical-vulns", "a3-medium-unavail", "a6-unscored"}

    def test_total_reports_filtered_count(self, api_server):
        """`total` is post-filter pre-pagination; operators need to see
        'showing 2 of 12 matching' counts."""
        resp = urlopen(f"{api_server}/api/assets?source=python-packages&limit=1")
        data = json.loads(resp.read())
        assert data["total"] == 3  # 3 python-packages rows in fixture
        assert len(data["rows"]) == 1  # paginated

    def test_limit_caps_at_1000_to_block_dos(self, api_server):
        """Hot-path DoS guard (code-reviewer 2026-06-11): an authenticated
        caller passing `?limit=10000000` must not be able to fetchall the
        entire table — limit silently snaps down to `_MAX_LIMIT = 1000`."""
        resp = urlopen(f"{api_server}/api/assets?limit=10000000")
        data = json.loads(resp.read())
        assert data["limit"] == 1000, "limit must clamp at 1000, not echo the requested value"

    def test_negative_offset_clamps_to_zero(self, api_server):
        """Defensive: negative offset clamps to 0 so sqlite3 doesn't see
        OFFSET -1 (which it accepts but disables — surprising behaviour)."""
        resp = urlopen(f"{api_server}/api/assets?offset=-5")
        data = json.loads(resp.read())
        assert data["offset"] == 0


# ---------------------------------------------------------------------------
# Server-side cve_status_hint rendering — the ONE call site per C rider
# ---------------------------------------------------------------------------


class TestServerSideCveStatusHint:
    """Per Rajan C rider (2026-06-11) + verdict scan-scoring-callsite.a1
    Finding 3: every row in `/api/assets` MUST carry a server-rendered
    `cve_status_hint` payload (label, severity, tooltip) derived via
    `attack_surface/rendering/cve_status_hints.py`. Dashboard JS never
    re-derives the mapping. One load-bearing call site."""

    def _row_by_id(self, api_server, asset_id):
        resp = urlopen(f"{api_server}/api/assets?limit=200")
        data = json.loads(resp.read())
        for row in data["rows"]:
            if row["id"] == asset_id:
                return row
        raise AssertionError(f"row {asset_id!r} missing")

    def test_ok_with_vulns_renders_warn_high(self, api_server):
        row = self._row_by_id(api_server, "a1-critical-vulns")
        hint = row["cve_status_hint"]
        assert hint["severity"] == "warn-high"
        assert "known vuln" in hint["label"].lower()

    def test_not_applicable_renders_neutral_dash(self, api_server):
        row = self._row_by_id(api_server, "a2-high-exfil")
        hint = row["cve_status_hint"]
        assert hint["severity"] == "neutral"
        assert hint["label"] == "—"

    def test_unavailable_renders_with_reason(self, api_server):
        row = self._row_by_id(api_server, "a3-medium-unavail")
        hint = row["cve_status_hint"]
        assert hint["severity"] == "warn-low"
        assert "rate" in hint["label"].lower() or "limit" in hint["label"].lower()

    def test_ok_empty_renders_info_no_known_vulns(self, api_server):
        row = self._row_by_id(api_server, "a4-low-clean")
        hint = row["cve_status_hint"]
        assert hint["severity"] == "info"
        assert "no known" in hint["label"].lower()

    def test_null_risk_score_renders_not_yet_scored_hint(self, api_server):
        """The NULL-risk_score row must carry a distinct `risk_score_hint`
        so the dashboard renders "not yet scored" — NOT a 0 score, NOT a
        band badge, NOT the same as INFO."""
        row = self._row_by_id(api_server, "a6-unscored")
        assert row["risk_score"] is None
        assert row["risk_band"] is None
        hint = row["risk_score_hint"]
        assert hint is not None
        assert "not yet scored" in hint["label"].lower()
        assert hint["severity"] == "neutral"

    def test_scored_assets_have_null_risk_score_hint(self, api_server):
        """Scored rows (risk_score is int) get `risk_score_hint = null`;
        the row's own risk badge renders the band/score directly."""
        row = self._row_by_id(api_server, "a1-critical-vulns")
        assert row["risk_score_hint"] is None

    def test_amendment_c_invariant_not_applicable_neq_unavailable(self, api_server):
        """Spec §6.10 / Amendment C: 'doesn't apply' and 'unavailable'
        must NEVER share a label. Verified end-to-end via the endpoint."""
        na = self._row_by_id(api_server, "a2-high-exfil")["cve_status_hint"]
        ua = self._row_by_id(api_server, "a3-medium-unavail")["cve_status_hint"]
        assert na["label"] != ua["label"]


# ---------------------------------------------------------------------------
# Detail endpoint
# ---------------------------------------------------------------------------


class TestAssetDetailEndpoint:
    def test_detail_route_exists(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/a1-critical-vulns")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["id"] == "a1-critical-vulns"

    def test_detail_unknown_id_returns_404(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc:
            urlopen(f"{api_server}/api/asset/does-not-exist")
        assert exc.value.code == 404

    def test_detail_returns_parsed_risk_factors(self, api_server):
        """Detail view exposes the full `risk_factors` JSON so the popover
        can render contributions / weights / applied_rules /
        applied_reputation / cves with no second lookup."""
        resp = urlopen(f"{api_server}/api/asset/a1-critical-vulns")
        data = json.loads(resp.read())
        assert "risk_factors" in data
        rf = data["risk_factors"]
        # Parsed object, NOT a JSON string — UI shouldn't re-parse.
        assert isinstance(rf, dict)
        assert rf["schema_version"] == 1
        assert rf["cve_status"] == "ok"
        assert isinstance(rf["weights"], dict)

    def test_detail_includes_cve_status_hint(self, api_server):
        """Detail view also carries the server-rendered hint so the
        popover header can use the same label as the list row."""
        resp = urlopen(f"{api_server}/api/asset/a3-medium-unavail")
        data = json.loads(resp.read())
        hint = data["cve_status_hint"]
        assert hint["severity"] == "warn-low"

    def test_detail_includes_ontology_tags_list(self, api_server):
        """Tags persist as JSON in the DB; the API parses them so JS
        renders chips directly without a second JSON.parse."""
        resp = urlopen(f"{api_server}/api/asset/a2-high-exfil")
        data = json.loads(resp.read())
        assert isinstance(data["ontology_tags"], list)
        assert "secrets_access" in data["ontology_tags"]


# ---------------------------------------------------------------------------
# Route registration — load-bearing pin so a future refactor cannot
# silently un-register the new endpoint
# ---------------------------------------------------------------------------


class TestRouteRegistration:
    def test_assets_route_in_routes_dict(self):
        """A future refactor of `do_GET` dispatch must keep `/api/assets`
        as a registered route. We pin by importing the handler class and
        instantiating a stripped instance to inspect the routes table."""
        from claude_monitoring.monitor import DashboardHandler

        # The routes dict is built inside do_GET; the safer pin is to
        # check the *_api_assets handler attribute exists.
        assert hasattr(DashboardHandler, "_api_assets"), "DashboardHandler must expose _api_assets handler method"
        assert hasattr(DashboardHandler, "_api_asset_detail"), (
            "DashboardHandler must expose _api_asset_detail handler method"
        )
