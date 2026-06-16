"""P6.2 — state-bar endpoint + markup tests.

Phase A judge p6.2.a2 APPROVE 2026-06-16 with eight ratified
decisions. The two load-bearing inversions:

  * D-alerts-derivation-mirrors-api-alerts — alerts counts MUST be
    derived from `events JOIN alert_dismissals` with severity parsed
    from `data_json` (NOT from a non-existent `alerts` table).
    Query failure surfaces as `None` counts (UI → "—"); empty events
    table surfaces as `0/0` (a true negative).
  * D-no-trigger-filter-on-last-scan — `discovery_runs` last-scan
    query drops the trigger filter so a `cli`-triggered scan
    (P4.6 --discover) shows up as the most-recent.

Plus D-awaiting-data-on-empty for fill-rate (percentage=None when
total=0) and D-path-filter-for-chat-calls (LIKE '/v1/messages%' OR
LIKE '%/chat/completions%').
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring import dashboard_state_bar
from claude_monitoring.dashboard_handler import DashboardHandler
from claude_monitoring.db import init_db


# Helper — seed an api_calls row.
def _seed_api_call(conn, *, endpoint_path, input_tokens, dest_service="claude-api", ts_offset_s=-3600):
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + ts_offset_s))
    conn.execute(
        """INSERT INTO api_calls
           (timestamp, endpoint_path, destination_service, input_tokens, output_tokens,
            destination_host, http_method, http_status)
           VALUES (?, ?, ?, ?, 0, 'api.anthropic.com', 'POST', 200)""",
        (ts_iso, endpoint_path, dest_service, input_tokens),
    )
    conn.commit()


def _seed_sensitive_event(conn, *, severity="medium", dismissed=False, ts_offset_s=-300):
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + ts_offset_s))
    data = json.dumps({"severity": severity, "categories": ["credential"], "confidence": "high"})
    cur = conn.execute(
        """INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json)
           VALUES (?, NULL, 'sensitive_data', 'test', ?)""",
        (ts_iso, data),
    )
    event_id = cur.lastrowid
    if dismissed:
        conn.execute(
            """INSERT INTO alert_dismissals (event_id, dismissed_at, reason)
               VALUES (?, ?, 'test')""",
            (event_id, ts_iso),
        )
    conn.commit()
    return event_id


def _seed_discovery_run(conn, *, trigger, completed_offset_s):
    """completed_offset_s is seconds in the past; pass None for in-progress."""
    started_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 1800))
    if completed_offset_s is None:
        completed_iso = None
    else:
        completed_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - completed_offset_s))
    conn.execute(
        """INSERT INTO discovery_runs
           (started_at, completed_at, trigger, assets_discovered, new_assets,
            removed_assets, new_cves, errors)
           VALUES (?, ?, ?, 0, 0, 0, 0, '[]')""",
        (started_iso, completed_iso, trigger),
    )
    conn.commit()


@pytest.fixture
def conn(tmp_path):
    db = init_db(tmp_path / "test.db")
    db.row_factory = sqlite3.Row
    yield db
    db.close()


# ---------------------------------------------------------------------------
# TestComputeFillRate24h
# ---------------------------------------------------------------------------


class TestComputeFillRate24h:
    """D-path-filter-for-chat-calls: rows match `/v1/messages%' OR
    `%/chat/completions%`."""

    def test_matches_messages_with_query_string(self, conn):
        # Empirical shape from primary laptop's monitor.db:
        # `/v1/messages?beta=true` × 12834 rows.
        _seed_api_call(conn, endpoint_path="/v1/messages?beta=true", input_tokens=42)
        _seed_api_call(conn, endpoint_path="/v1/messages?beta=true", input_tokens=0)
        result = dashboard_state_bar.compute_fill_rate_24h(conn)
        assert result["total"] == 2
        assert result["filled"] == 1
        assert result["percentage"] == 50

    def test_matches_chat_completions(self, conn):
        _seed_api_call(conn, endpoint_path="/v1/chat/completions", input_tokens=10)
        result = dashboard_state_bar.compute_fill_rate_24h(conn)
        assert result["total"] == 1
        assert result["percentage"] == 100

    def test_excludes_non_chat_paths(self, conn):
        # Inversion — paths that AREN'T chat calls must not contribute.
        _seed_api_call(conn, endpoint_path="/v1/usage", input_tokens=99)
        _seed_api_call(conn, endpoint_path="/v1/models", input_tokens=88)
        result = dashboard_state_bar.compute_fill_rate_24h(conn)
        assert result["total"] == 0
        assert result["percentage"] is None  # D-awaiting-data-on-empty

    def test_excludes_rows_outside_24h_window(self, conn):
        # Row older than 24h must not contribute.
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=10, ts_offset_s=-(48 * 3600))
        result = dashboard_state_bar.compute_fill_rate_24h(conn)
        assert result["total"] == 0

    def test_by_service_breakdown(self, conn):
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=1, dest_service="claude-api")
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=0, dest_service="claude-api")
        _seed_api_call(conn, endpoint_path="/v1/chat/completions", input_tokens=5, dest_service="openai-api")
        result = dashboard_state_bar.compute_fill_rate_24h(conn)
        assert result["by_service"]["claude-api"] == {"filled": 1, "total": 2}
        assert result["by_service"]["openai-api"] == {"filled": 1, "total": 1}


# ---------------------------------------------------------------------------
# TestComputeFillRateSparkline7d
# ---------------------------------------------------------------------------


class TestComputeFillRateSparkline7d:
    def test_returns_seven_entries(self, conn):
        result = dashboard_state_bar.compute_fill_rate_sparkline_7d(conn)
        assert len(result) == 7

    def test_zero_call_day_returns_none_not_zero(self, conn):
        # Data-truthfulness: a day with no chat calls is unknown rate,
        # not "0% filled". UI renders None as a zero-height bar
        # without the .now class.
        result = dashboard_state_bar.compute_fill_rate_sparkline_7d(conn)
        assert all(v is None for v in result)

    def test_today_bucket_includes_recent_calls(self, conn):
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=1, ts_offset_s=-60)
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=0, ts_offset_s=-120)
        result = dashboard_state_bar.compute_fill_rate_sparkline_7d(conn)
        # Last entry (today/newest) is 50%; older days are still None.
        assert result[-1] == 50
        assert result[0] is None


# ---------------------------------------------------------------------------
# TestComputeFillRateEmptyDb
# ---------------------------------------------------------------------------


class TestComputeFillRateEmptyDb:
    def test_empty_db_returns_none_percentage_zero_counts(self, conn):
        """D-awaiting-data-on-empty — empty DB is a true negative (the
        scheduler hasn't run yet, or no chat calls yet). percentage=None
        signals the UI to render 'Awaiting data' rather than '0%'."""
        result = dashboard_state_bar.compute_fill_rate_24h(conn)
        assert result["percentage"] is None
        assert result["filled"] == 0
        assert result["total"] == 0
        assert result["by_service"] == {}


# ---------------------------------------------------------------------------
# TestComputeAlertsCounts (load-bearing — pinned by judge a2)
# ---------------------------------------------------------------------------


class TestComputeAlertsCounts:
    """D-alerts-derivation-mirrors-api-alerts: data MUST come from
    `events e LEFT JOIN alert_dismissals d`, severity parsed from
    `data_json` in Python (matches the merged `_api_alerts` derivation
    at dashboard_handler.py:1236)."""

    def test_counts_one_critical_one_medium(self, conn):
        _seed_sensitive_event(conn, severity="critical", dismissed=False)
        _seed_sensitive_event(conn, severity="medium", dismissed=False)
        result = dashboard_state_bar.compute_alerts_counts(conn)
        assert result["critical_count"] == 1
        assert result["total_count"] == 2

    def test_dismissed_events_excluded(self, conn):
        _seed_sensitive_event(conn, severity="critical", dismissed=False)
        _seed_sensitive_event(conn, severity="critical", dismissed=True)
        result = dashboard_state_bar.compute_alerts_counts(conn)
        assert result["critical_count"] == 1
        assert result["total_count"] == 1

    def test_empty_events_table_returns_zero_zero(self, conn):
        """True negative — empty events table is NOT a query failure.
        Returns 0/0 so UI renders '0 critical'. Distinct from the
        sqlite3.Error case below."""
        result = dashboard_state_bar.compute_alerts_counts(conn)
        assert result["critical_count"] == 0
        assert result["total_count"] == 0

    def test_sqlite_error_returns_none_not_zero(self, conn):
        """INVERSION (pinned by judge a2 binding contract): on
        sqlite3.Error the counts MUST be None — never 0. A populated
        security state rendered as clean is the §4.5 inversion the
        contract forbids."""
        broken = MagicMock()
        broken.execute.side_effect = sqlite3.Error("simulated db corruption")
        result = dashboard_state_bar.compute_alerts_counts(broken)
        assert result["critical_count"] is None
        assert result["total_count"] is None

    def test_default_severity_medium_when_data_json_omits_field(self, conn):
        """Mirror _api_alerts: data.get('severity', 'medium') — a row
        whose data_json has no severity field counts as medium (NOT
        critical)."""
        ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        conn.execute(
            """INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json)
               VALUES (?, NULL, 'sensitive_data', 'test', '{}')""",
            (ts_iso,),
        )
        conn.commit()
        result = dashboard_state_bar.compute_alerts_counts(conn)
        assert result["critical_count"] == 0
        assert result["total_count"] == 1


# ---------------------------------------------------------------------------
# TestComputeAttackSurfaceLastScan (load-bearing — pinned by judge a2)
# ---------------------------------------------------------------------------


class TestComputeAttackSurfaceLastScan:
    """D-no-trigger-filter-on-last-scan: discovery_runs query drops the
    trigger filter so cli/scheduled/on_demand scans all surface as
    'most recent completed scan, full stop'."""

    def test_cli_triggered_row_picked_up_as_most_recent(self, conn):
        """Pin against a1's regression: cli is a real trigger (P4.6
        --discover writes trigger='cli') and must NOT be filtered out."""
        _seed_discovery_run(conn, trigger="scheduled", completed_offset_s=86400)  # 1d ago
        _seed_discovery_run(conn, trigger="on_demand", completed_offset_s=7200)  # 2h ago
        _seed_discovery_run(conn, trigger="cli", completed_offset_s=600)  # 10m ago
        result = dashboard_state_bar.compute_attack_surface_last_scan(conn)
        # Newest completion is the cli row (10m ago). If trigger filter
        # were back, this would return the 2h-ago on_demand row.
        assert result["last_scan_ts"] is not None
        import calendar

        last_epoch = calendar.timegm(time.strptime(result["last_scan_ts"][:19], "%Y-%m-%dT%H:%M:%S"))
        age = int(time.time()) - last_epoch
        # cli row was 10m ago — assert within 60s tolerance.
        assert 540 < age < 660, f"expected cli row (~600s old) to win, got age={age}s"

    def test_in_progress_flag_set_when_uncompleted_run_exists(self, conn):
        _seed_discovery_run(conn, trigger="cli", completed_offset_s=300)
        _seed_discovery_run(conn, trigger="scheduled", completed_offset_s=None)
        result = dashboard_state_bar.compute_attack_surface_last_scan(conn)
        assert result["in_progress"] is True
        # Completed scan timestamp still surfaces.
        assert result["last_scan_ts"] is not None

    def test_empty_table_returns_none_not_zero(self, conn):
        result = dashboard_state_bar.compute_attack_surface_last_scan(conn)
        assert result["last_scan_ts"] is None
        assert result["in_progress"] is False


# ---------------------------------------------------------------------------
# TestComputeMonitorStatus
# ---------------------------------------------------------------------------


class TestComputeMonitorStatus:
    def test_capturing_when_recent_api_call(self, conn):
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=1, ts_offset_s=-60)
        result = dashboard_state_bar.compute_monitor_status(conn)
        assert result["status"] == "capturing"
        assert result["last_seen_ts"] is not None

    def test_stopped_when_last_call_old(self, conn):
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=1, ts_offset_s=-7200)
        result = dashboard_state_bar.compute_monitor_status(conn)
        assert result["status"] == "stopped"

    def test_idle_when_empty_db(self, conn):
        result = dashboard_state_bar.compute_monitor_status(conn)
        assert result["status"] == "idle"
        assert result["last_seen_ts"] is None


# ---------------------------------------------------------------------------
# TestStateBarEndpointEnvelope
# ---------------------------------------------------------------------------


class TestStateBarEndpointEnvelope:
    def test_envelope_has_four_top_keys(self, conn):
        """The /api/state-bar response carries the 4-cell envelope
        per directive line 222."""
        # Use a fake handler instance that overrides get_thread_db.
        handler = DashboardHandler.__new__(DashboardHandler)
        captured = {}
        handler._send_json = lambda payload: captured.setdefault("payload", payload)
        with patch("claude_monitoring.dashboard_handler.get_thread_db", return_value=conn):
            handler._api_state_bar({})
        envelope = captured["payload"]
        assert set(envelope.keys()) == {
            "monitor",
            "fill_rate",
            "fill_rate_sparkline_7d",
            "alerts",
            "attack_surface",
        }


# ---------------------------------------------------------------------------
# TestStateBarHtmlMarkup
# ---------------------------------------------------------------------------


_DASHBOARD_HTML = Path(__file__).resolve().parents[1] / "src" / "claude_monitoring" / "dashboard.html"


@pytest.fixture(scope="module")
def dashboard_html() -> str:
    return _DASHBOARD_HTML.read_text()


class TestStateBarHtmlMarkup:
    def test_statebar_present_after_nav(self, dashboard_html):
        assert '<div class="statebar"' in dashboard_html
        # Order: <nav class="v-tabs"> comes BEFORE <div class="statebar">.
        nav_pos = dashboard_html.find('<nav class="v-tabs">')
        bar_pos = dashboard_html.find('<div class="statebar"')
        assert nav_pos < bar_pos, "statebar must come AFTER the v-tabs nav (global, above content)"

    def test_four_sb_cells_plus_grow_spacer(self, dashboard_html):
        # Extract the statebar block (one line for grep simplicity).
        m = re.search(r'<div class="statebar"[^>]*>([\s\S]*?)</div>\s*<!--\s*/statebar\s*-->', dashboard_html)
        assert m is not None, "statebar block not found / missing closing comment marker"
        body = m.group(1)
        sb_cells = re.findall(r'<div class="sb[^"]*"', body)
        assert len(sb_cells) >= 4, f"expected ≥4 .sb cells inside .statebar, got {len(sb_cells)}"
        assert "sb__grow" in body, ".sb__grow spacer absent from statebar"

    def test_sparkline_has_seven_bars_last_is_now(self, dashboard_html):
        # The .spark contains 7 <span> bars; the last carries .now per
        # D-sparkline-7-bars-with-now.
        m = re.search(r'<span class="spark"[^>]*>([\s\S]*?)</span>\s*<!--\s*/spark\s*-->', dashboard_html)
        assert m is not None, "spark block not found / missing closing comment marker"
        body = m.group(1)
        bars = re.findall(r"<span[^>]*></span>", body)
        assert len(bars) == 7, f"sparkline must have exactly 7 bars, got {len(bars)}"
        # Last bar tagged with .now.
        assert re.search(r'<span class="now"[^>]*></span>\s*$', body.strip()) or 'class="now"' in bars[-1], (
            "last sparkline bar must carry .now class"
        )

    def test_volstrip_replaces_legacy_stat_cards(self, dashboard_html):
        assert '<div class="volstrip"' in dashboard_html
        assert '<div class="stats" id="stat-cards">' not in dashboard_html

    def test_volstrip_has_five_vi_items(self, dashboard_html):
        m = re.search(r'<div class="volstrip"[^>]*>([\s\S]*?)</div>', dashboard_html)
        assert m is not None
        body = m.group(1)
        vi_items = re.findall(r'<span class="vi[^"]*"', body)
        assert len(vi_items) == 5, f"D-five-volstrip-items: expected 5 .vi items, got {len(vi_items)}"

    def test_state_bar_loader_js_present(self, dashboard_html):
        assert "loadStateBar" in dashboard_html
        assert "/api/state-bar" in dashboard_html

    def test_awaiting_data_string_present(self, dashboard_html):
        """D-awaiting-data-on-empty — the renderer must have an
        'Awaiting data' code path (so empty DB doesn't show '0%')."""
        assert "Awaiting data" in dashboard_html
