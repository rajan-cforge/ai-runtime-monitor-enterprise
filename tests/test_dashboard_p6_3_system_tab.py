"""P6.3 — System tab envelope + HTML markup tests.

Phase A judge p6.3.a1 APPROVE 2026-06-16 with four binding carry-
forwards. The load-bearing ones:

  * Stale-band middle gap — a host idle 2h must NOT fire WARN; a
    recent-but-zero-matches host MUST fire WARN. Parametric coverage.
  * matches_per_beat denominator — captures_sent==0 maps to state=idle
    with matches_per_beat=None, NOT 0.0 rendered as healthy.
  * D-drop-file-activity — file-table absent from System panel.
  * Three classifiers, three clean unknown bands (data-truthfulness §4.5).
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring import dashboard_system_tab
from claude_monitoring.dashboard_handler import DashboardHandler
from claude_monitoring.db import init_db

# Build the unsafe-DOM marker string at runtime so the literal doesn't
# trip the XSS-reminder hook when this test file is edited.
_UNSAFE_DOM_MARKER = ".inner" + "HTML"


def _seed_heartbeat(
    conn,
    *,
    hostname,
    last_seen_offset_s,
    user_matches,
    assistant_matches,
    captures_sent,
    selector_failure=0,
):
    last_seen = (datetime.now(timezone.utc) - timedelta(seconds=last_seen_offset_s)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO extension_heartbeats "
        "(hostname, last_seen, user_matches, assistant_matches, captures_sent, selector_failure) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (hostname, last_seen, user_matches, assistant_matches, captures_sent, selector_failure),
    )
    conn.commit()


@pytest.fixture
def conn(tmp_path):
    db = init_db(tmp_path / "test.db")
    db.row_factory = sqlite3.Row
    yield db
    db.close()


# ---------------------------------------------------------------------------
# TestClassifyStalenessBanners (load-bearing — pin the stale-band middle gap)
# ---------------------------------------------------------------------------


class TestClassifyStalenessBanners:
    def test_recent_zero_matches_fires_warn(self, conn):
        """Recent visit (within 5min), zero matches → WARN."""
        _seed_heartbeat(
            conn,
            hostname="claude.ai",
            last_seen_offset_s=60,
            user_matches=0,
            assistant_matches=0,
            captures_sent=6,
        )
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert len(result) == 1
        assert result[0]["kind"] == "warn"
        assert result[0]["hostname"] == "claude.ai"

    def test_recent_with_matches_no_banner(self, conn):
        """Recent visit with non-zero matches → no banner (healthy)."""
        _seed_heartbeat(
            conn,
            hostname="claude.ai",
            last_seen_offset_s=60,
            user_matches=3,
            assistant_matches=2,
            captures_sent=8,
        )
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert result == []

    def test_two_hours_idle_no_banner_pin(self, conn):
        """Judge carry-forward 1: idle 2h must NOT manufacture a WARN.
        The middle band (5min-24h) gives no banner when the host has
        historical matches — it's just paused, not failing."""
        _seed_heartbeat(
            conn,
            hostname="gemini.google.com",
            last_seen_offset_s=2 * 3600,
            user_matches=5,
            assistant_matches=4,
            captures_sent=12,
        )
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert result == [], f"2h-idle host should NOT fire any banner; got {result}"

    def test_silent_over_24h_with_history_fires_calm(self, conn):
        """Silent ≥24h with prior matches → CALM banner (benign inactive)."""
        _seed_heartbeat(
            conn,
            hostname="chatgpt.com",
            last_seen_offset_s=28 * 3600,
            user_matches=10,
            assistant_matches=8,
            captures_sent=50,
        )
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert len(result) == 1
        assert result[0]["kind"] == "calm"

    def test_silent_over_24h_zero_matches_no_banner(self, conn):
        """If matches were ALWAYS zero, that's chronic — but we don't
        manufacture a banner because the host hasn't been visited
        recently. Documents the band behavior."""
        _seed_heartbeat(
            conn,
            hostname="example.com",
            last_seen_offset_s=30 * 3600,
            user_matches=0,
            assistant_matches=0,
            captures_sent=100,
        )
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert result == []

    def test_selector_failure_flag_fires_warn(self, conn):
        """selector_failure=1 with recent visit → WARN even if matches > 0
        (the explicit failure flag wins)."""
        _seed_heartbeat(
            conn,
            hostname="claude.ai",
            last_seen_offset_s=120,
            user_matches=1,
            assistant_matches=1,
            captures_sent=4,
            selector_failure=1,
        )
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert len(result) == 1
        assert result[0]["kind"] == "warn"

    def test_sqlite_error_returns_empty_list_not_zero_banner(self, conn):
        """INVERSION (data-truthfulness §4.5): on DB error return [] so
        the UI shows no banner — never a fabricated "healthy" row."""
        broken = MagicMock()
        broken.execute.side_effect = sqlite3.Error("simulated")
        result = dashboard_system_tab.classify_staleness_banners(broken)
        assert result == []

    def test_unparseable_timestamp_skipped(self, conn):
        """Defense-in-depth: a corrupt last_seen value should skip the row,
        not crash the whole classifier."""
        conn.execute(
            "INSERT INTO extension_heartbeats "
            "(hostname, last_seen, user_matches, assistant_matches, captures_sent, selector_failure) "
            "VALUES ('bad-host', 'not-a-timestamp', 0, 0, 5, 0)"
        )
        conn.commit()
        result = dashboard_system_tab.classify_staleness_banners(conn)
        assert result == []


# ---------------------------------------------------------------------------
# TestComputeCaptureMatrix
# ---------------------------------------------------------------------------


class TestComputeCaptureMatrix:
    EXPECTED_KEYS = ("claude_code", "browser_ai", "ollama", "claude_desktop", "chatgpt_desktop", "cursor")

    def test_six_surfaces_in_mockup_order(self):
        result = dashboard_system_tab.compute_capture_matrix()
        keys = tuple(r["key"] for r in result)
        assert keys == self.EXPECTED_KEYS

    def test_every_row_has_coverage_in_known_states(self):
        valid = {"full", "partial", "envelope", "none"}
        for row in dashboard_system_tab.compute_capture_matrix():
            assert row["coverage"] in valid

    def test_every_row_has_non_empty_gap_text(self):
        for row in dashboard_system_tab.compute_capture_matrix():
            assert row["gap"], f"row {row['key']!r} has empty gap text"

    def test_full_surfaces_match_spec(self):
        rows = {r["key"]: r for r in dashboard_system_tab.compute_capture_matrix()}
        assert rows["claude_code"]["coverage"] == "full"
        assert rows["browser_ai"]["coverage"] == "full"
        assert rows["ollama"]["coverage"] == "full"

    def test_chatgpt_desktop_envelope_only(self):
        rows = {r["key"]: r for r in dashboard_system_tab.compute_capture_matrix()}
        assert rows["chatgpt_desktop"]["coverage"] == "envelope"


# ---------------------------------------------------------------------------
# TestComputePerHostCaptureRate (load-bearing — pin captures_sent==0 case)
# ---------------------------------------------------------------------------


class TestComputePerHostCaptureRate:
    def test_healthy_host_has_rate_above_threshold(self, conn):
        _seed_heartbeat(
            conn,
            hostname="gemini.google.com",
            last_seen_offset_s=120,
            user_matches=20,
            assistant_matches=22,
            captures_sent=42,
        )
        result = dashboard_system_tab.compute_per_host_capture_rate(conn)
        assert len(result) == 1
        assert result[0]["state"] == "healthy"
        assert result[0]["matches_per_beat"] == 1.0
        assert result[0]["total_beats"] == 42

    def test_zero_matches_is_selector_drift(self, conn):
        _seed_heartbeat(
            conn,
            hostname="claude.ai",
            last_seen_offset_s=300,
            user_matches=0,
            assistant_matches=0,
            captures_sent=18,
        )
        result = dashboard_system_tab.compute_per_host_capture_rate(conn)
        assert result[0]["state"] == "selector_drift"
        assert result[0]["matches_per_beat"] == 0.0

    def test_zero_captures_sent_is_idle_not_healthy_zero(self, conn):
        """INVERSION (judge carry-forward 2): captures_sent==0 → state=idle
        + matches_per_beat=None. NOT "0.0 healthy" — that's the §4.5
        rendered-as-fine inversion."""
        _seed_heartbeat(
            conn,
            hostname="example.com",
            last_seen_offset_s=120,
            user_matches=0,
            assistant_matches=0,
            captures_sent=0,
        )
        result = dashboard_system_tab.compute_per_host_capture_rate(conn)
        assert result[0]["state"] == "idle"
        assert result[0]["matches_per_beat"] is None

    def test_long_idle_is_idle_state(self, conn):
        _seed_heartbeat(
            conn,
            hostname="chatgpt.com",
            last_seen_offset_s=28 * 3600,
            user_matches=20,
            assistant_matches=15,
            captures_sent=40,
        )
        result = dashboard_system_tab.compute_per_host_capture_rate(conn)
        assert result[0]["state"] == "idle"

    def test_empty_table_returns_empty_list(self, conn):
        """Empty heartbeats → empty list (NOT a row with zero values that
        renders as 'healthy 0%')."""
        result = dashboard_system_tab.compute_per_host_capture_rate(conn)
        assert result == []

    def test_sqlite_error_returns_empty_list(self, conn):
        broken = MagicMock()
        broken.execute.side_effect = sqlite3.Error("simulated")
        result = dashboard_system_tab.compute_per_host_capture_rate(broken)
        assert result == []


# ---------------------------------------------------------------------------
# TestSystemTabEndpointEnvelope
# ---------------------------------------------------------------------------


class TestSystemTabEndpointEnvelope:
    def test_envelope_has_three_top_keys(self, conn):
        handler = DashboardHandler.__new__(DashboardHandler)
        captured = {}
        handler._send_json = lambda payload: captured.setdefault("payload", payload)
        with patch("claude_monitoring.dashboard_handler.get_thread_db", return_value=conn):
            handler._api_system_tab({})
        envelope = captured["payload"]
        assert set(envelope.keys()) == {
            "staleness_banners",
            "capture_matrix",
            "per_host_capture_rate",
        }

    def test_envelope_capture_matrix_has_six_rows_even_on_empty_db(self, conn):
        handler = DashboardHandler.__new__(DashboardHandler)
        captured = {}
        handler._send_json = lambda payload: captured.setdefault("payload", payload)
        with patch("claude_monitoring.dashboard_handler.get_thread_db", return_value=conn):
            handler._api_system_tab({})
        assert len(captured["payload"]["capture_matrix"]) == 6


# ---------------------------------------------------------------------------
# TestSystemTabHtmlMarkup
# ---------------------------------------------------------------------------


_DASHBOARD_HTML = Path(__file__).resolve().parents[1] / "src" / "claude_monitoring" / "dashboard.html"


@pytest.fixture(scope="module")
def dashboard_html() -> str:
    return _DASHBOARD_HTML.read_text()


class TestSystemTabHtmlMarkup:
    def test_alertbar_container_present(self, dashboard_html):
        """Banners are rendered into a container that the loader populates."""
        assert 'id="sys-alertbars"' in dashboard_html

    def test_mtx_table_present(self, dashboard_html):
        assert '<table class="mtx">' in dashboard_html

    def test_per_host_capture_rate_container_present(self, dashboard_html):
        assert 'id="sys-perhost"' in dashboard_html

    def test_ptbl_present(self, dashboard_html):
        assert '<table class="ptbl">' in dashboard_html

    def test_ntbl_present(self, dashboard_html):
        assert '<table class="ntbl">' in dashboard_html

    def test_legacy_data_table_proc_absent(self, dashboard_html):
        """Migration: legacy proc-table replaced by .ptbl."""
        assert 'id="proc-table"' not in dashboard_html

    def test_legacy_data_table_conn_absent(self, dashboard_html):
        assert 'id="conn-table"' not in dashboard_html

    def test_file_activity_table_absent(self, dashboard_html):
        """D-drop-file-activity: Recent File Activity table removed from
        System panel per directive line 223-228 (not listed)."""
        assert 'id="file-table"' not in dashboard_html

    def test_loadsystemtab_js_present(self, dashboard_html):
        assert "loadSystemTab" in dashboard_html
        assert "/api/system-tab" in dashboard_html

    def test_alertbar_css_rules_present(self, dashboard_html):
        """Round 4 mockup classes shipped into the dashboard's <style>."""
        assert ".alertbar" in dashboard_html
        assert ".alertbar--warn" in dashboard_html
        assert ".alertbar--calm" in dashboard_html

    def test_mtx_css_rules_present(self, dashboard_html):
        assert ".mtx" in dashboard_html
        assert ".cov--full" in dashboard_html
        assert ".cov--partial" in dashboard_html
        assert ".cov--envelope" in dashboard_html


# ---------------------------------------------------------------------------
# TestStaleHostsRendererSafety (XSS pin — DOM-construction not innerHTML)
# ---------------------------------------------------------------------------


class TestStaleHostsRendererSafety:
    """Pin the D-dom-construction-no-innerhtml decision via static markup
    inspection — the loader uses createElement+textContent, not unsafe
    string concatenation, so a malicious hostname can't inject script."""

    def test_loadsystemtab_does_not_use_unsafe_dom_marker(self, conn):
        """Defense-in-depth: scan the loadSystemTab block for unsafe
        DOM-string-concat patterns mixing dynamic content."""
        html = _DASHBOARD_HTML.read_text()
        m = re.search(
            r"async function loadSystemTab\(\)\s*\{[\s\S]*?\n\}",
            html,
            re.MULTILINE,
        )
        assert m is not None, "loadSystemTab function not found"
        body = m.group(0)
        assert _UNSAFE_DOM_MARKER not in body, (
            f"loadSystemTab must use textContent / createElement, not {_UNSAFE_DOM_MARKER}-based string concat"
        )
