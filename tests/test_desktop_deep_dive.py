# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for desktop session activity summary enrichment.

Desktop synthetic sessions (``desktop_claude_desktop``,
``desktop_chatgpt_desktop``, ``desktop_cursor_desktop``) surface
aggregated network activity instead of conversation content — the
proxy captures every request/response envelope for these apps but
cannot parse SSE/protobuf bodies, so content capture is the browser
extension's job, not the proxy's.

These tests verify that ``_api_session_detail`` returns the
``activity_summary`` dict (totals, daily breakdown, peak hour, top
hosts) and the ``traffic_captured`` flag used by the dashboard to
branch between "show the summary" and "show the configure-proxy
hint" (Cursor path).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from urllib.request import urlopen

import pytest

from claude_monitoring.db import init_db


@pytest.fixture()
def desktop_server(tmp_path, monkeypatch):
    """Spin up a DashboardHandler with a fresh DB."""
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path = tmp_path / "monitor.db"
    init_db(db_path).close()

    monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
    monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
    monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
    monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
    from claude_monitoring import monitor as mon

    monkeypatch.setattr(mon, "DB_PATH", db_path)
    monkeypatch.setattr(mon, "OUTPUT_DIR", tmp_path)

    server = HTTPServer(("127.0.0.1", 0), mon.DashboardHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", db_path
    server.shutdown()


def _get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode())


def _seed_desktop_session(db_path, agent_type: str = "claude_desktop") -> str:
    session_id = f"desktop_{agent_type}"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """INSERT INTO sessions
           (session_id, agent_type, start_time, last_activity, total_turns,
            total_input_tokens, total_output_tokens)
           VALUES (?, ?, ?, ?, 0, 0, 0)""",
        (
            session_id,
            agent_type,
            datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    return session_id


def _insert_api_call(
    db_path,
    service: str,
    *,
    host: str = "claude.ai",
    timestamp: str | None = None,
    req_bytes: int = 1500,
    resp_bytes: int = 4000,
    latency_ms: int = 200,
    path: str = "/api/organizations/x/chat_conversations",
) -> None:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """INSERT INTO api_calls
           (timestamp, destination_host, destination_service, endpoint_path,
            http_method, http_status, model, input_tokens, output_tokens,
            latency_ms, request_size_bytes, response_size_bytes)
           VALUES (?, ?, ?, ?, 'POST', 200, '', 0, 0, ?, ?, ?)""",
        (ts, host, service, path, latency_ms, req_bytes, resp_bytes),
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────


class TestDesktopActivitySummary:
    def test_claude_desktop_returns_activity_summary(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        for _ in range(5):
            _insert_api_call(db_path, "claude_web", host="claude.ai")

        data = _get_json(f"{base}/api/session/{session_id}")
        assert data["is_desktop_session"] is True
        assert data["traffic_captured"] is True
        summary = data["activity_summary"]
        assert summary["total_calls"] == 5
        assert summary["bytes_up"] == 5 * 1500
        assert summary["bytes_down"] == 5 * 4000
        assert summary["avg_latency_ms"] == 200

    def test_chatgpt_desktop_matches_chatgpt_hosts(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "chatgpt_desktop")
        _insert_api_call(db_path, "chatgpt_web", host="chatgpt.com")
        _insert_api_call(db_path, "openai_api", host="api.openai.com")

        data = _get_json(f"{base}/api/session/{session_id}")
        assert data["traffic_captured"] is True
        assert data["activity_summary"]["total_calls"] == 2

    def test_cursor_desktop_no_traffic_sets_traffic_captured_false(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "cursor_desktop")
        # No api_calls for cursor — real-world scenario where Cursor
        # bypasses the system proxy entirely.
        data = _get_json(f"{base}/api/session/{session_id}")
        assert data["is_desktop_session"] is True
        assert data["traffic_captured"] is False
        assert data["activity_summary"]["total_calls"] == 0

    def test_cursor_desktop_captures_cursor_hosts_when_present(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "cursor_desktop")
        # Simulate Cursor configured with proxy — traffic to api2.cursor.sh
        _insert_api_call(db_path, "unknown", host="api2.cursor.sh", path="/v1/completion")

        data = _get_json(f"{base}/api/session/{session_id}")
        assert data["traffic_captured"] is True
        assert data["activity_summary"]["total_calls"] == 1

    def test_daily_breakdown_last_14_days(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        # Insert rows on 3 distinct days
        now = datetime.now(timezone.utc)
        for days_ago, count in [(0, 5), (1, 10), (2, 3)]:
            ts = (now - timedelta(days=days_ago)).isoformat()
            for _ in range(count):
                _insert_api_call(db_path, "claude_web", host="claude.ai", timestamp=ts)

        data = _get_json(f"{base}/api/session/{session_id}")
        daily = data["activity_summary"]["daily"]
        assert len(daily) == 3
        # Newest first
        assert daily[0]["calls"] == 5
        assert daily[1]["calls"] == 10
        assert daily[2]["calls"] == 3

    def test_peak_hour_identifies_busiest_window(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        # 2 calls in hour A, 10 calls in hour B
        for _ in range(2):
            _insert_api_call(db_path, "claude_web", host="claude.ai", timestamp="2026-04-11T10:00:00+00:00")
        for _ in range(10):
            _insert_api_call(db_path, "claude_web", host="claude.ai", timestamp="2026-04-11T20:00:00+00:00")

        data = _get_json(f"{base}/api/session/{session_id}")
        peak = data["activity_summary"]["peak_hour"]
        assert peak is not None
        assert peak["calls"] == 10
        assert peak["hour"].startswith("2026-04-11T20")

    def test_top_hosts_returns_most_frequent(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        for _ in range(5):
            _insert_api_call(db_path, "claude_web", host="claude.ai")
        for _ in range(2):
            _insert_api_call(db_path, "anthropic_api", host="api.anthropic.com")

        data = _get_json(f"{base}/api/session/{session_id}")
        hosts = data["activity_summary"]["top_hosts"]
        assert len(hosts) == 2
        assert hosts[0]["host"] == "claude.ai"
        assert hosts[0]["calls"] == 5
        assert hosts[1]["host"] == "api.anthropic.com"
        assert hosts[1]["calls"] == 2

    def test_non_desktop_session_has_no_activity_summary(self, desktop_server):
        base, db_path = desktop_server
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """INSERT INTO sessions
               (session_id, agent_type, start_time, last_activity, total_turns,
                total_input_tokens, total_output_tokens)
               VALUES ('real-session-1', 'claude_code', ?, ?, 0, 0, 0)""",
            (
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        data = _get_json(f"{base}/api/session/real-session-1")
        assert data.get("is_desktop_session") is not True
        assert "activity_summary" not in data
        assert "traffic_captured" not in data
