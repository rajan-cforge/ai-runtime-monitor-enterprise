# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for desktop session detail enrichment.

The Session Explorer right-hand panel and the Deep Dive modal for
desktop synthetic sessions (``desktop_claude_desktop``,
``desktop_chatgpt_desktop``, ``desktop_cursor_desktop``) render proxy-
captured conversation content from ``api_calls``. The enrichment
pipeline lives in ``_api_session_detail`` at
``src/claude_monitoring/monitor.py`` — these tests hit the live HTTP
endpoint and verify that:

- Preview fields (user + assistant) round-trip from the DB
- Token / cost / cache / tool-call fields are propagated
- Empty-preview rows (claude_web / chatgpt_web) are still returned so
  the dashboard can show a muted metadata-only row
- ``content_coverage`` counts are accurate
- Non-desktop sessions are unchanged (regression)
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import HTTPServer
from urllib.request import urlopen

import pytest

from claude_monitoring.db import init_db


@pytest.fixture()
def desktop_server(tmp_path, monkeypatch):
    """Spin up a DashboardHandler with a fresh DB.

    Matches the pattern from test_supply_chain_ux.py: disable auth,
    rewire the DB path, start a real HTTPServer on an ephemeral port.
    """
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
    """Create the synthetic session row that desktop sessions use."""
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
    user_preview: str = "",
    assistant_preview: str = "",
    model: str = "claude-sonnet-4-5",
    input_tokens: int = 100,
    output_tokens: int = 50,
    cache_read_tokens: int = 0,
    cost: float = 0.01,
    tool_call_count: int = 0,
    host: str = "api.anthropic.com",
    path: str = "/v1/messages",
) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """INSERT INTO api_calls
           (timestamp, destination_host, destination_service, endpoint_path,
            http_method, http_status, model, input_tokens, output_tokens,
            cache_read_tokens, cache_write_tokens, latency_ms,
            request_size_bytes, response_size_bytes,
            last_user_msg_preview, assistant_msg_preview,
            estimated_cost_usd, tool_call_count)
           VALUES (?, ?, ?, ?, 'POST', 200, ?, ?, ?, ?, 0, 1500, 2000, 4000, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            host,
            service,
            path,
            model,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            user_preview,
            assistant_preview,
            cost,
            tool_call_count,
        ),
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────


class TestDesktopSessionDetail:
    def test_includes_preview_fields(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        _insert_api_call(
            db_path,
            "anthropic_api",
            user_preview="Write a haiku about TLS",
            assistant_preview="TLS flows through pipes, / encrypted whispers travel, / bytes safe in transit.",
        )

        data = _get_json(f"{base}/api/session/{session_id}")
        api_events = [e for e in data["events"] if e["event_type"] == "api_call"]
        assert len(api_events) == 1
        ev = api_events[0]
        assert ev["data"]["user_preview"] == "Write a haiku about TLS"
        assert "TLS flows" in ev["data"]["assistant_preview"]
        assert data["is_desktop_session"] is True

    def test_metadata_only_row_still_returned(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        _insert_api_call(
            db_path,
            "claude_web",
            user_preview="",
            assistant_preview="",
            host="claude.ai",
            path="/api/organizations/x/chat_conversations",
        )

        data = _get_json(f"{base}/api/session/{session_id}")
        api_events = [e for e in data["events"] if e["event_type"] == "api_call"]
        assert len(api_events) == 1
        ev = api_events[0]
        # Keys must be PRESENT (dashboard branches on them), not omitted
        assert ev["data"]["user_preview"] == ""
        assert ev["data"]["assistant_preview"] == ""
        assert ev["data"]["destination_host"] == "claude.ai"

    def test_content_coverage_counts(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        # 2 rows with content (anthropic_api), 3 rows without (claude_web)
        _insert_api_call(db_path, "anthropic_api", user_preview="q1", assistant_preview="a1")
        _insert_api_call(db_path, "anthropic_api", user_preview="q2", assistant_preview="a2")
        _insert_api_call(db_path, "claude_web", host="claude.ai")
        _insert_api_call(db_path, "claude_web", host="claude.ai")
        _insert_api_call(db_path, "claude_web", host="claude.ai")

        data = _get_json(f"{base}/api/session/{session_id}")
        cov = data.get("content_coverage")
        assert cov == {"total": 5, "with_content": 2, "metadata_only": 3}

    def test_propagates_tokens_and_cost(self, desktop_server):
        base, db_path = desktop_server
        session_id = _seed_desktop_session(db_path, "claude_desktop")
        _insert_api_call(
            db_path,
            "anthropic_api",
            user_preview="hi",
            assistant_preview="hello",
            input_tokens=2341,
            output_tokens=847,
            cache_read_tokens=12000,
            cost=0.0142,
            tool_call_count=2,
        )

        data = _get_json(f"{base}/api/session/{session_id}")
        ev = next(e for e in data["events"] if e["event_type"] == "api_call")
        assert ev["data"]["input_tokens"] == 2341
        assert ev["data"]["output_tokens"] == 847
        assert ev["data"]["cache_read_tokens"] == 12000
        assert ev["data"]["estimated_cost_usd"] == pytest.approx(0.0142)
        assert ev["data"]["tool_call_count"] == 2

    def test_non_desktop_session_has_no_content_coverage(self, desktop_server):
        base, db_path = desktop_server
        # A real (non-desktop) session — no synthetic events, no
        # content_coverage key on the response.
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
        assert "content_coverage" not in data
