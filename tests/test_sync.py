# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for sync.py — SyncAgent control plane integration.

Covers the read helpers, payload construction, watermark management,
and backoff behavior. The actual HTTP POST is mocked — we don't need
a real control plane server to verify the client logic.
"""

from __future__ import annotations

import json
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring.db import init_db
from claude_monitoring.sync import SyncAgent


@pytest.fixture()
def sync_db(tmp_path, monkeypatch):
    """Set up a temp DB with sample data for sync tests."""
    db_path = tmp_path / "sync_test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    monkeypatch.setattr("claude_monitoring.sync.get_db_path", lambda: db_path)

    conn.execute(
        "INSERT INTO sessions (session_id, start_time, cwd, model, total_turns, "
        "total_input_tokens, total_output_tokens, last_activity) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("sync-s1", "2026-04-01T00:00:00Z", "/tmp/proj", "claude-sonnet-4", 3, 500, 200, "2026-04-01T01:00:00Z"),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        ("2026-04-01T00:01:00Z", "sync-s1", "user_prompt", "jsonl", '{"text":"hello"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-04-01T00:02:00Z",
            "sync-s1",
            "sensitive_data",
            "network",
            json.dumps(
                {
                    "severity": "high",
                    "patterns": ["aws_key"],
                    "context": "tool_result",
                    "snippet": "AKIA****",
                    "confidence": "high",
                }
            ),
        ),
    )
    conn.execute(
        "INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number, "
        "destination_host, destination_service, endpoint_path, http_method, http_status, "
        "model, stream, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, "
        "request_size_bytes, response_size_bytes, latency_ms, num_messages, "
        "system_prompt_chars, tool_call_count, sensitive_pattern_count, stop_reason, request_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "2026-04-01T00:03:00Z",
            "sync-s1",
            "t1",
            1,
            "api.anthropic.com",
            "anthropic_api",
            "/v1/messages",
            "POST",
            200,
            "claude-sonnet-4",
            "true",
            500,
            200,
            0,
            0,
            1000,
            800,
            350,
            5,
            100,
            1,
            0,
            "end_turn",
            "req-1",
        ),
    )
    conn.commit()
    yield conn, db_path
    conn.close()


class TestSyncAgentInit:
    def test_init_stores_config(self):
        agent = SyncAgent("https://cp.example.com/", "key-123", interval=60)
        assert agent.cp_url == "https://cp.example.com"
        assert agent.api_key == "key-123"
        assert agent.interval == 60
        assert agent.endpoint_id is None

    def test_stop_sets_event(self):
        agent = SyncAgent("http://localhost", "key")
        assert not agent._stop.is_set()
        agent.stop()
        assert agent._stop.is_set()


class TestReadHelpers:
    def test_read_sessions(self, sync_db):
        conn, _ = sync_db
        agent = SyncAgent("http://localhost", "key")
        sessions, max_rowid = agent._read_sessions(conn, 0)
        assert len(sessions) >= 1
        assert max_rowid > 0
        s = sessions[0]
        assert s["client_session_id"] == "sync-s1"
        assert s["model"] == "claude-sonnet-4"
        assert s["total_input_tokens"] == 500
        assert s["total_turns"] == 3

    def test_read_sessions_respects_watermark(self, sync_db):
        """P0-01 regression: _read_sessions used to ignore last_id and
        re-send the first 100 sessions forever. With the fix, a
        watermark past the max rowid returns an empty list."""
        conn, _ = sync_db
        agent = SyncAgent("http://localhost", "key")
        sessions, max_rowid = agent._read_sessions(conn, 0)
        assert len(sessions) >= 1
        # Re-call with the watermark — should return empty
        sessions_after, max_rowid_after = agent._read_sessions(conn, max_rowid)
        assert sessions_after == []
        assert max_rowid_after == max_rowid

    def test_read_events(self, sync_db):
        conn, _ = sync_db
        agent = SyncAgent("http://localhost", "key")
        events, _ = agent._read_events(conn, 0)
        assert len(events) >= 2
        types = {e["event_type"] for e in events}
        assert "user_prompt" in types
        assert "sensitive_data" in types

    def test_read_events_respects_watermark(self, sync_db):
        conn, _ = sync_db
        agent = SyncAgent("http://localhost", "key")
        all_events, max_id = agent._read_events(conn, 0)
        assert max_id == max(e["client_event_id"] for e in all_events)
        empty, _ = agent._read_events(conn, max_id)
        assert empty == []

    def test_read_api_calls(self, sync_db):
        conn, _ = sync_db
        agent = SyncAgent("http://localhost", "key")
        calls, max_id = agent._read_api_calls(conn, 0)
        assert len(calls) == 1
        assert max_id == calls[0]["client_call_id"]
        c = calls[0]
        assert c["model"] == "claude-sonnet-4"
        assert c["input_tokens"] == 500
        assert c["latency_ms"] == 350


class TestExtractAlerts:
    def test_extracts_sensitive_data_events(self, sync_db):
        conn, _ = sync_db
        agent = SyncAgent("http://localhost", "key")
        events, _ = agent._read_events(conn, 0)
        alerts = agent._extract_alerts(events)
        assert len(alerts) == 1
        a = alerts[0]
        assert a["severity"] == "high"
        assert "aws_key" in a["patterns"]
        assert a["confidence"] == "high"

    def test_ignores_non_sensitive_events(self):
        agent = SyncAgent("http://localhost", "key")
        events = [
            {"event_type": "user_prompt", "client_event_id": 1, "timestamp": "t", "session_id": "s", "data_json": {}},
        ]
        assert agent._extract_alerts(events) == []


class TestEndpointInfo:
    def test_returns_hostname_and_os(self):
        agent = SyncAgent("http://localhost", "key")
        info = agent._get_endpoint_info()
        assert "hostname" in info
        assert "os" in info
        assert info["hostname"]  # not empty
        assert info["monitor_version"] == "0.2.0"


class TestDoSync:
    def _mock_requests_module(self, response_data):
        """Build a mock requests module whose .post() returns a preset response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.raise_for_status = MagicMock()
        mock_mod = MagicMock()
        mock_mod.post.return_value = mock_resp
        return mock_mod

    def test_full_sync_posts_to_cp(self, sync_db):
        conn, db_path = sync_db
        conn.close()
        agent = SyncAgent("https://cp.test.com", "key-abc")

        mock_mod = self._mock_requests_module(
            {
                "endpoint_id": "ep-123",
                "stored": {"sessions": 1, "events": 2, "api_calls": 1},
            }
        )

        with patch.dict("sys.modules", {"requests": mock_mod}):
            agent._do_sync()

        mock_mod.post.assert_called_once()
        call_args = mock_mod.post.call_args
        assert call_args[0][0] == "https://cp.test.com/api/v1/ingest"
        assert call_args[1]["headers"]["X-API-Key"] == "key-abc"
        payload = call_args[1]["json"]
        assert len(payload["sessions"]) >= 1
        assert len(payload["events"]) >= 2
        assert len(payload["api_calls"]) >= 1
        assert len(payload["alerts"]) >= 1
        assert agent.endpoint_id == "ep-123"

    def test_sync_updates_watermarks(self, sync_db):
        conn, db_path = sync_db
        conn.close()
        agent = SyncAgent("http://localhost", "key")

        mock_mod = self._mock_requests_module({"endpoint_id": "x", "stored": {}})

        with patch.dict("sys.modules", {"requests": mock_mod}):
            agent._do_sync()

        verify_conn = sqlite3.connect(str(db_path))
        rows = verify_conn.execute("SELECT table_name, last_synced_id FROM sync_state").fetchall()
        verify_conn.close()
        watermarks = {r[0]: r[1] for r in rows}
        assert "events" in watermarks
        assert watermarks["events"] >= 2

    def test_no_data_skips_post(self, tmp_path, monkeypatch):
        db_path = tmp_path / "empty.db"
        init_db(db_path).close()
        monkeypatch.setattr("claude_monitoring.sync.get_db_path", lambda: db_path)
        agent = SyncAgent("http://localhost", "key")

        mock_mod = self._mock_requests_module({})
        with patch.dict("sys.modules", {"requests": mock_mod}):
            agent._do_sync()
        mock_mod.post.assert_not_called()

    def test_missing_db_does_not_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr("claude_monitoring.sync.get_db_path", lambda: tmp_path / "nope.db")
        agent = SyncAgent("http://localhost", "key")
        agent._do_sync()  # should return without error


class TestSyncLoop:
    def test_backoff_doubles_on_failure(self):
        agent = SyncAgent("http://localhost", "key", interval=0)
        assert agent._backoff_time == 1

        call_count = {"n": 0}

        def fail_then_stop():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ConnectionError("down")
            # Second call: stop the loop so the test finishes
            agent._stop.set()

        agent._do_sync = fail_then_stop
        agent._sync_loop()
        assert call_count["n"] == 2
        # After one failure + one success, backoff was doubled then reset
        assert agent._backoff_time == 1  # reset on success


class TestPayloadSanitization:
    """P1-04 regression: sync payloads must be scrubbed for plaintext
    credentials before POSTing to the control plane. Even though the
    primary capture pipelines mask on write, sync is downstream and
    cannot trust upstream — any path that stores raw text (historical
    rows, new capture paths that forgot to mask) must be caught here."""

    def test_sanitize_payload_masks_aws_key_in_snippet(self):
        from claude_monitoring.sync import _sanitize_payload

        raw = "AKIAIOSFODNN7EXAMPLE"
        payload = {
            "alerts": [
                {
                    "snippet": f"my key is {raw}",
                    "matched_value": raw,
                    "patterns": ["aws_key"],
                    "session_id": "sess1",
                }
            ]
        }
        scrubbed = _sanitize_payload(payload)
        assert raw not in scrubbed["alerts"][0]["snippet"]
        assert raw not in scrubbed["alerts"][0]["matched_value"]
        # Non-sensitive fields untouched
        assert scrubbed["alerts"][0]["patterns"] == ["aws_key"]
        assert scrubbed["alerts"][0]["session_id"] == "sess1"

    def test_sanitize_payload_masks_event_text(self):
        from claude_monitoring.sync import _sanitize_payload

        raw = "AKIAIOSFODNN7EXAMPLE"
        payload = {
            "events": [
                {
                    "event_type": "user_prompt",
                    "data_json": {"text": f"help debug {raw} not working"},
                }
            ]
        }
        scrubbed = _sanitize_payload(payload)
        assert raw not in scrubbed["events"][0]["data_json"]["text"]

    def test_sanitize_payload_preserves_non_string_fields(self):
        from claude_monitoring.sync import _sanitize_payload

        payload = {
            "api_calls": [
                {
                    "input_tokens": 1234,
                    "output_tokens": 567,
                    "estimated_cost_usd": 0.01,
                    "timestamp": "2026-04-17T10:00:00Z",
                    "session_id": "s1",
                }
            ]
        }
        scrubbed = _sanitize_payload(payload)
        assert scrubbed["api_calls"][0]["input_tokens"] == 1234
        assert scrubbed["api_calls"][0]["output_tokens"] == 567
        assert scrubbed["api_calls"][0]["estimated_cost_usd"] == 0.01

    def test_sanitize_payload_handles_nested_lists(self):
        from claude_monitoring.sync import _sanitize_payload

        raw = "AKIAIOSFODNN7EXAMPLE"
        payload = {
            "events": [
                {"data_json": {"text": f"first {raw}"}},
                {"data_json": {"text": "clean text here"}},
                {"data_json": {"text": f"third with {raw} again"}},
            ]
        }
        scrubbed = _sanitize_payload(payload)
        assert raw not in scrubbed["events"][0]["data_json"]["text"]
        assert scrubbed["events"][1]["data_json"]["text"] == "clean text here"
        assert raw not in scrubbed["events"][2]["data_json"]["text"]

    def test_sanitize_payload_empty_and_none_safe(self):
        from claude_monitoring.sync import _sanitize_payload

        assert _sanitize_payload({}) == {}
        assert _sanitize_payload([]) == []
        assert _sanitize_payload({"snippet": None}) == {"snippet": None}
        assert _sanitize_payload({"snippet": ""}) == {"snippet": ""}
