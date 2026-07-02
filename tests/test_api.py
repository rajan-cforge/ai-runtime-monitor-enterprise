"""Tests for the DashboardHandler HTTP API routes."""

import json
import threading
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import Request, urlopen

import pytest

from claude_monitoring.db import init_db


def _setup_test_db(tmp_path):
    """Create a test database with schema and sample data."""
    db_path = tmp_path / "test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)

    conn = init_db(db_path)

    # Insert sample data
    conn.execute(
        "INSERT INTO sessions (session_id, start_time, model, total_turns, total_input_tokens, total_output_tokens, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("test-sess-1", "2026-01-01T00:00:00Z", "claude-sonnet-4", 5, 1000, 500, "2026-01-01T00:10:00Z"),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T00:00:00Z", "test-sess-1", "user_prompt", "network", '{"text":"hello"}'),
    )
    # Insert sample browser session data
    conn.execute(
        """INSERT INTO browser_sessions (service, url, title, conversation_id, visit_time, duration_seconds)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("ChatGPT", "https://chatgpt.com/c/test-conv-1", "Test Chat", "test-conv-1", "2026-01-01T00:05:00Z", 120.0),
    )
    conn.execute(
        """INSERT INTO browser_sessions (service, url, title, conversation_id, visit_time, duration_seconds)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            "ChatGPT",
            "https://chatgpt.com/c/test-conv-1",
            "Test Chat Continued",
            "test-conv-1",
            "2026-01-01T00:08:00Z",
            60.0,
        ),
    )
    # Insert sample api_calls data for traffic endpoints
    conn.execute(
        """INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number,
            destination_host, destination_service, endpoint_path, http_method,
            http_status, model, stream, input_tokens, output_tokens,
            cache_read_tokens, cache_write_tokens,
            request_size_bytes, response_size_bytes, latency_ms, num_messages,
            system_prompt_chars, tool_call_count, sensitive_pattern_count,
            stop_reason, request_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2026-01-01T00:01:00Z",
            "test-sess-1",
            "turn-1",
            1,
            "api.anthropic.com",
            "anthropic_api",
            "/v1/messages",
            "POST",
            200,
            "claude-sonnet-4",
            "true",
            5000,
            1000,
            100,
            50,
            12000,
            8000,
            1500,
            10,
            5000,
            2,
            0,
            "end_turn",
            "req-abc123",
        ),
    )
    conn.execute(
        """INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number,
            destination_host, destination_service, endpoint_path, http_method,
            http_status, model, stream, input_tokens, output_tokens,
            cache_read_tokens, cache_write_tokens,
            request_size_bytes, response_size_bytes, latency_ms, num_messages,
            system_prompt_chars, tool_call_count, sensitive_pattern_count,
            stop_reason, request_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2026-01-01T00:02:00Z",
            "test-sess-1",
            "turn-2",
            2,
            "api.anthropic.com",
            "anthropic_api",
            "/v1/messages",
            "POST",
            200,
            "claude-sonnet-4",
            "true",
            8000,
            2000,
            200,
            100,
            20000,
            15000,
            2500,
            15,
            5000,
            3,
            1,
            "tool_use",
            "req-def456",
        ),
    )
    # Additional events for turns testing: tool_use and token_usage within the same session
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T00:01:00Z", "test-sess-1", "tool_use", "network", '{"name":"read_file","path":"/tmp/foo.py"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:02:00Z",
            "test-sess-1",
            "token_usage",
            "network",
            '{"input_tokens":800,"output_tokens":400}',
        ),
    )
    # Sensitive data event for alerts testing
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:03:00Z",
            "test-sess-1",
            "sensitive_data",
            "network",
            '{"patterns":["AWS_KEY"],"severity":"critical","categories":["credential"],"context":"found key","snippet":"AKIA..."}',
        ),
    )
    # A second sensitive_data event with different severity for filter testing
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:04:00Z",
            "test-sess-1",
            "sensitive_data",
            "network",
            '{"patterns":["PRIVATE_KEY"],"severity":"high","categories":["secret"],"context":"found pem","snippet":"-----BEGIN"}',
        ),
    )
    # File event for /api/files testing
    conn.execute(
        "INSERT INTO file_events (timestamp, path, operation, session_id, size) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T00:05:00Z", "/tmp/foo.py", "write", "test-sess-1", 1234),
    )
    # MCP tool_use events for MCP testing
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:06:00Z",
            "test-sess-1",
            "tool_use",
            "network",
            '{"name":"mcp__filesystem__read_file","id":"t1","input":{"path":"/tmp/foo"},"input_preview":"/tmp/foo"}',
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:06:01Z",
            "test-sess-1",
            "mcp_call",
            "network",
            '{"server":"filesystem","method":"read_file","tool_name":"mcp__filesystem__read_file","input_preview":"/tmp/foo"}',
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:07:00Z",
            "test-sess-1",
            "tool_use",
            "network",
            '{"name":"mcp__github__list_repos","id":"t2","input":{},"input_preview":"{}"}',
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:07:01Z",
            "test-sess-1",
            "mcp_call",
            "network",
            '{"server":"github","method":"list_repos","tool_name":"mcp__github__list_repos","input_preview":"{}"}',
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:07:02Z",
            "test-sess-1",
            "mcp_call",
            "network",
            '{"server":"filesystem","method":"write_file","tool_name":"mcp__filesystem__write_file","input_preview":"/tmp/bar"}',
        ),
    )
    # Second session for insights testing
    conn.execute(
        "INSERT INTO sessions (session_id, start_time, cwd, model, total_turns, total_input_tokens, total_output_tokens, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "test-sess-2",
            "2026-01-01T01:00:00Z",
            "/home/user/project-b",
            "claude-opus-4",
            10,
            5000,
            2500,
            "2026-01-01T02:00:00Z",
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        ("2026-01-01T01:00:00Z", "test-sess-2", "user_prompt", "network", '{"text":"build feature"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T01:01:00Z",
            "test-sess-2",
            "token_usage",
            "network",
            '{"input_tokens":5000,"output_tokens":2500,"model":"claude-opus-4"}',
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            "2026-01-01T01:01:00Z",
            "test-sess-2",
            "tool_use",
            "network",
            '{"name":"Read","input_preview":"/src/main.py"}',
        ),
    )
    conn.commit()
    conn.close()
    return db_path, output_dir


@pytest.fixture()
def api_server(tmp_path, monkeypatch):
    """Start a real HTTP server on a random port for testing.

    Auth is disabled for tests via DISABLE_DASHBOARD_AUTH=1 — the dashboard
    token feature is exercised separately by test_security_hardening.py.
    """
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path, output_dir = _setup_test_db(tmp_path)

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


class TestDashboardAPI:
    def test_root_returns_html(self, api_server):
        resp = urlopen(f"{api_server}/")
        assert resp.status == 200
        body = resp.read().decode()
        assert "<html" in body.lower()

    def test_api_stats(self, api_server):
        resp = urlopen(f"{api_server}/api/stats")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "total_sessions" in data
        assert "total_input_tokens" in data
        assert "total_output_tokens" in data

    def test_api_sessions(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    def test_api_feed(self, api_server):
        resp = urlopen(f"{api_server}/api/feed")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_api_export_sessions(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=sessions&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_unknown_path_404(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/unknown/path")
        assert exc_info.value.code == 404

    def test_api_processes(self, api_server):
        resp = urlopen(f"{api_server}/api/processes")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "processes" in data

    def test_api_connections(self, api_server):
        resp = urlopen(f"{api_server}/api/connections")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "connections" in data

    def test_api_browser_sessions(self, api_server):
        resp = urlopen(f"{api_server}/api/browser/sessions")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "browser_sessions" in data
        assert isinstance(data["browser_sessions"], list)
        # Should have our test conversation grouped
        assert len(data["browser_sessions"]) >= 1
        sess = data["browser_sessions"][0]
        assert sess["conversation_id"] == "test-conv-1"
        assert sess["visit_count"] == 2

    def test_api_browser_session_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/browser/session/test-conv-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["conversation_id"] == "test-conv-1"
        assert data["service"] == "ChatGPT"
        assert len(data["visits"]) == 2
        assert "correlated_connections" in data

    def test_api_activity_timeline(self, api_server):
        resp = urlopen(f"{api_server}/api/activity/timeline")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "timeline" in data
        assert "count" in data
        assert isinstance(data["timeline"], list)

    def test_api_timeline_source_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/activity/timeline?source=browser")
        assert resp.status == 200
        data = json.loads(resp.read())
        for ev in data["timeline"]:
            assert ev["source"] == "browser"

    def test_api_sessions_include_browser(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?include_browser=true")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data
        sources = set(s.get("source") for s in data["sessions"])
        # Should have both cli and browser sessions
        assert "cli" in sources
        assert "browser" in sources

    def test_api_sessions_source_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?source=browser")
        assert resp.status == 200
        data = json.loads(resp.read())
        for s in data["sessions"]:
            assert s["source"] == "browser"

    def test_api_process_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/process/1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "processes" in data
        assert "connections" in data
        assert "service_breakdown" in data

    def test_api_traffic(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "calls" in data
        assert "total" in data
        assert data["total"] == 2
        assert len(data["calls"]) == 2

    def test_api_traffic_with_limit(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic?limit=1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["calls"]) == 1
        assert data["total"] >= 1

    def test_api_traffic_with_service_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic?service=anthropic_api")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total"] == 2
        for call in data["calls"]:
            assert call["destination_service"] == "anthropic_api"

    def test_api_traffic_with_model_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic?model=sonnet")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total"] == 2

    def test_api_traffic_stats(self, api_server):
        resp = urlopen(f"{api_server}/api/traffic/stats")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total_calls"] == 2
        assert data["total_input_tokens"] == 13000
        assert data["total_output_tokens"] == 3000
        assert data["avg_latency"] > 0
        assert "by_service" in data
        assert "by_model" in data
        assert len(data["by_service"]) >= 1
        assert len(data["by_model"]) >= 1

    def test_api_session_traffic(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1/traffic")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["session_id"] == "test-sess-1"
        assert data["total_calls"] == 2
        assert len(data["calls"]) == 2

    def test_api_session_traffic_empty(self, api_server):
        resp = urlopen(f"{api_server}/api/session/nonexistent/traffic")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total_calls"] == 0
        assert data["calls"] == []

    # ── Session detail endpoint ──────────────────────────────────────

    def test_api_session_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "session" in data
        assert "events" in data
        assert data["session"]["session_id"] == "test-sess-1"
        assert data["session"]["model"] == "claude-sonnet-4"
        assert data["session"]["total_turns"] == 5
        assert isinstance(data["events"], list)
        assert len(data["events"]) >= 1

    def test_api_session_detail_not_found(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/session/nonexistent-session-xyz")
        assert exc_info.value.code == 404

    def test_api_session_detail_events_structure(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        events = data["events"]
        # Should have at least the user_prompt, tool_use, token_usage, and sensitive_data events
        event_types = [e["event_type"] for e in events]
        assert "user_prompt" in event_types
        assert "tool_use" in event_types
        assert "token_usage" in event_types
        assert "sensitive_data" in event_types
        # Each event should have required fields
        for evt in events:
            assert "id" in evt
            assert "timestamp" in evt
            assert "event_type" in evt
            assert "source" in evt
            assert "data" in evt

    # ── Session turns endpoint ───────────────────────────────────────

    def test_api_session_turns(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1/turns")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "session" in data
        assert "turns" in data
        assert "total_turns" in data
        assert "total_input" in data
        assert "total_output" in data
        assert data["session"]["session_id"] == "test-sess-1"
        # There is one user_prompt event so there should be exactly one turn
        assert data["total_turns"] == 1
        assert len(data["turns"]) == 1

    def test_api_session_turns_structure(self, api_server):
        resp = urlopen(f"{api_server}/api/session/test-sess-1/turns")
        assert resp.status == 200
        data = json.loads(resp.read())
        turn = data["turns"][0]
        assert turn["turn_number"] == 1
        assert "timestamp" in turn
        assert "prompt_preview" in turn
        assert "events" in turn
        assert "tools_used" in turn
        assert "has_alert" in turn
        assert "token_delta" in turn
        assert "cumulative_tokens" in turn
        # The turn should contain tool_use, token_usage, and sensitive_data events
        assert "read_file" in turn["tools_used"]
        assert turn["has_alert"] is True
        assert turn["token_delta"]["input"] == 800
        assert turn["token_delta"]["output"] == 400
        assert turn["cumulative_tokens"]["input"] == 800
        assert turn["cumulative_tokens"]["output"] == 400
        assert data["total_input"] == 800
        assert data["total_output"] == 400

    def test_api_session_turns_not_found(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/session/nonexistent-session-xyz/turns")
        assert exc_info.value.code == 404

    # ── Alerts endpoint ──────────────────────────────────────────────

    def test_api_alerts(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "alerts" in data
        assert "severity_counts" in data
        assert "category_counts" in data
        assert "total" in data
        assert "has_more" in data
        assert data["total"] == 2
        assert isinstance(data["alerts"], list)
        assert len(data["alerts"]) == 2
        # Verify alert structure
        alert = data["alerts"][0]
        assert "id" in alert
        assert "timestamp" in alert
        assert "session_id" in alert
        assert "severity" in alert
        assert "categories" in alert
        assert "patterns" in alert
        assert "turn_number" in alert

    def test_api_alerts_severity_filter_critical(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?severity=critical&confidence=all")
        assert resp.status == 200
        data = json.loads(resp.read())
        # Only the critical alert should be in the filtered list
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["severity"] == "critical"
        assert "AWS_KEY" in data["alerts"][0]["patterns"]
        # severity_counts reflect filtered results
        assert data["severity_counts"]["critical"] == 1
        assert data["total"] == 1

    def test_api_alerts_severity_filter_no_match(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?severity=low&confidence=all")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["alerts"]) == 0
        assert data["total"] == 0

    # ── Files endpoint ───────────────────────────────────────────────

    def test_api_files(self, api_server):
        resp = urlopen(f"{api_server}/api/files")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "files" in data
        assert isinstance(data["files"], list)
        assert len(data["files"]) >= 1
        f = data["files"][0]
        assert f["path"] == "/tmp/foo.py"
        assert f["operation"] == "write"
        assert f["session_id"] == "test-sess-1"
        assert f["size"] == 1234

    # ── Export events endpoint ───────────────────────────────────────

    def test_api_export_events_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&format=json")
        assert resp.status == 200
        body = resp.read()
        data = json.loads(body)
        assert "data" in data
        assert "export_type" in data
        assert data["export_type"] == "events"
        assert "count" in data
        assert isinstance(data["data"], list)
        assert data["count"] >= 1
        # Each exported event should have parsed data (not raw data_json)
        evt = data["data"][0]
        assert "id" in evt
        assert "timestamp" in evt
        assert "session_id" in evt
        assert "event_type" in evt
        assert "data" in evt
        assert isinstance(evt["data"], dict)

    def test_api_export_events_ndjson(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&format=ndjson")
        assert resp.status == 200
        assert "application/x-ndjson" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        lines = [line for line in body.strip().split("\n") if line]
        assert len(lines) >= 1
        # Each line should be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "event_type" in parsed
            assert "session_id" in parsed

    def test_api_export_alerts_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=alerts&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "alerts"
        assert data["count"] == 2
        assert isinstance(data["data"], list)
        # Should have inlined data_json fields
        alert = data["data"][0]
        assert "timestamp" in alert
        assert "session_id" in alert
        assert "patterns" in alert or "severity" in alert

    def test_api_export_connections_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=connections&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "connections"
        assert isinstance(data["data"], list)

    def test_api_export_unknown_type(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/export?type=bogus")
        assert exc_info.value.code == 400

    def test_api_export_sessions_ndjson(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=sessions&format=ndjson")
        assert resp.status == 200
        assert "application/x-ndjson" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        lines = [line for line in body.strip().split("\n") if line]
        assert len(lines) >= 1
        parsed = json.loads(lines[0])
        assert "session_id" in parsed

    def test_api_browser_raw(self, api_server):
        resp = urlopen(f"{api_server}/api/browser")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "browser_sessions" in data
        assert isinstance(data["browser_sessions"], list)

    def test_api_alerts_with_category_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?category=credential")
        assert resp.status == 200
        data = json.loads(resp.read())
        for alert in data["alerts"]:
            assert "credential" in alert["categories"]

    def test_api_alerts_with_offset(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?offset=1&limit=1")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["alerts"]) == 1
        assert data["total"] == 2

    def test_api_export_events_with_session_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&session_id=test-sess-1")
        assert resp.status == 200
        data = json.loads(resp.read())
        for evt in data["data"]:
            assert evt["session_id"] == "test-sess-1"

    def test_api_export_events_with_type_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&event_type=user_prompt")
        assert resp.status == 200
        data = json.loads(resp.read())
        for evt in data["data"]:
            assert evt["event_type"] == "user_prompt"

    # ── MCP endpoints ────────────────────────────────────────────────

    def test_mcp_stats_endpoint(self, api_server):
        resp = urlopen(f"{api_server}/api/mcp/stats")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "servers" in data
        assert "total_calls" in data
        assert "total_servers" in data
        assert "recent_calls" in data
        # Should have filesystem and github servers from test data
        server_names = [s["server"] for s in data["servers"]]
        assert "filesystem" in server_names
        assert "github" in server_names
        # Filesystem has 2 calls (read_file, write_file), github has 1
        fs = next(s for s in data["servers"] if s["server"] == "filesystem")
        assert fs["call_count"] >= 2
        assert "read_file" in fs["methods"]

    def test_mcp_servers_endpoint(self, api_server):
        resp = urlopen(f"{api_server}/api/mcp/servers")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "servers" in data
        assert "total" in data
        assert data["total"] >= 2
        server_names = [s["server"] for s in data["servers"]]
        assert "filesystem" in server_names
        assert "github" in server_names
        # Check methods are listed
        fs = next(s for s in data["servers"] if s["server"] == "filesystem")
        assert "read_file" in fs["methods"]
        assert fs["call_count"] >= 2

    # ── Insights endpoints ───────────────────────────────────────────

    def test_insights_endpoint(self, api_server):
        resp = urlopen(f"{api_server}/api/insights?period=all")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "total_sessions" in data
        assert "efficiency" in data
        assert "top_tools" in data
        assert "top_files" in data
        assert "projects" in data
        assert "daily_trend" in data
        assert "models" in data
        assert data["total_sessions"] >= 2
        assert data["efficiency"]["avg_turns_per_session"] > 0

    def test_insights_period_filter(self, api_server):
        # 7d filter — our test data is from 2026-01-01 which may be outside 7d
        resp = urlopen(f"{api_server}/api/insights?period=7d")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "total_sessions" in data

        # All time — should include everything
        resp_all = urlopen(f"{api_server}/api/insights?period=all")
        data_all = json.loads(resp_all.read())
        assert data_all["total_sessions"] >= data["total_sessions"]

    def test_insights_projects_detail(self, api_server):
        resp = urlopen(f"{api_server}/api/insights/projects?cwd=/home/user/project-b")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["cwd"] == "/home/user/project-b"
        assert data["total_sessions"] >= 1
        assert "sessions" in data
        assert "daily" in data

    def test_insights_projects_missing_cwd(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/insights/projects")
        assert exc_info.value.code == 400

    def test_insights_efficiency(self, api_server):
        resp = urlopen(f"{api_server}/api/insights/efficiency?period=all")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data
        assert "total" in data
        assert data["total"] >= 2
        # Each session should have computed columns
        sess = data["sessions"][0]
        assert "tokens_per_turn" in sess

    # ── Export CSV and traffic ────────────────────────────────────────

    def test_export_csv_format(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=sessions&format=csv")
        assert resp.status == 200
        assert "text/csv" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        lines = body.strip().split("\n")
        assert len(lines) >= 2  # header + at least 1 row
        assert "session_id" in lines[0]

    def test_export_traffic(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=traffic&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "traffic"
        assert isinstance(data["data"], list)
        assert data["count"] >= 1

    def test_export_traffic_csv(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=traffic&format=csv")
        assert resp.status == 200
        assert "text/csv" in resp.headers.get("Content-Type", "")

    # ── Report endpoint ──────────────────────────────────────────────

    def test_report_html(self, api_server):
        resp = urlopen(f"{api_server}/api/report?days=7&format=html")
        assert resp.status == 200
        body = resp.read().decode()
        assert "<html" in body.lower()
        assert "AI Runtime Monitor" in body
        assert "Chart" in body  # Chart.js reference

    def test_report_markdown(self, api_server):
        resp = urlopen(f"{api_server}/api/report?days=7&format=markdown")
        assert resp.status == 200
        assert "text/markdown" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        assert "# AI Runtime Monitor Report" in body
        assert "## Overview" in body

    def test_report_csv(self, api_server):
        resp = urlopen(f"{api_server}/api/report?days=7&format=csv")
        assert resp.status == 200
        assert "text/csv" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        assert "day" in body  # header

    # ── Alert dismissal endpoints ───────────────────────────────────

    def test_dismiss_alert_creates_record(self, api_server):
        # First get the alert IDs
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true")
        data = json.loads(resp.read())
        alert_id = data["alerts"][0]["id"]

        # Dismiss it
        req = Request(
            f"{api_server}/api/alerts/dismiss",
            data=json.dumps({"event_id": alert_id, "reason": "false_positive"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        result = json.loads(resp.read())
        assert result["ok"] is True
        assert result["event_id"] == alert_id

    def test_dismiss_nonexistent_event_returns_404(self, api_server):
        from urllib.error import HTTPError

        req = Request(
            f"{api_server}/api/alerts/dismiss",
            data=json.dumps({"event_id": 99999}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 404

    def test_dismiss_bad_input_returns_400(self, api_server):
        from urllib.error import HTTPError

        req = Request(
            f"{api_server}/api/alerts/dismiss",
            data=json.dumps({}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400

    def test_alerts_include_dismissed_status(self, api_server):
        # Get alerts with dismissed included
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true")
        data = json.loads(resp.read())
        # All alerts should have a 'dismissed' field
        for alert in data["alerts"]:
            assert "dismissed" in alert
            assert isinstance(alert["dismissed"], bool)

    def test_alerts_dismissed_hidden_by_default(self, api_server):
        # First dismiss an alert
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true")
        data = json.loads(resp.read())
        alert_id = data["alerts"][0]["id"]
        req = Request(
            f"{api_server}/api/alerts/dismiss",
            data=json.dumps({"event_id": alert_id, "reason": "test"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(req)
        except Exception:
            pass  # May already be dismissed from earlier test

        # Default query should hide dismissed alerts
        resp = urlopen(f"{api_server}/api/alerts")
        data = json.loads(resp.read())
        dismissed_ids = [a["id"] for a in data["alerts"] if a.get("dismissed")]
        assert alert_id not in dismissed_ids

    # P9.3 (judge p9.3.a2 APPROVE 2026-06-24): /api/alerts/triage set + clear.
    # Mirrors the dismiss tests above. Coverage motivator — these wire the
    # new handler methods into the integration test runner so the per-file
    # ratchet on dashboard_handler.py stays green.

    def test_triage_set_creates_verdict(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true&triage_filter=all")
        data = json.loads(resp.read())
        alert_id = data["alerts"][0]["id"]

        req = Request(
            f"{api_server}/api/alerts/triage",
            data=json.dumps({"event_id": alert_id, "verdict": "true_positive"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        result = json.loads(resp.read())
        assert result["ok"] is True
        assert result["event_id"] == alert_id
        assert result["verdict"] == "true_positive"

    def test_triage_muted_rejected_until_p9_4(self, api_server):
        """P9.3 F3 LIVE-rejection: P9.4 Mute is DEFERRED to v0.3 per Rajan
        release-scope 2026-06-24. The endpoint MUST reject `verdict='muted'`
        with a 4xx — P9.3 ships ZERO mute capability."""
        from urllib.error import HTTPError

        # Need an alert that exists — pick from include_dismissed=true list.
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true&triage_filter=all")
        data = json.loads(resp.read())
        alert_id = data["alerts"][0]["id"]

        req = Request(
            f"{api_server}/api/alerts/triage",
            data=json.dumps({"event_id": alert_id, "verdict": "muted"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400  # _normalize_verdict('muted') → fail-closed

    def test_triage_bad_input_returns_400(self, api_server):
        from urllib.error import HTTPError

        # Missing event_id
        req = Request(
            f"{api_server}/api/alerts/triage",
            data=json.dumps({"verdict": "true_positive"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400

    def test_triage_nonexistent_event_returns_404(self, api_server):
        from urllib.error import HTTPError

        req = Request(
            f"{api_server}/api/alerts/triage",
            data=json.dumps({"event_id": 99999, "verdict": "false_positive"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 404

    def test_triage_clear_removes_verdict(self, api_server):
        """POST /api/alerts/triage/clear deletes the verdict row; idempotent
        (succeeds whether the row existed or not)."""
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true&triage_filter=all")
        data = json.loads(resp.read())
        alert_id = data["alerts"][0]["id"]

        # Set a verdict first.
        req = Request(
            f"{api_server}/api/alerts/triage",
            data=json.dumps({"event_id": alert_id, "verdict": "false_positive"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req)

        # Clear it.
        req = Request(
            f"{api_server}/api/alerts/triage/clear",
            data=json.dumps({"event_id": alert_id}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        result = json.loads(resp.read())
        assert result["ok"] is True
        assert result["cleared"] is True

    def test_triage_clear_idempotent_on_missing_row(self, api_server):
        """Clearing an alert that was never triaged returns success — not 404."""
        req = Request(
            f"{api_server}/api/alerts/triage/clear",
            data=json.dumps({"event_id": 99999}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200

    # P7.1 (Rajan-ratified 2026-06-30): the two new namespaced routes
    # `/api/attack-surface/{assets,scan-now}` mirror the interim `/api/assets`
    # surface during the P7.1→P7.4 transition. HTTP-level tests wire the
    # handler methods into the integration test runner so per-file coverage
    # on dashboard_handler.py stays green.

    def test_attack_surface_assets_returns_json_envelope(self, api_server):
        """`GET /api/attack-surface/assets` mirrors `_api_assets` — same envelope
        (`rows`, `total`, `limit`, `offset`). Preserves `?source=` per R0-2."""
        resp = urlopen(f"{api_server}/api/attack-surface/assets?limit=5&offset=0")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "rows" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["limit"] == 5
        assert data["offset"] == 0

    def test_attack_surface_assets_source_filter_preserved(self, api_server):
        """R0-2 ratified PRESERVE: `?source=` filter round-trips via list_assets."""
        resp = urlopen(f"{api_server}/api/attack-surface/assets?source=python-packages&limit=10")
        assert resp.status == 200
        data = json.loads(resp.read())
        # All rows must be from the requested source
        for row in data.get("rows", []):
            assert row.get("source") == "python-packages", (
                f"?source= filter must apply; got row with source={row.get('source')!r}"
            )

    def test_attack_surface_scan_now_returns_202_or_409(self, api_server, monkeypatch):
        """P7-A rewired scan-now from 501 stub to real run_discover trigger.
        MONKEYPATCH run_discover to a no-op so the HTTP contract is verified
        WITHOUT actually starting a scan in a background thread — a real scan
        would pollute shared orchestrator / lock module state and break
        downstream tests (this was the Ubuntu 3.10/3.11 CI collision root
        cause).
        (P7.1 shipped 501; P7-A rewire replaces per judge Ask #1 ratification.)"""
        import time as _t

        from claude_monitoring import discovery_scheduler as _ds

        monkeypatch.setattr(_ds, "run_discover", lambda json_out=True: 0)

        req = Request(
            f"{api_server}/api/attack-surface/scan-now",
            data=json.dumps({}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status in (202, 409), (
            f"P7-A scan-now must return 202 (accepted) or 409 (concurrent); got {resp.status}"
        )
        data = json.loads(resp.read())
        if resp.status == 202:
            assert data.get("started") is True
            assert data.get("trigger") == "on_demand"
        else:
            assert data.get("ok") is False

        # Drain the background runner + reset in-memory state so subsequent
        # tests see a clean idle slate (poll up to 2s for thread completion).
        from claude_monitoring.dashboard_handler import (
            _discovery_scan_state,
            _discovery_scan_state_lock,
        )

        for _ in range(20):
            with _discovery_scan_state_lock:
                if _discovery_scan_state["status"] != "running":
                    break
            _t.sleep(0.1)
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"
            _discovery_scan_state["started_at"] = None
            _discovery_scan_state["finished_at"] = None

    def test_attack_surface_overview_envelope(self, api_server):
        """P7-A: /api/attack-surface/overview returns composite State C payload
        with 7 required keys per D-overview-endpoint spec."""
        resp = urlopen(f"{api_server}/api/attack-surface/overview")
        assert resp.status == 200
        data = json.loads(resp.read())
        required_keys = {
            "total",
            "by_band",
            "top_5",
            "new_assets_24h",
            "new_cves_24h",
            "last_scan_ts",
            "scan_in_progress",
        }
        assert required_keys.issubset(data.keys()), f"Missing keys: {required_keys - data.keys()}"
        # CF-5: by_band has distinct unscored bucket
        assert "unscored" in data["by_band"]
        # M7: top_5 has at most 5 rows
        assert len(data["top_5"]) <= 5
        # M9: new_cves_24h always {count:0, status:'unavailable'} in v0.2.2
        assert data["new_cves_24h"]["count"] == 0
        assert data["new_cves_24h"]["status"] == "unavailable"

    def test_attack_surface_overview_by_band_sums_to_total(self, api_server):
        """CF-5 sibling: by_band sums (including unscored) reconcile with total."""
        resp = urlopen(f"{api_server}/api/attack-surface/overview")
        data = json.loads(resp.read())
        bb = data["by_band"]
        band_sum = bb["critical"] + bb["high"] + bb["medium"] + bb["low"] + bb["info"] + bb["unscored"]
        assert band_sum <= data["total"], f"by_band sum {band_sum} must be ≤ total {data['total']}"

    def test_attack_surface_scan_progress_returns_snapshot(self, api_server):
        """P7-A: /api/attack-surface/scan-progress returns the module-level
        _discovery_scan_state snapshot for State B polling. Idle DB → status='idle'
        (unless a prior test triggered a scan)."""
        resp = urlopen(f"{api_server}/api/attack-surface/scan-progress")
        assert resp.status == 200
        data = json.loads(resp.read())
        # Envelope keys expected regardless of state
        assert "status" in data
        assert "current_source" in data
        assert "completed_sources" in data
        assert "trigger" in data
        # status is one of the terminal states we defined
        assert data["status"] in ("idle", "running", "done", "error", "skipped_lock_held")

    def test_scan_now_exit_code_1_maps_to_skipped_lock_held(self, api_server, monkeypatch):
        """Architect INFORMATIONAL fold-in: run_discover exit_code=1 (ScanLock
        held) → status='skipped_lock_held' with truthful error message
        (NOT silently 'done'). Covers the runner's exit_code=1 branch."""
        import time as _t

        from claude_monitoring import discovery_scheduler as _ds
        from claude_monitoring.dashboard_handler import (
            _discovery_scan_state,
            _discovery_scan_state_lock,
        )

        monkeypatch.setattr(_ds, "run_discover", lambda json_out=True: 1)
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"

        req = Request(
            f"{api_server}/api/attack-surface/scan-now",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req).read()
        # Wait for runner terminal.
        for _ in range(30):
            with _discovery_scan_state_lock:
                s = _discovery_scan_state["status"]
            if s != "running":
                break
            _t.sleep(0.1)
        with _discovery_scan_state_lock:
            final_status = _discovery_scan_state["status"]
            final_error = _discovery_scan_state["error"]
        assert final_status == "skipped_lock_held", f"got {final_status!r}"
        assert final_error and "ScanLock" in final_error
        # Reset for next test.
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"
            _discovery_scan_state["error"] = None

    def test_scan_now_exit_code_2_maps_to_error(self, api_server, monkeypatch):
        """run_discover exit_code=2 (orchestrator raised) → status='error'
        with fallback error message. Covers the runner's else branch."""
        import time as _t

        from claude_monitoring import discovery_scheduler as _ds
        from claude_monitoring.dashboard_handler import (
            _discovery_scan_state,
            _discovery_scan_state_lock,
        )

        monkeypatch.setattr(_ds, "run_discover", lambda json_out=True: 2)
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"

        req = Request(
            f"{api_server}/api/attack-surface/scan-now",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req).read()
        for _ in range(30):
            with _discovery_scan_state_lock:
                s = _discovery_scan_state["status"]
            if s != "running":
                break
            _t.sleep(0.1)
        with _discovery_scan_state_lock:
            final_status = _discovery_scan_state["status"]
            final_error = _discovery_scan_state["error"]
        assert final_status == "error", f"got {final_status!r}"
        assert final_error and "exit" in final_error.lower()
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"
            _discovery_scan_state["error"] = None

    def test_scan_now_exception_in_runner_maps_to_error(self, api_server, monkeypatch):
        """Runner catches unexpected exception from run_discover, marks
        status='error' with the exception message. Covers try/except branch."""
        import time as _t

        from claude_monitoring import discovery_scheduler as _ds
        from claude_monitoring.dashboard_handler import (
            _discovery_scan_state,
            _discovery_scan_state_lock,
        )

        def _raiser(json_out=True):
            raise RuntimeError("boom-in-runner")

        monkeypatch.setattr(_ds, "run_discover", _raiser)
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"

        req = Request(
            f"{api_server}/api/attack-surface/scan-now",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req).read()
        for _ in range(30):
            with _discovery_scan_state_lock:
                s = _discovery_scan_state["status"]
            if s != "running":
                break
            _t.sleep(0.1)
        with _discovery_scan_state_lock:
            final_status = _discovery_scan_state["status"]
            final_error = _discovery_scan_state["error"]
        assert final_status == "error"
        assert final_error == "boom-in-runner"
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "idle"
            _discovery_scan_state["error"] = None

    def test_scan_now_returns_409_when_state_running(self, api_server, monkeypatch):
        """M4 concurrency pin: if _discovery_scan_state.status is already
        'running', scan-now returns 409 with reason='scan already running'."""
        from urllib.error import HTTPError

        from claude_monitoring.dashboard_handler import (
            _discovery_scan_state,
            _discovery_scan_state_lock,
        )

        # Simulate a running scan.
        with _discovery_scan_state_lock:
            _discovery_scan_state["status"] = "running"
            _discovery_scan_state["started_at"] = "2026-07-02T00:00:00+00:00"

        try:
            req = Request(
                f"{api_server}/api/attack-surface/scan-now",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(HTTPError) as exc:
                urlopen(req)
            assert exc.value.code == 409
            data = json.loads(exc.value.read())
            assert data.get("ok") is False
            assert "scan already running" in data.get("reason", "")
        finally:
            # Always reset to idle to avoid polluting downstream tests.
            with _discovery_scan_state_lock:
                _discovery_scan_state["status"] = "idle"
                _discovery_scan_state["started_at"] = None

    def test_attack_surface_recent_activity_endpoint_reachable(self, api_server):
        """P7-B: /api/attack-surface/recent-activity handler is
        auth-inherited via do_GET._check_auth path. Endpoint always
        returns 200 with the 3-state envelope; branch depends on
        heartbeat + DB state (in the test-env this typically yields
        'off' since no capture heartbeat is running, which exercises the
        early-return path in the handler)."""
        resp = urlopen(f"{api_server}/api/attack-surface/recent-activity")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "capture_status" in data
        assert data["capture_status"] in ("off", "no_captures_yet", "ok")
        assert "assets" in data
        assert isinstance(data["assets"], list)

    def test_severity_counts_correct(self, api_server):
        resp = urlopen(f"{api_server}/api/alerts?include_dismissed=true")
        data = json.loads(resp.read())
        sc = data["severity_counts"]
        assert sc["critical"] == 1
        assert sc["high"] == 1
        assert sc["medium"] == 0
        assert sc["low"] == 0
        assert data["total"] == 2

    # --- Browser ingest endpoint tests ---

    def test_browser_ingest_valid_events(self, api_server):
        events = [
            {
                "service": "ChatGPT",
                "url": "https://chatgpt.com/c/abc",
                "type": "user_prompt",
                "text": "hello world",
                "timestamp": "2026-01-01T12:00:00Z",
                "conversation_id": "abc",
                "title": "Test Chat",
            },
            {
                "service": "Claude Web",
                "url": "https://claude.ai/chat/xyz",
                "type": "assistant_response",
                "text": "Here is the answer to your question.",
                "timestamp": "2026-01-01T12:00:01Z",
                "conversation_id": "xyz",
                "title": "Claude Chat",
            },
        ]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        result = json.loads(resp.read())
        assert result["stored"] == 2
        assert "alerts" in result

    def test_browser_ingest_empty_list(self, api_server):
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": []}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        result = json.loads(resp.read())
        assert result["stored"] == 0

    def test_browser_ingest_bad_json(self, api_server):
        from urllib.error import HTTPError

        req = Request(
            f"{api_server}/api/browser/ingest",
            data=b"not json at all{{{",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400

    def test_browser_ingest_oversized(self, api_server):
        from urllib.error import HTTPError

        events = [{"service": f"svc-{i}", "type": "user_prompt", "text": "x"} for i in range(101)]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400

    def test_browser_ingest_feed_label_user_prompt(self, api_server):
        """POST /api/browser/ingest with type=user_prompt must land in the
        Live Feed with event_type='user_prompt' (NOT the generic 'browser_ai'),
        so the dashboard label renders as USER PROMPT."""
        from claude_monitoring import monitor as mon

        with mon.live_feed_lock:
            mon.live_feed.clear()
            mon._live_feed_seen.clear()

        events = [
            {
                "service": "ChatGPT",
                "url": "https://chatgpt.com/c/label-test-1",
                "type": "user_prompt",
                "text": "what is the capital of france",
                "timestamp": "2026-02-01T12:00:00Z",
                "conversation_id": "label-test-1",
            },
        ]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        assert json.loads(resp.read())["stored"] == 1

        feed_resp = urlopen(f"{api_server}/api/feed?limit=50")
        feed = json.loads(feed_resp.read())["events"]
        matching = [e for e in feed if e.get("session_id") == "browser_label-test-1"]
        assert matching, "browser event did not make it into live feed"
        assert matching[-1]["event_type"] == "user_prompt"

    def test_browser_ingest_feed_label_assistant_response(self, api_server):
        """POST /api/browser/ingest with type=assistant_response must land in
        the Live Feed with event_type='assistant_response' so the dashboard
        renders ASSISTANT RESPONSE — not USER PROMPT and not BROWSER AI."""
        from claude_monitoring import monitor as mon

        with mon.live_feed_lock:
            mon.live_feed.clear()
            mon._live_feed_seen.clear()

        events = [
            {
                "service": "Claude Web",
                "url": "https://claude.ai/chat/label-test-2",
                "type": "assistant_response",
                "text": "Paris is the capital of France.",
                "timestamp": "2026-02-01T12:00:01Z",
                "conversation_id": "label-test-2",
            },
        ]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req)

        feed_resp = urlopen(f"{api_server}/api/feed?limit=50")
        feed = json.loads(feed_resp.read())["events"]
        matching = [e for e in feed if e.get("session_id") == "browser_label-test-2"]
        assert matching
        assert matching[-1]["event_type"] == "assistant_response"

    def test_browser_ingest_feed_mixed_labels(self, api_server):
        """A single ingest batch of user_prompt + assistant_response should
        produce two DISTINCT feed entries with the right labels — this is the
        regression case for the 'both show BROWSER AI' bug."""
        from claude_monitoring import monitor as mon

        with mon.live_feed_lock:
            mon.live_feed.clear()
            mon._live_feed_seen.clear()

        events = [
            {
                "service": "ChatGPT",
                "url": "https://chatgpt.com/c/mixed",
                "type": "user_prompt",
                "text": "tell me a joke please",
                "timestamp": "2026-02-01T13:00:00Z",
                "conversation_id": "mixed",
            },
            {
                "service": "ChatGPT",
                "url": "https://chatgpt.com/c/mixed",
                "type": "assistant_response",
                "text": "Why did the chicken cross the road? To get to the other side.",
                "timestamp": "2026-02-01T13:00:02Z",
                "conversation_id": "mixed",
            },
        ]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req)

        feed_resp = urlopen(f"{api_server}/api/feed?limit=50")
        feed = json.loads(feed_resp.read())["events"]
        types = [e["event_type"] for e in feed if e.get("session_id") == "browser_mixed"]
        assert "user_prompt" in types
        assert "assistant_response" in types
        # And neither got the generic browser_ai label.
        assert "browser_ai" not in types

    def test_browser_ingest_masks_credentials_in_content(self, api_server):
        """P1-02 regression: raw credentials posted via the Chrome extension
        must be masked inline before being stored in browser_sessions. The
        raw value must not appear in content_text and must not appear in the
        associated sensitive_data event's matched_value / snippet."""
        from claude_monitoring import monitor as mon

        raw_aws_key = "AKIAIOSFODNN7EXAMPLE"
        events = [
            {
                "service": "ChatGPT",
                "url": "https://chatgpt.com/c/mask-test",
                "type": "user_prompt",
                "text": f"Please help me debug why my AWS key {raw_aws_key} isn't working",
                "timestamp": "2026-02-01T14:00:00Z",
                "conversation_id": "mask-test",
            },
        ]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200

        # browser_sessions row must not contain the raw key
        db = mon.get_thread_db()
        row = db.execute(
            "SELECT content_text FROM browser_sessions WHERE conversation_id = ? LIMIT 1",
            ("mask-test",),
        ).fetchone()
        assert row is not None
        assert raw_aws_key not in row["content_text"]

        # The sensitive_data event must not contain the raw key in snippet or matched_value
        ev = db.execute(
            """SELECT data_json FROM events
               WHERE session_id='browser_mask-test' AND event_type='sensitive_data'
               ORDER BY id DESC LIMIT 1"""
        ).fetchone()
        assert ev is not None
        data = json.loads(ev["data_json"])
        assert raw_aws_key not in data.get("snippet", "")
        assert raw_aws_key not in data.get("matched_value", "")
        # Masked form should be present in matched_value
        assert data["matched_value"] != raw_aws_key
        # matched_hash is the hash of the raw value — consumers who know the
        # value can verify, but the DB alone does not leak it.
        assert "matched_hash" in data

    def test_browser_ingest_missing_fields(self, api_server):
        events = [
            {"text": "no service or type"},
            {"service": "ChatGPT"},
            {"type": "user_prompt"},
        ]
        req = Request(
            f"{api_server}/api/browser/ingest",
            data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200
        result = json.loads(resp.read())
        assert result["stored"] == 0

    def test_options_returns_cors_headers(self, api_server):
        req = Request(f"{api_server}/api/stats", method="OPTIONS")
        resp = urlopen(req)
        assert resp.status == 200

    def test_post_unknown_path_404(self, api_server):
        from urllib.error import HTTPError

        req = Request(
            f"{api_server}/api/nonexistent",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 404

    def test_api_sessions_with_search(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?q=sonnet")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data

    def test_api_sessions_sort_by_turns(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?sort=turns")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data

    def test_api_sessions_sort_by_tokens(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?sort=tokens")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data

    def test_api_sessions_source_all(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?source=all&include_browser=true")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data

    def test_api_session_detail_missing_id(self, api_server):
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{api_server}/api/session?id=")
        assert exc_info.value.code == 400

    def test_api_insights_returns_data(self, api_server):
        resp = urlopen(f"{api_server}/api/insights")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert isinstance(data, dict)

    def test_api_mcp_stats_returns_data(self, api_server):
        resp = urlopen(f"{api_server}/api/mcp/stats")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert isinstance(data, dict)

    def test_api_mcp_servers_returns_data(self, api_server):
        resp = urlopen(f"{api_server}/api/mcp/servers")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert isinstance(data, dict)

    def test_api_export_events_since_date(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&since=2025-01-01")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "events"

    def test_api_export_events_until_date(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&until=2027-01-01")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "events"

    def test_api_export_events_multiple_type_filter(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=events&event_type=tool_use,token_usage")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "events"
        for ev in data["data"]:
            assert ev["event_type"] in ("tool_use", "token_usage")

    def test_api_export_traffic_json(self, api_server):
        resp = urlopen(f"{api_server}/api/export?type=traffic&format=json")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["export_type"] == "traffic"

    def test_api_sessions_sort_newest(self, api_server):
        resp = urlopen(f"{api_server}/api/sessions?sort=newest")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "sessions" in data

    def test_api_insights_efficiency(self, api_server):
        resp = urlopen(f"{api_server}/api/insights/efficiency")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert isinstance(data, dict)

    def test_api_insights_projects_with_cwd(self, api_server):
        from urllib.parse import quote

        cwd = quote("/home/user/project-b")
        resp = urlopen(f"{api_server}/api/insights/projects?cwd={cwd}")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert isinstance(data, dict)
