"""End-to-end tests for the full AI Runtime Monitor system.

Spins up a real HTTP server with a temporary database and exercises every
API endpoint, the dashboard HTML, browser extension ingest/heartbeat flows,
CLI commands, and export functionality.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import Request, urlopen

import pytest

from claude_monitoring.db import init_db

# ── Helpers ─────────────────────────────────────────────────────


def _get_json(base_url: str, path: str) -> dict:
    """GET a JSON endpoint and return the parsed body."""
    resp = urlopen(f"{base_url}{path}", timeout=10)
    assert resp.status == 200
    return json.loads(resp.read().decode())


def _post_json(base_url: str, path: str, payload: dict) -> dict:
    """POST JSON to an endpoint and return the parsed response body."""
    data = json.dumps(payload).encode()
    req = Request(
        f"{base_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urlopen(req, timeout=10)
    assert resp.status == 200
    return json.loads(resp.read().decode())


# ── Fixture ─────────────────────────────────────────────────────


def _setup_e2e_db(tmp_path):
    """Create a test database with schema and sample data for E2E tests."""
    db_path = tmp_path / "e2e_test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)

    conn = init_db(db_path)

    # 1 session
    conn.execute(
        """INSERT INTO sessions
           (session_id, start_time, cwd, model, total_turns,
            total_input_tokens, total_output_tokens, last_activity)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "e2e-sess-1",
            "2026-01-01T00:00:00Z",
            "/tmp/project",
            "claude-sonnet-4",
            5,
            1000,
            500,
            "2026-01-01T00:10:00Z",
        ),
    )

    # 1 event
    conn.execute(
        """INSERT INTO events
           (timestamp, session_id, event_type, source_layer, data_json)
           VALUES (?, ?, ?, ?, ?)""",
        (
            "2026-01-01T00:00:00Z",
            "e2e-sess-1",
            "user_prompt",
            "network",
            '{"text":"hello world"}',
        ),
    )

    # 1 api_call
    conn.execute(
        """INSERT INTO api_calls
           (timestamp, session_id, turn_id, turn_number,
            destination_host, destination_service, endpoint_path,
            http_method, http_status, model, stream,
            input_tokens, output_tokens,
            cache_read_tokens, cache_write_tokens,
            request_size_bytes, response_size_bytes, latency_ms,
            num_messages, system_prompt_chars, tool_call_count,
            sensitive_pattern_count, stop_reason, request_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2026-01-01T00:01:00Z",
            "e2e-sess-1",
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
            "req-e2e-1",
        ),
    )

    # 1 browser_session
    conn.execute(
        """INSERT INTO browser_sessions
           (service, url, title, conversation_id, visit_time, duration_seconds)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            "ChatGPT",
            "https://chatgpt.com/c/e2e-conv-1",
            "E2E Test Chat",
            "e2e-conv-1",
            "2026-01-01T00:05:00Z",
            120.0,
        ),
    )

    # 1 process (use the processes table — some setups call it 'processes')
    try:
        conn.execute(
            """INSERT INTO processes
               (pid, name, cmdline, start_time, session_id)
               VALUES (?, ?, ?, ?, ?)""",
            (99999, "node", "node index.js", "2026-01-01T00:00:00Z", "e2e-sess-1"),
        )
    except Exception:
        # Table may not exist or have different schema — skip silently
        pass

    conn.commit()
    conn.close()
    return db_path, output_dir


@pytest.fixture()
def e2e_server(tmp_path, monkeypatch):
    """Start a real HTTP server on a random port with a fresh test DB.

    Auth is disabled via DISABLE_DASHBOARD_AUTH=1.
    Yields the base URL (e.g. http://127.0.0.1:PORT).
    """
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path, output_dir = _setup_e2e_db(tmp_path)

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


# ── Test 2: All GET endpoints respond with 200 ─────────────────


# Endpoints that don't need query params
_SIMPLE_GET_ENDPOINTS = [
    "/api/stats",
    "/api/sessions",
    "/api/feed",
    "/api/processes",
    "/api/files",
    "/api/connections",
    "/api/browser",
    "/api/alerts",
    "/api/browser/sessions",
    "/api/browser/extension-health",
    "/api/activity/timeline",
    "/api/export",
    "/api/traffic",
    "/api/traffic/stats",
    "/api/mcp/stats",
    "/api/mcp/servers",
    "/api/insights",
    "/api/insights/efficiency",
    "/api/report",
    "/api/supply-chain",
    "/api/supply-chain/scan-status",
    "/api/supply-chain/environment",
    "/api/supply-chain/intel-status",
    "/api/supply-chain/sbom",
    "/api/supply-chain/watchlist",
]

# Endpoints that need a query param
_PARAMETERIZED_GET_ENDPOINTS = [
    "/api/session?id=e2e-sess-1",
    "/api/session_turns?id=e2e-sess-1",
    "/api/session_traffic?id=e2e-sess-1",
    "/api/browser/session_detail?conversation_id=e2e-conv-1",
    "/api/process_detail?pid=99999",
    "/api/supply-chain/detail?package=test-pkg",
    "/api/supply-chain/registry?package=test-pkg",
    "/api/insights/projects?cwd=/tmp/test-project",
]

_ALL_GET_ENDPOINTS = _SIMPLE_GET_ENDPOINTS + _PARAMETERIZED_GET_ENDPOINTS


@pytest.mark.parametrize("endpoint", _ALL_GET_ENDPOINTS, ids=lambda e: e.split("?")[0])
def test_all_get_endpoints_respond(e2e_server, endpoint):
    """Every registered GET endpoint must return HTTP 200."""
    resp = urlopen(f"{e2e_server}{endpoint}", timeout=10)
    assert resp.status == 200, f"{endpoint} returned {resp.status}"


# ── Test 3: Dashboard HTML loads ────────────────────────────────


def test_dashboard_html_loads(e2e_server):
    """The root URL serves HTML containing all 9 navigation tab names."""
    resp = urlopen(f"{e2e_server}/", timeout=10)
    assert resp.status == 200
    body = resp.read().decode()
    assert "<html" in body.lower()

    expected_tabs = [
        "Session Explorer",
        "Live Feed",
        "Analytics",
        "Insights",
        "System",
        "API Traffic",
        "Activity Timeline",
        "Supply Chain",
        "Alerts",
    ]
    for tab in expected_tabs:
        assert tab in body, f"Tab '{tab}' not found in dashboard HTML"


# ── Test 4: Dashboard auth script present ───────────────────────


def test_dashboard_html_has_auth_script(e2e_server):
    """Verify the token-auth monkey-patch code is present in the HTML."""
    resp = urlopen(f"{e2e_server}/", timeout=10)
    body = resp.read().decode()
    assert "monkey-patch" in body.lower(), "Auth monkey-patch comment not found"
    assert "ai_monitor_token" in body, "Token localStorage key not found"
    assert "Authentication required" in body, "401 handler page not found"


# ── Test 5: Browser ingest + alert detection ────────────────────


def test_browser_ingest_and_alert(e2e_server):
    """POST a browser event with a fake AWS key; verify alert is created."""
    payload = {
        "events": [
            {
                "service": "ChatGPT",
                "url": "https://chatgpt.com/c/e2e-test",
                "type": "user_prompt",
                "text": "Here is my key AKIAJ5TESTXXXXXXXXXZ please use it",
                "conversation_id": "e2e-alert-conv",
                "title": "Secret leak test",
                "timestamp": "2026-01-01T10:00:00Z",
            }
        ]
    }
    result = _post_json(e2e_server, "/api/browser/ingest", payload)
    assert result.get("stored", 0) >= 1 or result.get("ok") is True

    # Fetch alerts and check for aws_key pattern
    alerts_data = _get_json(e2e_server, "/api/alerts")
    alerts = alerts_data.get("alerts", [])
    found = any("aws_key" in str(a.get("patterns", a.get("data", {}).get("patterns", []))) for a in alerts)
    assert found, f"Expected aws_key alert, got alerts: {alerts}"


# ── Test 6: Browser heartbeat + extension health ────────────────


def test_browser_heartbeat_and_health(e2e_server):
    """POST a heartbeat, then verify the host appears as non-stale."""
    heartbeat = {
        "hostname": "test.ai",
        "user_matches": 5,
        "assistant_matches": 3,
        "captures_sent": 2,
        "selector_failure": False,
    }
    result = _post_json(e2e_server, "/api/browser/heartbeat", heartbeat)
    assert result.get("ok") is True
    assert result.get("hostname") == "test.ai"

    # Check extension-health endpoint
    health = _get_json(e2e_server, "/api/browser/extension-health")
    hosts = health.get("hosts", [])
    test_host = [h for h in hosts if h.get("hostname") == "test.ai"]
    assert len(test_host) == 1, f"Expected test.ai in hosts, got: {hosts}"
    assert test_host[0].get("is_stale") is False


# ── Test 7: ai-monitor --status CLI ─────────────────────────────


def test_status_command():
    """ai-monitor --status exits 0 and mentions 'Monitor' in output."""
    result = subprocess.run(
        [sys.executable, "-m", "claude_monitoring.monitor", "--status"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"--status failed: {result.stderr}"
    assert "Monitor" in result.stdout, f"Expected 'Monitor' in: {result.stdout}"


# ── Test 8: ai-monitor --cleanup --dry-run CLI ──────────────────


def test_cleanup_dry_run():
    """ai-monitor --cleanup --dry-run exits 0 and shows dry-run output."""
    result = subprocess.run(
        [sys.executable, "-m", "claude_monitoring.monitor", "--cleanup", "--dry-run"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"--cleanup --dry-run failed: {result.stderr}"
    combined = result.stdout + result.stderr
    assert "DRY RUN" in combined or "Would remove" in combined, f"Expected dry-run marker in: {combined}"


# ── Test 9: Export markdown ──────────────────────────────────────


def test_export_markdown(e2e_server):
    """GET /api/report?format=markdown returns markdown with expected header."""
    resp = urlopen(f"{e2e_server}/api/report?format=markdown", timeout=10)
    assert resp.status == 200
    body = resp.read().decode()
    assert "# AI Runtime" in body, f"Expected markdown header, got: {body[:200]}"
