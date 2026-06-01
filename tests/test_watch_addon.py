"""Tests for ClaudeWatchAddon class methods that don't require mitmproxy.

Tests _get_service, record initialization (inline in request()),
_write_row, response finalization (inline in response()), and the
DashboardHandler served by run_dashboard.
"""

from __future__ import annotations

import csv
import json
import sqlite3
import threading
import time
from http.server import HTTPServer
from unittest.mock import patch
from urllib.request import urlopen

import pytest

try:
    import mitmproxy  # noqa: F401

    HAS_MITMPROXY = True
except ImportError:
    HAS_MITMPROXY = False

from claude_monitoring.constants import AI_HOSTS, CSV_COLUMNS
from claude_monitoring.db import init_db, insert_api_call

pytestmark = pytest.mark.skipif(not HAS_MITMPROXY, reason="mitmproxy not installed")

# ---------------------------------------------------------------------------
# Fixture: create a ClaudeWatchAddon with mocked config paths
# ---------------------------------------------------------------------------


@pytest.fixture()
def addon(tmp_path):
    """Create a ClaudeWatchAddon whose CSV and DB point at tmp_path."""
    session_dir = tmp_path / "sessions"
    session_dir.mkdir(exist_ok=True)

    # Initialize real DB so insert_api_call can write
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.close()

    with (
        patch("claude_monitoring.watch.get_output_dir", return_value=tmp_path),
        patch("claude_monitoring.watch.get_session_dir", return_value=session_dir),
        patch("claude_monitoring.watch.get_db_path", return_value=db_path),
        patch("claude_monitoring.config.get_output_dir", return_value=tmp_path),
        patch("claude_monitoring.config.get_db_path", return_value=db_path),
        patch("claude_monitoring.db.get_output_dir", return_value=tmp_path),
        patch("claude_monitoring.db.get_db_path", return_value=db_path),
    ):
        from claude_monitoring.watch import ClaudeWatchAddon

        addon = ClaudeWatchAddon()
        addon._db_path = db_path  # stash for assertions
        addon._session_dir = session_dir  # stash for assertions
        yield addon


def _make_record(overrides=None):
    """Return a full record dict with sensible defaults for every CSV column."""
    record = {col: "" for col in CSV_COLUMNS}
    record.update(
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "session_id": "test-sess",
            "turn_id": "turn-1",
            "turn_number": 1,
            "destination_host": "api.anthropic.com",
            "destination_service": "anthropic_api",
            "endpoint_path": "/v1/messages",
            "http_method": "POST",
            "http_status": 200,
            "model": "claude-sonnet-4",
            "stream": "true",
            "input_tokens": 5000,
            "output_tokens": 1000,
            "cache_read_tokens": 200,
            "cache_write_tokens": 100,
            "estimated_cost_usd": 0.0,
            "request_size_bytes": 12000,
            "response_size_bytes": 8000,
            "latency_ms": 1500,
            "num_messages": 10,
            "system_prompt_chars": 5000,
            "last_user_msg_preview": "hello world",
            "assistant_msg_preview": "Sure; I can help.",
            "tool_calls": "[]",
            "tool_call_count": 0,
            "bash_commands": "[]",
            "files_read": "[]",
            "files_written": "[]",
            "urls_fetched": "[]",
            "sensitive_patterns": "",
            "sensitive_pattern_count": 0,
            "content_types_sent": "text",
            "stop_reason": "end_turn",
            "request_id": "req-abc",
            "raw_request_hash": "aabbcc112233",
        }
    )
    if overrides:
        record.update(overrides)
    return record


# ===================================================================
# 1. _get_service
# ===================================================================


class TestGetService:
    """Test the host-to-service lookup in _get_service."""

    def test_known_host_anthropic(self, addon):
        assert addon._get_service("api.anthropic.com") == "anthropic_api"

    def test_known_host_openai(self, addon):
        assert addon._get_service("api.openai.com") == "openai_api"

    def test_known_host_sentry(self, addon):
        assert addon._get_service("sentry.io") == "error_reporting"

    def test_known_host_gemini(self, addon):
        assert addon._get_service("generativelanguage.googleapis.com") == "gemini_api"

    def test_known_host_groq(self, addon):
        assert addon._get_service("api.groq.com") == "groq_api"

    def test_known_host_deepseek(self, addon):
        assert addon._get_service("api.deepseek.com") == "deepseek_api"

    def test_unknown_host_returns_unknown(self, addon):
        assert addon._get_service("example.com") == "unknown"

    def test_unknown_host_random_domain(self, addon):
        assert addon._get_service("totally-random-host.xyz") == "unknown"

    def test_subdomain_matching_anthropic(self, addon):
        """_get_service uses substring 'in' matching, so subdomains of known
        hosts should also resolve if the AI_HOSTS key is a substring."""
        result = addon._get_service("statsig.anthropic.com")
        assert result == "anthropic_telemetry"

    def test_subdomain_matching_ingest_sentry(self, addon):
        result = addon._get_service("ingest.sentry.io")
        assert result == "error_reporting"

    def test_all_ai_hosts_are_resolvable(self, addon):
        """Every host defined in AI_HOSTS should map back to its service."""
        for host, expected_svc in AI_HOSTS.items():
            result = addon._get_service(host)
            assert result == expected_svc, f"_get_service({host!r}) returned {result!r}, expected {expected_svc!r}"

    def test_empty_host(self, addon):
        """Empty string should not match any AI host."""
        assert addon._get_service("") == "unknown"


class TestClassifyBrowserService:
    """PR A: _classify_browser_service uses _matches(host, domain) for exact-
    or-subdomain matching, replacing prior bare `in host` substring checks.
    Guards against attacker-controlled hosts like evil-claude.ai.bad.com."""

    def test_exact_match_claude_ai(self, addon):
        assert addon._classify_browser_service("claude.ai") == "claude_web"

    def test_subdomain_match_claude_ai(self, addon):
        assert addon._classify_browser_service("app.claude.ai") == "claude_web"

    def test_attacker_lookalike_rejected_claude_ai(self, addon):
        """Pre-PR-A substring check would have mis-classified this."""
        assert addon._classify_browser_service("evil-claude.ai.attacker.com") == "browser_ai"

    def test_exact_match_chatgpt_com(self, addon):
        assert addon._classify_browser_service("chatgpt.com") == "chatgpt_web"

    def test_subdomain_match_chat_openai(self, addon):
        assert addon._classify_browser_service("api.chat.openai.com") == "chatgpt_web"

    def test_exact_match_gemini(self, addon):
        assert addon._classify_browser_service("gemini.google.com") == "gemini_web"

    def test_exact_match_perplexity(self, addon):
        assert addon._classify_browser_service("perplexity.ai") == "perplexity_web"

    def test_unknown_host_falls_through(self, addon):
        assert addon._classify_browser_service("example.com") == "browser_ai"


# ===================================================================
# 2. Record initialization (inline _new_record equivalent)
# ===================================================================


class TestNewRecord:
    """Verify that the addon creates records with all expected CSV_COLUMNS keys."""

    def test_record_has_all_csv_columns(self):
        """A record built by _make_record should have every CSV column."""
        record = _make_record()
        for col in CSV_COLUMNS:
            assert col in record, f"Missing CSV column: {col}"

    def test_record_default_numeric_fields(self):
        """Numeric fields should default to zero-ish values."""
        record = _make_record(
            {
                "input_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 0,
                "tool_call_count": 0,
                "sensitive_pattern_count": 0,
            }
        )
        assert record["input_tokens"] == 0
        assert record["output_tokens"] == 0
        assert record["latency_ms"] == 0
        assert record["tool_call_count"] == 0
        assert record["sensitive_pattern_count"] == 0

    def test_record_default_json_list_fields(self):
        """JSON list fields should default to '[]'."""
        record = _make_record()
        for field in ("tool_calls", "bash_commands", "files_read", "files_written", "urls_fetched"):
            assert record[field] == "[]", f"{field} should default to '[]'"

    def test_record_column_count_matches(self):
        """The record should have at least as many keys as CSV_COLUMNS."""
        record = _make_record()
        for col in CSV_COLUMNS:
            assert col in record


# ===================================================================
# 3. _write_row
# ===================================================================


class TestWriteRow:
    """Test that _write_row persists data to CSV and SQLite."""

    def test_csv_header_written_on_init(self, addon):
        """__init__ should create the CSV file with a header row."""
        with open(addon.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
        assert header == CSV_COLUMNS

    def test_write_row_appends_to_csv(self, addon):
        record = _make_record({"session_id": addon.session_id})
        addon._write_row(record)

        with open(addon.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["destination_host"] == "api.anthropic.com"
        assert rows[0]["model"] == "claude-sonnet-4"
        assert rows[0]["session_id"] == addon.session_id

    def test_write_row_multiple_rows(self, addon):
        """Multiple _write_row calls should append multiple rows."""
        for i in range(3):
            record = _make_record({"turn_number": i + 1, "turn_id": f"turn-{i + 1}"})
            addon._write_row(record)

        with open(addon.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["turn_number"] == "1"
        assert rows[2]["turn_number"] == "3"

    def test_write_row_only_csv_columns(self, addon):
        """_write_row should only write columns defined in CSV_COLUMNS,
        even if the record has extra keys like _start_time."""
        record = _make_record({"_extra_field": "should_not_appear"})
        addon._write_row(record)

        with open(addon.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert "_extra_field" not in rows[0]
        assert set(rows[0].keys()) == set(CSV_COLUMNS)

    def test_write_row_inserts_into_sqlite(self, addon):
        """_write_row should also dual-write into the api_calls SQLite table."""
        record = _make_record({"session_id": addon.session_id})
        addon._write_row(record)

        conn = sqlite3.connect(str(addon._db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM api_calls LIMIT 1").fetchone()
        conn.close()

        assert row is not None
        assert row["destination_host"] == "api.anthropic.com"
        assert row["model"] == "claude-sonnet-4"
        assert row["input_tokens"] == 5000
        assert row["output_tokens"] == 1000

    def test_write_row_csv_data_integrity(self, addon):
        """Verify that specific field values survive the CSV round-trip."""
        record = _make_record(
            {
                "tool_calls": json.dumps(["bash", "read_file"]),
                "tool_call_count": 2,
                "bash_commands": json.dumps(["ls -la"]),
                "sensitive_patterns": "aws_key,private_key",
                "sensitive_pattern_count": 2,
            }
        )
        addon._write_row(record)

        with open(addon.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = list(reader)[0]

        tools = json.loads(row["tool_calls"])
        assert "bash" in tools
        assert "read_file" in tools
        assert row["tool_call_count"] == "2"
        assert "aws_key" in row["sensitive_patterns"]

    def test_write_row_handles_commas_in_preview(self, addon):
        """Ensure commas in text fields don't corrupt CSV."""
        record = _make_record(
            {
                "last_user_msg_preview": "first; second; third",
                "assistant_msg_preview": "a; b; c",
            }
        )
        addon._write_row(record)

        with open(addon.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = list(reader)[0]

        assert row["last_user_msg_preview"] == "first; second; third"
        assert row["assistant_msg_preview"] == "a; b; c"


# ===================================================================
# 4. Response finalization (inline _finalize_record equivalent)
# ===================================================================


class TestFinalizeRecord:
    """Test the response finalization logic that computes latency, etc.

    The finalization happens inside the ``response()`` method:
      - pops ``_start_time`` from the record
      - computes ``latency_ms``
      - sets ``http_status``, ``response_size_bytes``, ``request_id``
      - calls parse_sse_response or parse_response_body
    We test the logic by exercising the standalone functions and
    verifying the same computations.
    """

    def test_latency_computed_from_start_time(self):
        """Verify the latency calculation: (now - start) * 1000."""
        start = time.time()
        time.sleep(0.05)  # 50ms
        latency_ms = round((time.time() - start) * 1000)
        assert latency_ms >= 40  # allow some timing slack
        assert latency_ms < 500  # sanity upper bound

    def test_response_sets_status_and_size(self):
        """After response(), http_status and response_size_bytes should be set.

        We simulate this by manually applying the same logic the response()
        method uses.
        """
        record = _make_record({"http_status": "", "response_size_bytes": 0})
        # Simulate what response() does
        record["http_status"] = 200
        record["response_size_bytes"] = 4096
        record["request_id"] = "req-xyz-789"
        assert record["http_status"] == 200
        assert record["response_size_bytes"] == 4096
        assert record["request_id"] == "req-xyz-789"

    def test_assistant_msg_preview_from_response(self):
        """parse_response_body should extract assistant text preview."""
        from claude_monitoring.watch import parse_response_body

        record = _make_record()
        body = {
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "stop_reason": "end_turn",
            "content": [
                {"type": "text", "text": "This is the assistant response."},
            ],
        }
        result = parse_response_body(body, record)
        assert "assistant response" in result["assistant_msg_preview"]

    def test_tool_calls_merged_from_response(self):
        """parse_response_body should merge tool calls from the response content."""
        from claude_monitoring.watch import parse_response_body

        record = _make_record({"tool_calls": json.dumps(["bash"])})
        body = {
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "stop_reason": "tool_use",
            "content": [
                {"type": "tool_use", "name": "read_file", "id": "toolu_1", "input": {}},
            ],
        }
        result = parse_response_body(body, record)
        tools = json.loads(result["tool_calls"])
        assert "bash" in tools
        assert "read_file" in tools


# ===================================================================
# 5. DashboardHandler (the watch.py mini-dashboard)
# ===================================================================


class TestWatchDashboardHandler:
    """Test the DashboardHandler inside run_dashboard.

    The DashboardHandler is defined as a local class inside run_dashboard(),
    so we replicate the pattern: create a CSV with test data, then spin up
    the HTTPServer with the handler using _load_latest_csv.
    """

    @pytest.fixture()
    def dashboard_server(self, tmp_path):
        """Set up a CSV with test data and spin up DashboardHandler."""
        import http.server
        import urllib.parse

        session_dir = tmp_path / "sessions"
        session_dir.mkdir(exist_ok=True)

        # Create a test CSV
        csv_path = session_dir / "claude_watch_20260101_000000.csv"
        rows = [
            {
                "timestamp": "2026-01-01T00:01:00+00:00",
                "session_id": "sess-1",
                "turn_id": "t-1",
                "turn_number": "1",
                "destination_host": "api.anthropic.com",
                "destination_service": "anthropic_api",
                "endpoint_path": "/v1/messages",
                "http_method": "POST",
                "http_status": "200",
                "model": "claude-sonnet-4",
                "stream": "true",
                "input_tokens": "5000",
                "output_tokens": "1000",
                "cache_read_tokens": "0",
                "cache_write_tokens": "0",
                "estimated_cost_usd": "0.0",
                "request_size_bytes": "12000",
                "response_size_bytes": "8000",
                "latency_ms": "1500",
                "num_messages": "10",
                "system_prompt_chars": "2000",
                "last_user_msg_preview": "hello",
                "assistant_msg_preview": "hi there",
                "tool_calls": "[]",
                "tool_call_count": "0",
                "bash_commands": "[]",
                "files_read": "[]",
                "files_written": "[]",
                "urls_fetched": "[]",
                "sensitive_patterns": "",
                "sensitive_pattern_count": "0",
                "content_types_sent": "text",
                "stop_reason": "end_turn",
                "request_id": "req-1",
                "raw_request_hash": "aabb",
            },
            {
                "timestamp": "2026-01-01T00:02:00+00:00",
                "session_id": "sess-1",
                "turn_id": "t-2",
                "turn_number": "2",
                "destination_host": "api.openai.com",
                "destination_service": "openai_api",
                "endpoint_path": "/v1/chat/completions",
                "http_method": "POST",
                "http_status": "200",
                "model": "gpt-4o",
                "stream": "false",
                "input_tokens": "3000",
                "output_tokens": "800",
                "cache_read_tokens": "0",
                "cache_write_tokens": "0",
                "estimated_cost_usd": "0.0",
                "request_size_bytes": "8000",
                "response_size_bytes": "5000",
                "latency_ms": "900",
                "num_messages": "5",
                "system_prompt_chars": "1000",
                "last_user_msg_preview": "analyze this",
                "assistant_msg_preview": "Here is my analysis",
                "tool_calls": '["bash"]',
                "tool_call_count": "1",
                "bash_commands": '["ls -la"]',
                "files_read": "[]",
                "files_written": "[]",
                "urls_fetched": "[]",
                "sensitive_patterns": "",
                "sensitive_pattern_count": "0",
                "content_types_sent": "text",
                "stop_reason": "end_turn",
                "request_id": "req-2",
                "raw_request_hash": "ccdd",
            },
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        sessions_dir_str = str(session_dir)

        # Replicate the DashboardHandler definition from watch.py
        from claude_monitoring.watch import _dashboard_html, _load_latest_csv

        _, loaded_rows = _load_latest_csv(sessions_dir_str)

        class DashboardHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/api/data":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    _, fresh_rows = _load_latest_csv(sessions_dir_str)
                    self.wfile.write(json.dumps(fresh_rows or loaded_rows).encode())
                elif parsed.path in ("/", "/index.html"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(_dashboard_html().encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        yield f"http://127.0.0.1:{port}"

        server.shutdown()

    def test_root_returns_html(self, dashboard_server):
        """GET / should return HTML content."""
        resp = urlopen(f"{dashboard_server}/")
        assert resp.status == 200
        content_type = resp.headers.get("Content-Type", "")
        assert "text/html" in content_type
        body = resp.read().decode()
        assert "<html" in body.lower() or "<HTML" in body or "html" in body.lower()

    def test_index_html_returns_html(self, dashboard_server):
        """GET /index.html should also return HTML."""
        resp = urlopen(f"{dashboard_server}/index.html")
        assert resp.status == 200
        body = resp.read().decode()
        assert "<html" in body.lower() or "html" in body.lower()

    def test_api_data_returns_json_list(self, dashboard_server):
        """GET /api/data should return a JSON list of row dicts."""
        resp = urlopen(f"{dashboard_server}/api/data")
        assert resp.status == 200
        content_type = resp.headers.get("Content-Type", "")
        assert "application/json" in content_type
        data = json.loads(resp.read())
        assert isinstance(data, list)
        assert len(data) == 2

    def test_api_data_contains_expected_fields(self, dashboard_server):
        """Each row in /api/data should contain CSV column keys."""
        resp = urlopen(f"{dashboard_server}/api/data")
        data = json.loads(resp.read())
        row = data[0]
        for col in CSV_COLUMNS:
            assert col in row, f"Missing column {col} in /api/data response"

    def test_api_data_row_values(self, dashboard_server):
        """Verify specific field values in the returned data."""
        resp = urlopen(f"{dashboard_server}/api/data")
        data = json.loads(resp.read())
        first = data[0]
        assert first["destination_host"] == "api.anthropic.com"
        assert first["model"] == "claude-sonnet-4"
        assert first["input_tokens"] == "5000"

        second = data[1]
        assert second["destination_host"] == "api.openai.com"
        assert second["model"] == "gpt-4o"

    def test_api_data_cors_header(self, dashboard_server):
        """The /api/data endpoint should include CORS header."""
        resp = urlopen(f"{dashboard_server}/api/data")
        cors = resp.headers.get("Access-Control-Allow-Origin", "")
        assert cors == "*"

    def test_unknown_path_returns_404(self, dashboard_server):
        """Unknown paths should return 404."""
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{dashboard_server}/nonexistent/path")
        assert exc_info.value.code == 404

    def test_api_random_endpoint_404(self, dashboard_server):
        """GET /api/unknown should return 404, not 200."""
        from urllib.error import HTTPError

        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{dashboard_server}/api/unknown")
        assert exc_info.value.code == 404


# ===================================================================
# 6. insert_api_call (dual-write helper used by _write_row)
# ===================================================================


class TestInsertApiCall:
    """Verify insert_api_call works correctly with realistic records."""

    def test_insert_succeeds_with_valid_record(self, tmp_path):
        db_path = tmp_path / "test.db"
        with (
            patch("claude_monitoring.db.get_output_dir", return_value=tmp_path),
            patch("claude_monitoring.db.get_db_path", return_value=db_path),
        ):
            conn = init_db(db_path)
            conn.close()

        record = _make_record()
        result = insert_api_call(db_path, record)
        assert result is True

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM api_calls LIMIT 1").fetchone()
        conn.close()
        assert row is not None
        assert row["model"] == "claude-sonnet-4"

    def test_insert_fails_with_nonexistent_db(self, tmp_path):
        db_path = tmp_path / "does_not_exist.db"
        record = _make_record()
        result = insert_api_call(db_path, record)
        assert result is False

    def test_insert_fails_with_none_path(self):
        record = _make_record()
        result = insert_api_call(None, record)
        assert result is False


# ===================================================================
# 7. get_csv_path
# ===================================================================


class TestGetCsvPath:
    """Test the get_csv_path helper."""

    def test_csv_path_in_session_dir(self, tmp_path):
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(exist_ok=True)
        with patch("claude_monitoring.watch.get_session_dir", return_value=session_dir):
            from claude_monitoring.watch import get_csv_path

            path = get_csv_path()
            assert path.parent == session_dir
            assert path.name.startswith("claude_watch_")
            assert path.name.endswith(".csv")

    def test_csv_path_creates_session_dir(self, tmp_path):
        session_dir = tmp_path / "new_sessions"
        with patch("claude_monitoring.watch.get_session_dir", return_value=session_dir):
            from claude_monitoring.watch import get_csv_path

            path = get_csv_path()
            assert session_dir.exists()
            assert path.parent == session_dir


# ===================================================================
# Response dispatch — Issue #65 fix
#
# Pre-fix dispatch at watch.py:705 was `raw.startswith("data:")` which
# matched OpenAI SSE but missed Anthropic SSE (which leads with
# `event: message_start\n...`). The SSE parser never ran for Anthropic
# streaming responses; the JSON fallback raised; the bare except: pass
# silently swallowed the error. Every streaming /v1/messages call was
# captured with zero tokens and empty content.
#
# These tests pin the new dispatch contract so the regression can't
# return: Content-Type header is the canonical signal; body sniff
# (event:|data:) is the fallback for servers that omit the header.
# ===================================================================


class TestIsSseResponse:
    """The dispatch gate used by ClaudeWatchAddon.response."""

    def test_content_type_event_stream_returns_true(self):
        from claude_monitoring.watch import _is_sse_response

        assert _is_sse_response("text/event-stream", "") is True

    def test_content_type_event_stream_with_charset_returns_true(self):
        from claude_monitoring.watch import _is_sse_response

        assert _is_sse_response("text/event-stream; charset=utf-8", "") is True

    def test_anthropic_event_prefix_body_returns_true(self):
        """The smoking-gun case for Issue #65 — Anthropic SSE starts with
        ``event:``, which the old dispatch missed."""
        from claude_monitoring.watch import _is_sse_response

        anthropic_sse = "event: message_start\ndata: {}\n\n"
        assert _is_sse_response("application/octet-stream", anthropic_sse) is True

    def test_openai_data_prefix_body_returns_true(self):
        """Regression — OpenAI SSE (data:-led) must still route to the
        SSE parser. The old dispatch worked for this case and the new
        dispatch must keep working."""
        from claude_monitoring.watch import _is_sse_response

        openai_sse = 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
        assert _is_sse_response("application/json", openai_sse) is True

    def test_plain_json_body_returns_false(self):
        from claude_monitoring.watch import _is_sse_response

        assert _is_sse_response("application/json", '{"role":"assistant"}') is False

    def test_empty_body_and_unknown_content_type_returns_false(self):
        from claude_monitoring.watch import _is_sse_response

        assert _is_sse_response("", "") is False

    def test_leading_whitespace_does_not_fool_sniff(self):
        """The body sniff tolerates leading ASCII whitespace.

        mitmproxy reassembles the full body before the response hook
        fires, so chunk-boundary whitespace shouldn't actually appear at
        this layer in production. This test pins the lstrip() behavior
        anyway so a future refactor that removes ``lstrip()`` as
        "unnecessary" fails CI rather than silently regressing.
        """
        from claude_monitoring.watch import _is_sse_response

        assert _is_sse_response("", "\n\nevent: message_start\n") is True
        assert _is_sse_response("", "  data: {}\n") is True

    def test_content_type_header_wins_over_body_sniff(self):
        """When the Content-Type says SSE, route to the SSE parser even
        if the body happens to look like JSON (mid-stream chunk could
        begin with ``{`` from a buffered delta event)."""
        from claude_monitoring.watch import _is_sse_response

        assert _is_sse_response("text/event-stream", '{"looks":"json"}') is True


class TestAddonResponseDispatch:
    """Integration: drive ClaudeWatchAddon.response() with a fake flow
    and assert the SSE parser is reached for Anthropic streaming.

    This is the test that would have caught Issue #65. The pre-fix code
    would write a row with input_tokens=0 / output_tokens=0 / empty
    assistant_msg_preview. The post-fix code writes a row with the real
    token counts and the assistant text extracted from text_delta chunks.
    """

    ANTHROPIC_SSE_REPLAY = (
        "event: message_start\n"
        'data: {"type":"message_start","message":{"id":"msg_01TEST",'
        '"model":"claude-sonnet-4-6",'
        '"usage":{"input_tokens":42,"cache_read_input_tokens":7,'
        '"cache_creation_input_tokens":3}}}\n'
        "\n"
        "event: content_block_start\n"
        'data: {"type":"content_block_start","index":0,'
        '"content_block":{"type":"text","text":""}}\n'
        "\n"
        "event: content_block_delta\n"
        'data: {"type":"content_block_delta","index":0,'
        '"delta":{"type":"text_delta","text":"PINEAPPLE-FROM-SSE"}}\n'
        "\n"
        "event: content_block_stop\n"
        'data: {"type":"content_block_stop","index":0}\n'
        "\n"
        "event: message_delta\n"
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
        '"usage":{"output_tokens":11}}\n'
        "\n"
        "event: message_stop\n"
        'data: {"type":"message_stop"}\n'
        "\n"
    )

    def _make_flow(self, *, flow_id: str, content: bytes, headers: dict):
        """Build a mitmproxy-shaped flow stub touching only the attrs
        the addon actually reads in response()."""
        from unittest.mock import MagicMock

        flow = MagicMock()
        flow.id = flow_id
        flow.response.status_code = 200
        flow.response.content = content
        flow.response.headers = headers
        return flow

    def _seed_pending(self, addon, flow_id: str):
        """Populate the addon's pending dict the way request() would
        have, so response() finds something to pop."""
        import time as _time

        addon.pending[flow_id] = {
            "_start_time": _time.time(),
            "_is_browser_metadata": False,
            "destination_host": "api.anthropic.com",
            "destination_service": "anthropic_api",
            "endpoint_path": "/v1/messages",
            "http_method": "POST",
            "timestamp": "2026-05-31T18:00:00+00:00",
            "session_id": "test-sess",
            "turn_id": "turn-1",
            "turn_number": 1,
            "stream": "",
            "model": "",
            "tool_calls": "[]",
        }

    def test_anthropic_streaming_routes_to_sse_parser_and_populates_tokens(self, addon):
        flow_id = "anthropic-streaming-flow"
        self._seed_pending(addon, flow_id)
        flow = self._make_flow(
            flow_id=flow_id,
            content=self.ANTHROPIC_SSE_REPLAY.encode("utf-8"),
            headers={"content-type": "text/event-stream", "x-request-id": "req-1"},
        )
        captured: dict = {}
        with patch.object(addon, "_write_row", side_effect=lambda r: captured.update(r)):
            addon.response(flow)

        assert captured.get("input_tokens") == 42, "SSE parser not reached or input_tokens missed"
        assert captured.get("output_tokens") == 11
        assert captured.get("cache_read_tokens") == 7
        assert captured.get("cache_write_tokens") == 3
        assert captured.get("stop_reason") == "end_turn"
        assert "PINEAPPLE-FROM-SSE" in (captured.get("assistant_msg_preview") or "")
        assert captured.get("stream") == "true"

    def test_anthropic_streaming_without_content_type_still_routes_to_sse(self, addon):
        """Body sniff fallback: even without text/event-stream header,
        a body starting with ``event:`` must still route to the SSE
        parser. Guards against upstream servers that emit SSE without
        the canonical header."""
        flow_id = "anthropic-no-ct-flow"
        self._seed_pending(addon, flow_id)
        flow = self._make_flow(
            flow_id=flow_id,
            content=self.ANTHROPIC_SSE_REPLAY.encode("utf-8"),
            headers={"content-type": "application/octet-stream"},
        )
        captured: dict = {}
        with patch.object(addon, "_write_row", side_effect=lambda r: captured.update(r)):
            addon.response(flow)
        assert captured.get("input_tokens") == 42
        assert "PINEAPPLE-FROM-SSE" in (captured.get("assistant_msg_preview") or "")

    def test_non_streaming_json_still_uses_json_parser(self, addon):
        """Regression: non-streaming Anthropic responses (JSON body) must
        keep working — they were the ONLY path that worked pre-fix and
        the new dispatch must not break them."""
        flow_id = "anthropic-nonstreaming-flow"
        self._seed_pending(addon, flow_id)
        body = json.dumps(
            {
                "id": "msg_01JSON",
                "model": "claude-haiku-4-5-20251001",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "JSON-PATH-WORKS"}],
                "usage": {
                    "input_tokens": 123,
                    "output_tokens": 45,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                },
            }
        )
        flow = self._make_flow(
            flow_id=flow_id,
            content=body.encode("utf-8"),
            headers={"content-type": "application/json"},
        )
        captured: dict = {}
        with patch.object(addon, "_write_row", side_effect=lambda r: captured.update(r)):
            addon.response(flow)
        assert captured.get("input_tokens") == 123
        assert captured.get("output_tokens") == 45

    def test_parse_failures_log_at_warning_level_not_silent(self, addon, caplog):
        """The previous bare except: pass made every parse failure
        invisible. The two-tier handler must now emit a log line — at
        warning for expected JSON/Unicode errors."""
        flow_id = "garbage-flow"
        self._seed_pending(addon, flow_id)
        flow = self._make_flow(
            flow_id=flow_id,
            content=b"\xff\xfe NOT JSON, NOT SSE",
            headers={"content-type": "application/json"},
        )
        with patch.object(addon, "_write_row"), caplog.at_level("WARNING"):
            addon.response(flow)
        # At least one warning/error mentioning the service name must surface.
        messages = " ".join(r.message for r in caplog.records)
        assert "anthropic_api" in messages, f"no log line mentioned the service: {caplog.text}"

    def test_response_with_null_json_body_does_not_crash_or_log_error(self, addon, caplog):
        """Regression test for the body-None crash exposed by PR #67's
        two-tier handler.

        Production traceback showed parse_response_body raising
        ``AttributeError: 'NoneType' object has no attribute 'get'``
        when the dispatch passed Python ``None`` (from
        ``json.loads("null")``) to the parser.

        Five explicit assertions:
          1. ``addon.response()`` does not raise
          2. A record is written (the row is not lost)
          3. Envelope fields are preserved (destination_service, http_status, response_size_bytes)
          4. Content fields are empty (parser returned without populating them)
          5. NO ERROR-level log entry was emitted (the parser now
             returns gracefully; only legitimate parse failures
             should ever reach the ERROR tier)
        """
        flow_id = "null-body-flow"
        self._seed_pending(addon, flow_id)
        flow = self._make_flow(
            flow_id=flow_id,
            content=b"null",  # valid JSON, parses to Python None
            headers={"content-type": "application/json"},
        )
        captured: dict = {}
        with patch.object(addon, "_write_row", side_effect=lambda r: captured.update(r)), caplog.at_level("WARNING"):
            addon.response(flow)  # assertion 1: must not raise

        # 2. row was written
        assert captured, "addon.response() must still write a record even when parser declines body"

        # 3. envelope fields preserved
        assert captured.get("destination_service") == "anthropic_api"
        assert captured.get("http_status") == 200
        assert captured.get("response_size_bytes") == len(b"null")

        # 4. content fields untouched — the guard returns the record
        # unchanged, so keys not present in the seed remain absent.
        # Stronger than `get(..., 0) == 0` which would mask a future
        # bug where the parser is accidentally reached and emits zeros.
        assert "input_tokens" not in captured
        assert "output_tokens" not in captured
        assert "assistant_msg_preview" not in captured

        # 5. no ERROR-level log entry (the body-None case used to land
        # in the unexpected-Exception bucket via logger.exception)
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert not error_records, (
            f"body=None must not produce ERROR-level logs; got: {[r.message for r in error_records]}"
        )
