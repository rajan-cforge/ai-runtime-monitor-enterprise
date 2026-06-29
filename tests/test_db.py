"""Tests for init_db() and database operations."""

import sqlite3

from claude_monitoring.db import get_thread_db, init_db, insert_api_call


class TestInitDb:
    def _init(self, tmp_path):
        db_path = tmp_path / "test.db"
        (tmp_path / "output").mkdir(exist_ok=True)
        conn = init_db(db_path)
        return conn, db_path

    def test_creates_all_tables(self, tmp_path):
        conn, _ = self._init(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cursor.fetchall()}
        expected = {"events", "sessions", "processes", "connections", "file_events", "browser_sessions", "api_calls"}
        assert expected.issubset(tables)
        conn.close()

    def test_idempotent(self, tmp_path):
        """Calling init_db twice should not error."""
        db_path = tmp_path / "test.db"
        conn1 = init_db(db_path)
        conn1.close()
        conn2 = init_db(db_path)
        conn2.close()

    def test_wal_mode(self, tmp_path):
        conn, _ = self._init(tmp_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_busy_timeout_30s(self, tmp_path):
        """The discovery-scheduler operator-path demo (2026-06-13)
        revealed the default 5s busy_timeout was too short for the
        scheduler's ~1094-asset persist to outlast the
        JSONLSessionWatcher's bulk writes. 30s gives headroom."""
        conn, _ = self._init(tmp_path)
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 30000, f"busy_timeout should be 30000ms, got {timeout}"
        conn.close()

    def test_session_insert_update(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, model) VALUES (?, ?, ?)",
            ("test-123", "2026-01-01T00:00:00Z", "claude-sonnet-4"),
        )
        conn.execute("UPDATE sessions SET total_turns = 5 WHERE session_id = ?", ("test-123",))
        conn.commit()
        row = conn.execute("SELECT total_turns FROM sessions WHERE session_id = ?", ("test-123",)).fetchone()
        assert row[0] == 5
        conn.close()

    def test_event_storage(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "sess-1", "user_prompt", "network", '{"text":"hello"}'),
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        assert row[0] == 1
        conn.close()

    def test_indexes_created(self, tmp_path):
        conn, _ = self._init(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_events_ts" in indexes
        assert "idx_events_session" in indexes
        assert "idx_api_calls_ts" in indexes
        assert "idx_api_calls_session" in indexes
        conn.close()

    def test_file_events_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO file_events (timestamp, path, operation) VALUES (?, ?, ?)",
            ("2026-01-01T00:00:00Z", "/tmp/test.py", "created"),
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM file_events").fetchone()
        assert row[0] == 1
        conn.close()

    def test_browser_sessions_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            "INSERT INTO browser_sessions (service, visit_time) VALUES (?, ?)", ("ChatGPT", "2026-01-01T00:00:00Z")
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()
        assert row[0] == 1
        conn.close()

    def test_api_calls_table(self, tmp_path):
        conn, _ = self._init(tmp_path)
        conn.execute(
            """INSERT INTO api_calls (timestamp, session_id, destination_service, model, input_tokens, output_tokens)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("2026-01-01T00:00:00Z", "sess-1", "anthropic_api", "claude-sonnet-4", 1000, 500),
        )
        conn.commit()
        row = conn.execute("SELECT COUNT(*) FROM api_calls").fetchone()
        assert row[0] == 1
        conn.close()


class TestInsertApiCall:
    def test_insert_api_call_success(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        record = {
            "timestamp": "2026-01-01T00:00:00Z",
            "session_id": "test-123",
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
            "estimated_cost_usd": 0.0,
            "latency_ms": 1500,
            "stop_reason": "end_turn",
            "request_id": "req-abc",
        }
        result = insert_api_call(db_path, record)
        assert result is True

        # Verify data was inserted
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT COUNT(*) FROM api_calls").fetchone()
        assert row[0] == 1
        conn.close()

    def test_insert_api_call_no_db(self, tmp_path):
        db_path = tmp_path / "nonexistent.db"
        result = insert_api_call(db_path, {"timestamp": "now"})
        assert result is False

    def test_insert_api_call_none_path(self):
        result = insert_api_call(None, {"timestamp": "now"})
        assert result is False

    def test_insert_api_call_defaults(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        # Minimal record — should use defaults for missing fields
        record = {"timestamp": "2026-01-01T00:00:00Z"}
        result = insert_api_call(db_path, record)
        assert result is True


class TestGetThreadDb:
    """`get_thread_db` is the per-thread connection helper used by the
    dashboard handler. Each call returns a new connection with WAL + 30s
    busy_timeout + Row factory — the same PRAGMA contract `init_db`
    establishes, mirrored here so dashboard reader threads tolerate the
    daemon's bulk writes (see db.py:467-470 for the operator-path-demo
    rationale).
    """

    def test_returns_connection_with_row_factory(self, tmp_path):
        """Row factory must be sqlite3.Row so dashboard handlers can use
        column-name access on query results."""
        db_path = tmp_path / "test.db"
        init_db(db_path).close()  # bootstrap the file so get_thread_db can open it

        conn = get_thread_db(db_path)
        assert conn.row_factory is sqlite3.Row
        # Verify column-name access works in practice:
        conn.execute("CREATE TABLE _probe (k TEXT, v INTEGER)")
        conn.execute("INSERT INTO _probe (k, v) VALUES ('hello', 42)")
        row = conn.execute("SELECT k, v FROM _probe").fetchone()
        assert row["k"] == "hello"
        assert row["v"] == 42
        conn.close()

    def test_pragmas_applied(self, tmp_path):
        """WAL journal + NORMAL sync + 30s busy_timeout — mirrors init_db
        (P4.5 operator-path-demo fix; bulk-write tolerance)."""
        db_path = tmp_path / "test.db"
        init_db(db_path).close()

        conn = get_thread_db(db_path)
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert journal_mode.lower() == "wal"
        # busy_timeout in ms; init_db sets the file-level value to 30000,
        # so the per-connection get_thread_db read should observe it.
        busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert busy_timeout >= 30000, f"busy_timeout {busy_timeout}ms < 30000ms"
        conn.close()

    def test_separate_connections_per_call(self, tmp_path):
        """Each get_thread_db() call returns a fresh connection object
        — the caller (handler) owns its lifecycle. The thread-locality
        is enforced by the handler's caching layer, not by this helper."""
        db_path = tmp_path / "test.db"
        init_db(db_path).close()

        c1 = get_thread_db(db_path)
        c2 = get_thread_db(db_path)
        assert c1 is not c2
        c1.close()
        c2.close()
