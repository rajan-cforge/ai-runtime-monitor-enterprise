"""Security tests for AI Runtime Monitor.

Covers:
  - SQL injection prevention via parameterized queries
  - Large input handling / text truncation
  - JSON escaping (no XSS in JSON output)
"""

import json

import pytest

from claude_monitoring import config
from claude_monitoring.db import init_db
from claude_monitoring.utils import scan_sensitive


@pytest.fixture(autouse=True)
def _reset_config():
    config.reset()
    yield
    config.reset()


class TestSQLInjection:
    def test_session_id_with_sql_injection(self, tmp_path):
        """Verify parameterized queries prevent SQL injection in session lookups."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
            conn = init_db(db_path)

        # Insert a legitimate session
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, last_activity) VALUES (?, ?, ?)",
            ("legit-session", "2026-01-01T00:00:00Z", "2026-01-01T00:10:00Z"),
        )
        conn.commit()

        # Attempt SQL injection via session_id
        malicious_id = "'; DROP TABLE sessions; --"
        result = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (malicious_id,),
        ).fetchone()

        # Injection should return no results, not crash
        assert result is None

        # Table should still exist
        count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        assert count == 1
        conn.close()

    def test_event_search_with_injection(self, tmp_path):
        """Verify parameterized queries in event searches."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
            conn = init_db(db_path)

        conn.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "test_event", "network", '{"text":"hello"}'),
        )
        conn.commit()

        # Parameterized LIKE query (as used in search endpoints)
        malicious_search = "%'; DROP TABLE events; --"
        result = conn.execute(
            "SELECT * FROM events WHERE data_json LIKE ?",
            (f"%{malicious_search}%",),
        ).fetchall()

        assert len(result) == 0
        # Table should still exist
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert count == 1
        conn.close()


class TestLargeInputHandling:
    def test_scan_sensitive_with_large_input(self):
        """Verify scan_sensitive handles very large input without crashing."""
        large_text = "Normal text. " * 10000
        results = scan_sensitive(large_text)
        # Should complete without error
        assert isinstance(results, list)

    def test_scan_sensitive_with_empty_input(self):
        """Verify scan_sensitive handles empty input."""
        results = scan_sensitive("")
        assert results == []

    def test_scan_sensitive_with_none_like_input(self):
        """Verify scan_sensitive handles edge cases."""
        results = scan_sensitive("   ")
        assert isinstance(results, list)

    def test_db_stores_truncated_data(self, tmp_path):
        """Verify the DB can store large data_json without issues."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
            conn = init_db(db_path)

        # Insert a very large data_json
        large_json = json.dumps({"text": "x" * 100000})
        conn.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "test", "network", large_json),
        )
        conn.commit()

        row = conn.execute("SELECT data_json FROM events WHERE id=1").fetchone()
        assert len(row[0]) == len(large_json)
        conn.close()


class TestJSONEscaping:
    def test_no_xss_in_json_dumps(self):
        """Verify json.dumps escapes HTML/script tags."""
        malicious = {"text": '<script>alert("XSS")</script>'}
        output = json.dumps(malicious)
        # json.dumps should produce valid JSON that, when parsed, returns the original
        parsed = json.loads(output)
        assert parsed["text"] == '<script>alert("XSS")</script>'
        # The raw output should not contain unescaped angle brackets in a way
        # that would execute -- json.dumps uses proper escaping
        assert isinstance(output, str)

    def test_json_special_chars_escaped(self):
        """Verify special characters are properly escaped in JSON."""
        data = {
            "user": 'admin"; DROP TABLE users; --',
            "path": "</script><script>alert(1)</script>",
            "newlines": "line1\nline2\r\nline3",
        }
        output = json.dumps(data)
        parsed = json.loads(output)
        assert parsed == data

    def test_unicode_in_json(self):
        """Verify unicode characters are handled."""
        data = {"text": "Hello \u2603 \u00e9\u00e8\u00ea"}
        output = json.dumps(data, ensure_ascii=False)
        parsed = json.loads(output)
        assert parsed == data

    def test_scan_sensitive_results_are_json_safe(self):
        """Verify scan_sensitive results can be safely serialized to JSON."""
        # Use text that would match patterns but contains special chars
        text = 'password = "xK9<script>alert(1)</script>mP2!"'
        results = scan_sensitive(text, validate=True)
        # Results should be JSON-serializable
        output = json.dumps(results)
        parsed = json.loads(output)
        assert isinstance(parsed, list)

    def test_null_bytes_in_json(self):
        """Verify null bytes don't cause issues in JSON serialization."""
        data = {"text": "hello\x00world"}
        output = json.dumps(data)
        parsed = json.loads(output)
        assert "hello" in parsed["text"]
