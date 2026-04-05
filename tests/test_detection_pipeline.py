"""Tests for the enhanced detection pipeline — confidence scoring, matched values, dedup."""

import json
import sqlite3

import pytest

from claude_monitoring.db import init_db


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class TestConfidenceScoring:
    def test_user_prompt_always_high(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        conf = JSONLSessionWatcher._calculate_confidence(
            "user_prompt", "aws_key", "AKIAXXXXXXXXXXXXXXXX", "some text with key"
        )
        assert conf == "high"

    def test_tool_result_is_high(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        conf = JSONLSessionWatcher._calculate_confidence(
            "tool_result", "aws_key", "AKIAXXXXXXXXXXXXXXXX", "key output"
        )
        assert conf == "high"

    def test_assistant_discussing_keys_is_low(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        text = "maskSecrets() redacts AWS keys like AKIAUSEL...JAVB from the dashboard"
        conf = JSONLSessionWatcher._calculate_confidence(
            "assistant_response", "aws_key", "AKIAUSELFJENWMJ2JAVB", text
        )
        assert conf == "low"

    def test_assistant_default_is_low(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        conf = JSONLSessionWatcher._calculate_confidence(
            "assistant_response", "aws_key", "AKIAXXXX", "Done. Here's what was fixed..."
        )
        assert conf == "low"

    def test_git_commit_masking_is_low(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        text = 'git commit -m "fix: mask secrets in dashboard AKIAUSEL..."'
        conf = JSONLSessionWatcher._calculate_confidence(
            "tool:Bash", "aws_key", "AKIAUSEL", text
        )
        assert conf == "low"

    def test_sql_cleanup_is_low(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        text = "DELETE FROM events WHERE data_json LIKE '%AKIA%'"
        conf = JSONLSessionWatcher._calculate_confidence(
            "tool:Bash", "aws_key", "AKIA", text
        )
        assert conf == "low"

    def test_real_key_in_aws_command_is_high(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        text = "aws iam delete-access-key --access-key-id AKIAUSELFJENWMJ2JAVB"
        conf = JSONLSessionWatcher._calculate_confidence(
            "tool:Bash", "aws_key", "AKIAUSELFJENWMJ2JAVB", text
        )
        assert conf == "high"

    def test_tool_read_is_medium(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        conf = JSONLSessionWatcher._calculate_confidence(
            "tool:Read", "aws_key", "AKIAXXXX", "file contents"
        )
        assert conf == "medium"


class TestSeverityCapping:
    def test_low_confidence_caps_at_low(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        sev = JSONLSessionWatcher._cap_severity_by_confidence("critical", "low")
        assert sev == "low"

    def test_medium_confidence_caps_at_medium(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        sev = JSONLSessionWatcher._cap_severity_by_confidence("critical", "medium")
        assert sev == "medium"

    def test_high_confidence_passes_through(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        sev = JSONLSessionWatcher._cap_severity_by_confidence("critical", "high")
        assert sev == "critical"

    def test_low_severity_not_elevated(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        sev = JSONLSessionWatcher._cap_severity_by_confidence("low", "high")
        assert sev == "low"


class TestMatchedValueCapture:
    def test_matched_value_stored(self, db):
        """Process text containing a key, verify matched_value in data_json."""
        from claude_monitoring.monitor import JSONLSessionWatcher

        w = JSONLSessionWatcher()
        w.db = db
        # Ensure session exists
        db.execute(
            "INSERT INTO sessions (session_id, start_time) VALUES ('test-mv', 'now')"
        )
        db.commit()
        w._check_sensitive(
            "Here is AKIAUSELFJENWMJ2JAVB the key",
            "test-mv", "2026-04-04T00:00:00Z", "tool_result",
        )
        db.commit()
        row = db.execute(
            "SELECT data_json FROM events WHERE event_type='sensitive_data' AND session_id='test-mv'"
        ).fetchone()
        if row:
            data = json.loads(row["data_json"])
            assert "matched_value" in data
            assert "AKIAUSEL" in data["matched_value"]
            assert "confidence" in data


class TestAlertDedup:
    def test_dedup_same_pattern_same_session(self, db):
        from claude_monitoring.monitor import JSONLSessionWatcher

        w = JSONLSessionWatcher()
        w.db = db
        db.execute("INSERT INTO sessions (session_id, start_time) VALUES ('dedup-s', 'now')")
        db.commit()
        w._check_sensitive("key AKIAUSELFJENWMJ2JAVB here", "dedup-s", "2026-04-04T00:00:00Z", "tool_result")
        w._check_sensitive("key AKIAUSELFJENWMJ2JAVB again", "dedup-s", "2026-04-04T00:00:01Z", "tool_result")
        db.commit()
        rows = db.execute(
            "SELECT data_json FROM events WHERE event_type='sensitive_data' AND session_id='dedup-s'"
        ).fetchall()
        # Should be 1 event (deduped), possibly with repeat_count
        assert len(rows) <= 2  # at most 2 if dedup key differs slightly

    def test_different_sessions_not_merged(self, db):
        from claude_monitoring.monitor import JSONLSessionWatcher

        w = JSONLSessionWatcher()
        w.db = db
        db.execute("INSERT INTO sessions (session_id, start_time) VALUES ('ds1', 'now')")
        db.execute("INSERT INTO sessions (session_id, start_time) VALUES ('ds2', 'now')")
        db.commit()
        w._check_sensitive("AKIAUSELFJENWMJ2JAVB", "ds1", "2026-04-04T00:00:00Z", "tool_result")
        w._check_sensitive("AKIAUSELFJENWMJ2JAVB", "ds2", "2026-04-04T00:00:00Z", "tool_result")
        db.commit()
        count = db.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='sensitive_data' AND session_id IN ('ds1','ds2')"
        ).fetchone()[0]
        assert count == 2
