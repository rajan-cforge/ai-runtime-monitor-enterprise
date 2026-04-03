"""Tests for JSONLSessionWatcher and JSONLFileHandler classes.

Covers the JSONL transcript processing pipeline (~380 lines of monitor.py):
  - Session management (_ensure_session, _update_session_stats)
  - Event storage (_store_event)
  - Sensitive data detection (_check_sensitive)
  - JSONL file processing (process_jsonl_file, _process_record)
  - Record type handlers (_process_user_message, _process_assistant_message,
    _process_progress)
  - File handler (JSONLFileHandler)
"""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring.db import init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def watcher(tmp_path):
    """Create a JSONLSessionWatcher backed by a real in-memory SQLite DB.

    Patches get_thread_db so that the watcher.__init__ path uses our
    test database and also patches push_live_event to avoid side effects.
    """
    db_path = tmp_path / "test_watcher.db"
    conn = init_db(db_path)

    with (
        patch("claude_monitoring.monitor.get_thread_db", return_value=conn),
        patch("claude_monitoring.monitor.push_live_event"),
    ):
        from claude_monitoring.monitor import JSONLSessionWatcher

        w = JSONLSessionWatcher()
        w.db = conn  # belt-and-suspenders
        yield w

    conn.close()


@pytest.fixture()
def db(watcher):
    """Shortcut to the watcher's database connection."""
    return watcher.db


def _count(db, table, where="1=1", params=()):
    return db.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]  # nosec B608


def _rows(db, table, where="1=1", params=()):
    return db.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()  # nosec B608


# ---------------------------------------------------------------------------
# _ensure_session
# ---------------------------------------------------------------------------


class TestEnsureSession:
    def test_insert_new_session(self, watcher, db):
        watcher._ensure_session("sess-1", "/tmp/test.jsonl", cwd="/home/user", start_time="2026-01-01T00:00:00Z")

        row = db.execute("SELECT * FROM sessions WHERE session_id='sess-1'").fetchone()
        assert row is not None
        # session_id, start_time, cwd, model, total_input_tokens,
        # total_output_tokens, total_turns, jsonl_path, last_activity, title
        assert row[0] == "sess-1"
        assert row[1] == "2026-01-01T00:00:00Z"
        assert row[2] == "/home/user"
        assert row[8] == "/tmp/test.jsonl"

    def test_upsert_same_session_no_error(self, watcher, db):
        """Calling _ensure_session twice with the same ID must not raise."""
        watcher._ensure_session("sess-dup", "/a.jsonl", cwd="/a")
        watcher._ensure_session("sess-dup", "/b.jsonl", cwd="/b")

        count = _count(db, "sessions", "session_id='sess-dup'")
        assert count == 1

    def test_upsert_preserves_first_values_and_updates_last_activity(self, watcher, db):
        watcher._ensure_session("sess-u", "/first.jsonl", cwd="/first", start_time="2026-01-01T00:00:00Z")
        watcher._ensure_session("sess-u", "/second.jsonl", cwd="/second", start_time="2026-02-01T00:00:00Z")

        row = db.execute("SELECT cwd, jsonl_path FROM sessions WHERE session_id='sess-u'").fetchone()
        # ON CONFLICT updates cwd and jsonl_path with COALESCE(excluded, existing)
        # Since both are non-null, the new value wins
        assert row[0] == "/second"
        assert row[1] == "/second.jsonl"

    def test_none_cwd_preserves_existing(self, watcher, db):
        watcher._ensure_session("sess-nc", "/a.jsonl", cwd="/original")
        watcher._ensure_session("sess-nc", None, cwd=None)

        row = db.execute("SELECT cwd FROM sessions WHERE session_id='sess-nc'").fetchone()
        assert row[0] == "/original"

    def test_default_start_time(self, watcher, db):
        """When start_time is None, now_iso() is used."""
        watcher._ensure_session("sess-ts", "/a.jsonl")
        row = db.execute("SELECT start_time FROM sessions WHERE session_id='sess-ts'").fetchone()
        assert row[0] is not None
        assert len(row[0]) > 10  # ISO timestamp


# ---------------------------------------------------------------------------
# _update_session_stats
# ---------------------------------------------------------------------------


class TestUpdateSessionStats:
    def _seed(self, watcher):
        watcher._ensure_session("stats-1", "/tmp/s.jsonl")

    def test_set_model(self, watcher, db):
        self._seed(watcher)
        watcher._update_session_stats("stats-1", model="claude-sonnet-4")

        row = db.execute("SELECT model FROM sessions WHERE session_id='stats-1'").fetchone()
        assert row[0] == "claude-sonnet-4"

    def test_increment_tokens(self, watcher, db):
        self._seed(watcher)
        watcher._update_session_stats("stats-1", input_tokens=100, output_tokens=50)
        watcher._update_session_stats("stats-1", input_tokens=200, output_tokens=75)

        row = db.execute(
            "SELECT total_input_tokens, total_output_tokens FROM sessions WHERE session_id='stats-1'"
        ).fetchone()
        assert row[0] == 300
        assert row[1] == 125

    def test_increment_turns(self, watcher, db):
        self._seed(watcher)
        watcher._update_session_stats("stats-1", is_turn=True)
        watcher._update_session_stats("stats-1", is_turn=True)
        watcher._update_session_stats("stats-1", is_turn=True)

        row = db.execute("SELECT total_turns FROM sessions WHERE session_id='stats-1'").fetchone()
        assert row[0] == 3

    def test_no_turn_increment_when_false(self, watcher, db):
        self._seed(watcher)
        watcher._update_session_stats("stats-1", is_turn=False)

        row = db.execute("SELECT total_turns FROM sessions WHERE session_id='stats-1'").fetchone()
        assert row[0] == 0

    def test_combined_update(self, watcher, db):
        self._seed(watcher)
        watcher._update_session_stats(
            "stats-1", model="claude-opus-4", input_tokens=500, output_tokens=100, is_turn=True
        )

        row = db.execute(
            "SELECT model, total_input_tokens, total_output_tokens, total_turns "
            "FROM sessions WHERE session_id='stats-1'"
        ).fetchone()
        assert row[0] == "claude-opus-4"
        assert row[1] == 500
        assert row[2] == 100
        assert row[3] == 1


# ---------------------------------------------------------------------------
# _store_event
# ---------------------------------------------------------------------------


class TestStoreEvent:
    def test_store_basic_event(self, watcher, db):
        watcher._store_event("2026-01-01T00:00:00Z", "sess-e", "user_prompt", "network", {"text": "hello"})
        # Force commit (batch threshold is 50)
        db.commit()

        row = db.execute("SELECT * FROM events WHERE session_id='sess-e'").fetchone()
        assert row is not None
        # id, timestamp, session_id, event_type, source_layer, data_json
        assert row[1] == "2026-01-01T00:00:00Z"
        assert row[3] == "user_prompt"
        assert row[4] == "network"
        data = json.loads(row[5])
        assert data["text"] == "hello"

    def test_dict_data_is_serialized(self, watcher, db):
        complex_data = {"name": "Bash", "input": {"command": "ls -la"}, "count": 42}
        watcher._store_event("2026-01-01T00:00:00Z", "sess-e2", "tool_use", "network", complex_data)
        db.commit()

        row = db.execute("SELECT data_json FROM events WHERE session_id='sess-e2'").fetchone()
        parsed = json.loads(row[0])
        assert parsed["name"] == "Bash"
        assert parsed["input"]["command"] == "ls -la"
        assert parsed["count"] == 42

    def test_batch_commit_threshold(self, watcher, db):
        """After 50 events, pending_commits resets (batch commit)."""
        for i in range(55):
            watcher._store_event("2026-01-01T00:00:00Z", "sess-batch", "test_event", "network", {"i": i})

        # After 50 events, a commit fires and resets the counter
        # The counter should be 5 at this point (55 - 50)
        assert watcher._pending_commits == 5

    def test_pending_commits_increments(self, watcher, db):
        assert watcher._pending_commits == 0
        watcher._store_event("2026-01-01T00:00:00Z", "sess-pc", "test", "network", {})
        assert watcher._pending_commits == 1


# ---------------------------------------------------------------------------
# _make_summary
# ---------------------------------------------------------------------------


class TestMakeSummary:
    def test_user_prompt_short(self, watcher):
        summary = watcher._make_summary("user_prompt", {"text": "hello"})
        assert summary == 'prompt: "hello"'

    def test_user_prompt_long(self, watcher):
        long_text = "x" * 100
        summary = watcher._make_summary("user_prompt", {"text": long_text})
        assert summary.startswith('prompt: "')
        assert summary.endswith('..."')

    def test_assistant_response(self, watcher):
        summary = watcher._make_summary("assistant_response", {"text": "Hi there"})
        assert summary == 'response: "Hi there"'

    def test_thinking(self, watcher):
        summary = watcher._make_summary("thinking", {"length": 500})
        assert summary == "thinking (500 chars)"

    def test_tool_use(self, watcher):
        summary = watcher._make_summary("tool_use", {"name": "Bash", "input_preview": "ls -la"})
        assert summary == "Bash: ls -la"

    def test_tool_result(self, watcher):
        summary = watcher._make_summary("tool_result", {"length": 1234})
        assert summary == "result (1234 chars)"

    def test_token_usage(self, watcher):
        summary = watcher._make_summary("token_usage", {"input_tokens": 100, "output_tokens": 50})
        assert summary == "\u2191100t \u219350t"

    def test_sensitive_data(self, watcher):
        summary = watcher._make_summary(
            "sensitive_data", {"severity": "critical", "patterns": ["aws_key", "openai_key"]}
        )
        assert "CRITICAL" in summary
        assert "aws_key" in summary

    def test_unknown_event_type(self, watcher):
        summary = watcher._make_summary("some_custom_event", {})
        assert summary == "some_custom_event"


# ---------------------------------------------------------------------------
# _check_sensitive
# ---------------------------------------------------------------------------


class TestCheckSensitive:
    def test_aws_key_creates_alert(self, watcher, db):
        watcher._ensure_session("sens-1", "/tmp/s.jsonl")
        watcher._check_sensitive("AKIAI44QH8DHBR3XYZAB credentials", "sens-1", "2026-01-01T00:00:00Z", "user_prompt")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-1' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) >= 1
        data = json.loads(rows[0][0])
        assert "aws_key" in data["patterns"]
        assert data["severity"] == "critical"
        assert data["context"] == "user_prompt"

    def test_clean_text_no_alert(self, watcher, db):
        watcher._ensure_session("sens-2", "/tmp/s.jsonl")
        watcher._check_sensitive("This is perfectly normal text", "sens-2", "2026-01-01T00:00:00Z", "user_prompt")
        db.commit()

        count = _count(db, "events", "session_id='sens-2' AND event_type='sensitive_data'")
        assert count == 0

    def test_none_text_no_crash(self, watcher, db):
        """Passing None should be a no-op, not a crash."""
        watcher._check_sensitive(None, "sens-3", "2026-01-01T00:00:00Z", "user_prompt")
        # Just verifying no exception was raised

    def test_empty_text_no_crash(self, watcher, db):
        watcher._check_sensitive("", "sens-4", "2026-01-01T00:00:00Z", "user_prompt")

    def test_multiple_patterns_detected(self, watcher, db):
        """Text with multiple sensitive patterns creates one event with all patterns."""
        watcher._ensure_session("sens-5", "/tmp/s.jsonl")
        text = "AKIAI44QH8DHBR3XYZAB and -----BEGIN RSA PRIVATE KEY-----"
        watcher._check_sensitive(text, "sens-5", "2026-01-01T00:00:00Z", "tool_result")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-5' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) == 1
        data = json.loads(rows[0][0])
        assert "aws_key" in data["patterns"]
        assert "private_key" in data["patterns"]
        assert data["severity"] == "critical"
        assert "credential" in data["categories"]

    def test_snippet_is_truncated(self, watcher, db):
        watcher._ensure_session("sens-6", "/tmp/s.jsonl")
        long_text = "AKIAI44QH8DHBR3XYZAB " + "a" * 500
        watcher._check_sensitive(long_text, "sens-6", "2026-01-01T00:00:00Z", "user_prompt")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-6' AND event_type='sensitive_data'"
        ).fetchone()
        data = json.loads(row[0])
        assert len(data["snippet"]) <= 200

    def test_known_example_secret_filtered_out(self, watcher, db):
        """Known example AWS keys should not trigger alerts."""
        watcher._ensure_session("sens-ex-1", "/tmp/s.jsonl")
        watcher._check_sensitive("AKIAIOSFODNN7EXAMPLE in docs", "sens-ex-1", "2026-01-01T00:00:00Z", "user_prompt")
        db.commit()

        count = _count(db, "events", "session_id='sens-ex-1' AND event_type='sensitive_data'")
        assert count == 0

    def test_context_aware_tool_result_with_tests_path(self, watcher, db):
        """Tool result containing /tests/ path should downgrade severity to low."""
        watcher._ensure_session("sens-ctx-1", "/tmp/s.jsonl")
        text = "AKIAI44QH8DHBR3XYZAB found in /tests/test_auth.py"
        watcher._check_sensitive(text, "sens-ctx-1", "2026-01-01T00:00:00Z", "tool_result")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-ctx-1' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) >= 1
        data = json.loads(rows[0][0])
        assert data["severity"] == "low"

    def test_context_aware_assistant_discussing_security(self, watcher, db):
        """Assistant discussing security findings should downgrade from critical to medium."""
        watcher._ensure_session("sens-ctx-2", "/tmp/s.jsonl")
        text = "I found AKIAI44QH8DHBR3XYZAB in the code and detected a credential leak. You should rotate this key."
        watcher._check_sensitive(text, "sens-ctx-2", "2026-01-01T00:00:00Z", "assistant_response")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-ctx-2' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) >= 1
        data = json.loads(rows[0][0])
        assert data["severity"] == "medium"

    def test_context_aware_tool_result_with_example(self, watcher, db):
        """Tool result containing 'EXAMPLE' near match should downgrade to low."""
        watcher._ensure_session("sens-ctx-3", "/tmp/s.jsonl")
        text = "The key AKIAI44QH8DHBR3XYZAB is an example credential for testing"
        watcher._check_sensitive(text, "sens-ctx-3", "2026-01-01T00:00:00Z", "tool_result")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-ctx-3' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) >= 1
        data = json.loads(rows[0][0])
        assert data["severity"] == "low"

    def test_telegram_sender_id_not_flagged_as_phone(self, watcher, db):
        """Telegram sender_id (10-digit number) should not trigger phone_number alerts."""
        watcher._ensure_session("sens-tg-1", "/tmp/s.jsonl")
        text = (
            "Conversation info (untrusted metadata):\n"
            "```json\n"
            '{"message_id": "4", "sender_id": "7465847486", "sender": "Aj K"}\n'
            "```\n\nhello"
        )
        watcher._check_sensitive(text, "sens-tg-1", "2026-04-02T00:00:00Z", "user_prompt")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-tg-1' AND event_type='sensitive_data'"
        ).fetchall()
        # Should produce zero alerts — phone_number is the only pattern that would match,
        # and it should be filtered out because "sender_id" is in the text
        assert len(rows) == 0

    def test_sender_id_filter_preserves_real_alerts(self, watcher, db):
        """If text has sender_id AND a real secret, the real secret should still alert."""
        watcher._ensure_session("sens-tg-2", "/tmp/s.jsonl")
        # Text contains sender_id (triggers phone_number) AND an AWS key (triggers aws_key)
        text = '{"sender_id": "7465847486"}\nAKIAIOSFODNN7REALKEY is exposed'
        watcher._check_sensitive(text, "sens-tg-2", "2026-04-02T00:00:00Z", "user_prompt")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-tg-2' AND event_type='sensitive_data'"
        ).fetchall()
        # Should still fire for the aws_key, just not for phone_number
        assert len(rows) >= 1
        data = json.loads(rows[0][0])
        assert "phone_number" not in data["patterns"]
        assert "aws_key" in data["patterns"]

    def test_credit_card_in_api_metadata_not_flagged(self, watcher, db):
        """Credit card regex matching numeric API metadata should be suppressed."""
        watcher._ensure_session("sens-cc-1", "/tmp/s.jsonl")
        # Simulates API proxy traffic with large token counts that look like card numbers
        text = (
            '{"input_tokens": 4512345678901234, "output_tokens": 500, '
            '"model": "claude-sonnet-4-6", "responseId": "msg_012345"}'
        )
        watcher._check_sensitive(text, "sens-cc-1", "2026-04-02T00:00:00Z", "tool_result")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-cc-1' AND event_type='sensitive_data'"
        ).fetchall()
        # No credit_card alerts from API metadata
        for row in rows:
            data = json.loads(row[0])
            assert "credit_card" not in data["patterns"], (
                f"credit_card should not trigger in API metadata, got patterns={data['patterns']}"
            )

    def test_credit_card_in_anthropic_traffic_not_flagged(self, watcher, db):
        """Credit card regex in anthropic API context should be suppressed."""
        watcher._ensure_session("sens-cc-2", "/tmp/s.jsonl")
        text = "api.anthropic.com cache_read_input_tokens=6511234567890123"
        watcher._check_sensitive(text, "sens-cc-2", "2026-04-02T00:00:00Z", "tool_result")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-cc-2' AND event_type='sensitive_data'"
        ).fetchall()
        for row in rows:
            data = json.loads(row[0])
            assert "credit_card" not in data["patterns"]

    def test_real_credit_card_still_flagged(self, watcher, db):
        """An actual credit card number in user text should still be flagged."""
        watcher._ensure_session("sens-cc-3", "/tmp/s.jsonl")
        text = "My card number is 4111 1111 1111 1111 and CVV 123"
        watcher._check_sensitive(text, "sens-cc-3", "2026-04-02T00:00:00Z", "user_prompt")
        db.commit()

        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='sens-cc-3' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) >= 1
        data = json.loads(rows[0][0])
        assert "credit_card" in data["patterns"]


# ---------------------------------------------------------------------------
# process_jsonl_file
# ---------------------------------------------------------------------------


class TestProcessJsonlFile:
    def _write_jsonl(self, path, records):
        with open(path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def test_processes_user_and_assistant_records(self, watcher, db, tmp_path):
        jsonl_path = tmp_path / "test_session.jsonl"
        records = [
            {
                "uuid": "u1",
                "type": "user",
                "message": {"role": "user", "content": [{"type": "text", "text": "hello world"}]},
                "timestamp": "2026-01-01T00:00:00.000Z",
                "sessionId": "test-file-1",
                "cwd": "/home/user/project",
            },
            {
                "uuid": "u2",
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Hi there!"}],
                    "model": "claude-sonnet-4",
                    "usage": {"input_tokens": 100, "output_tokens": 50},
                    "stop_reason": "end_turn",
                },
                "timestamp": "2026-01-01T00:00:01.000Z",
                "sessionId": "test-file-1",
            },
        ]
        self._write_jsonl(jsonl_path, records)

        watcher.process_jsonl_file(str(jsonl_path))

        # Session should be created
        sess = db.execute("SELECT * FROM sessions WHERE session_id='test-file-1'").fetchone()
        assert sess is not None

        # Events should be created
        events = db.execute("SELECT event_type FROM events WHERE session_id='test-file-1'").fetchall()
        event_types = [e[0] for e in events]
        assert "user_prompt" in event_types
        assert "assistant_response" in event_types
        assert "token_usage" in event_types

    def test_file_position_tracking(self, watcher, db, tmp_path):
        """Second call to process_jsonl_file should not re-process old lines."""
        jsonl_path = tmp_path / "incremental.jsonl"
        records = [
            {
                "uuid": "inc-1",
                "type": "user",
                "message": {"role": "user", "content": "first message"},
                "timestamp": "2026-01-01T00:00:00.000Z",
                "sessionId": "test-inc",
            }
        ]
        self._write_jsonl(jsonl_path, records)

        watcher.process_jsonl_file(str(jsonl_path))
        count_after_first = _count(db, "events", "session_id='test-inc'")

        # Call again without adding new data
        watcher.process_jsonl_file(str(jsonl_path))
        count_after_second = _count(db, "events", "session_id='test-inc'")

        assert count_after_first == count_after_second

    def test_incremental_reading(self, watcher, db, tmp_path):
        """Appending to the file should only process new records."""
        jsonl_path = tmp_path / "append.jsonl"

        # Write first record
        with open(jsonl_path, "w") as f:
            f.write(
                json.dumps(
                    {
                        "uuid": "app-1",
                        "type": "user",
                        "message": {"role": "user", "content": "first"},
                        "timestamp": "2026-01-01T00:00:00.000Z",
                        "sessionId": "test-append",
                    }
                )
                + "\n"
            )

        watcher.process_jsonl_file(str(jsonl_path))
        first_count = _count(db, "events", "session_id='test-append'")

        # Append second record
        with open(jsonl_path, "a") as f:
            f.write(
                json.dumps(
                    {
                        "uuid": "app-2",
                        "type": "user",
                        "message": {"role": "user", "content": "second"},
                        "timestamp": "2026-01-01T00:00:01.000Z",
                        "sessionId": "test-append",
                    }
                )
                + "\n"
            )

        watcher.process_jsonl_file(str(jsonl_path))
        second_count = _count(db, "events", "session_id='test-append'")

        assert second_count > first_count

    def test_nonexistent_file_no_crash(self, watcher):
        """Processing a non-existent file should not raise."""
        watcher.process_jsonl_file("/nonexistent/path/foo.jsonl")

    def test_malformed_json_lines_skipped(self, watcher, db, tmp_path):
        """Lines that are not valid JSON should be skipped."""
        jsonl_path = tmp_path / "malformed.jsonl"
        with open(jsonl_path, "w") as f:
            f.write("not valid json\n")
            f.write(
                json.dumps(
                    {
                        "uuid": "mal-1",
                        "type": "user",
                        "message": {"role": "user", "content": "valid"},
                        "timestamp": "2026-01-01T00:00:00.000Z",
                        "sessionId": "test-malformed",
                    }
                )
                + "\n"
            )
            f.write("{{also broken}}\n")

        watcher.process_jsonl_file(str(jsonl_path))

        count = _count(db, "events", "session_id='test-malformed'")
        assert count >= 1  # Only the valid record should be processed

    def test_empty_file(self, watcher, db, tmp_path):
        jsonl_path = tmp_path / "empty.jsonl"
        jsonl_path.write_text("")
        watcher.process_jsonl_file(str(jsonl_path))
        # No crash, no events

    def test_flush_pending_commits(self, watcher, db, tmp_path):
        """process_jsonl_file should flush pending commits at the end."""
        jsonl_path = tmp_path / "flush.jsonl"
        records = [
            {
                "uuid": f"flush-{i}",
                "type": "user",
                "message": {"role": "user", "content": f"msg {i}"},
                "timestamp": "2026-01-01T00:00:00.000Z",
                "sessionId": "test-flush",
            }
            for i in range(5)
        ]
        self._write_jsonl(jsonl_path, records)

        watcher.process_jsonl_file(str(jsonl_path))

        # After process_jsonl_file, pending_commits should be reset to 0
        assert watcher._pending_commits == 0


# ---------------------------------------------------------------------------
# _process_record
# ---------------------------------------------------------------------------


class TestProcessRecord:
    def test_skips_record_without_session_id(self, watcher, db):
        record = {"type": "user", "message": {"content": "hello"}, "timestamp": "2026-01-01T00:00:00Z"}
        watcher._process_record(record, "/tmp/test.jsonl")
        # No session or events created since sessionId is missing
        count = _count(db, "sessions")
        assert count == 0

    def test_dedup_by_uuid(self, watcher, db):
        """Records with the same uuid should only be processed once."""
        record = {
            "uuid": "dedup-test-1",
            "type": "user",
            "message": {"role": "user", "content": "hello"},
            "timestamp": "2026-01-01T00:00:00Z",
            "sessionId": "dedup-sess",
        }
        watcher._process_record(record, "/tmp/test.jsonl")
        first_count = _count(db, "events", "session_id='dedup-sess'")

        # Process the same record again
        watcher._process_record(record, "/tmp/test.jsonl")
        second_count = _count(db, "events", "session_id='dedup-sess'")

        assert first_count == second_count

    def test_routes_user_type(self, watcher, db):
        record = {
            "uuid": "route-user-1",
            "type": "user",
            "message": {"role": "user", "content": "test prompt"},
            "timestamp": "2026-01-01T00:00:00Z",
            "sessionId": "route-sess",
        }
        watcher._process_record(record, "/tmp/test.jsonl")
        db.commit()

        count = _count(db, "events", "session_id='route-sess' AND event_type='user_prompt'")
        assert count == 1

    def test_routes_assistant_type(self, watcher, db):
        record = {
            "uuid": "route-asst-1",
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "response text"}],
                "model": "claude-sonnet-4",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            "timestamp": "2026-01-01T00:00:00Z",
            "sessionId": "route-sess-2",
        }
        watcher._process_record(record, "/tmp/test.jsonl")
        db.commit()

        count = _count(db, "events", "session_id='route-sess-2' AND event_type='assistant_response'")
        assert count == 1

    def test_routes_system_type(self, watcher, db):
        record = {
            "uuid": "route-sys-1",
            "type": "system",
            "subtype": "init",
            "timestamp": "2026-01-01T00:00:00Z",
            "sessionId": "route-sess-3",
        }
        watcher._process_record(record, "/tmp/test.jsonl")
        db.commit()

        count = _count(db, "events", "session_id='route-sess-3' AND event_type='system_event'")
        assert count == 1

    def test_routes_progress_type(self, watcher, db):
        record = {
            "uuid": "route-prog-1",
            "type": "progress",
            "data": {"type": "bash_progress", "output": "running..."},
            "timestamp": "2026-01-01T00:00:00Z",
            "sessionId": "route-sess-4",
        }
        watcher._process_record(record, "/tmp/test.jsonl")
        db.commit()

        count = _count(db, "events", "session_id='route-sess-4' AND event_type='bash_progress'")
        assert count == 1

    @patch("claude_monitoring.monitor.active_session_cwds", new_callable=set)
    @patch("claude_monitoring.monitor.active_cwds_lock", new_callable=threading.Lock)
    def test_tracks_cwd(self, mock_lock, mock_cwds, watcher, db):
        record = {
            "uuid": "cwd-1",
            "type": "user",
            "message": {"role": "user", "content": "test"},
            "timestamp": "2026-01-01T00:00:00Z",
            "sessionId": "cwd-sess",
            "cwd": "/home/user/project",
        }
        watcher._process_record(record, "/tmp/test.jsonl")
        assert "/home/user/project" in mock_cwds

    def test_malformed_record_no_crash(self, watcher, db):
        """A record with unexpected structure should not crash."""
        record = {"type": "unknown_type", "sessionId": "bad-sess", "weird_field": 12345}
        watcher._process_record(record, "/tmp/test.jsonl")
        # Just verify no exception


# ---------------------------------------------------------------------------
# _process_user_message
# ---------------------------------------------------------------------------


class TestProcessUserMessage:
    def test_simple_string_content(self, watcher, db):
        watcher._ensure_session("user-1", "/tmp/s.jsonl")
        record = {
            "message": {"role": "user", "content": "What is Python?"},
        }
        watcher._process_user_message(record, "user-1", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='user-1' AND event_type='user_prompt'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["text"] == "What is Python?"

    def test_list_content_with_text_blocks(self, watcher, db):
        watcher._ensure_session("user-2", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Please explain this"},
                    {"type": "text", "text": "And also this"},
                ],
            },
        }
        watcher._process_user_message(record, "user-2", "2026-01-01T00:00:00Z")
        db.commit()

        count = _count(db, "events", "session_id='user-2' AND event_type='user_prompt'")
        assert count == 2

    def test_list_content_with_tool_result(self, watcher, db):
        watcher._ensure_session("user-3", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool-123",
                        "content": [{"type": "text", "text": "command output here"}],
                        "is_error": False,
                    }
                ],
            },
        }
        watcher._process_user_message(record, "user-3", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='user-3' AND event_type='tool_result'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["tool_use_id"] == "tool-123"
        assert "command output here" in data["content"]
        assert data["is_error"] is False

    def test_tool_result_with_string_content(self, watcher, db):
        watcher._ensure_session("user-4", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool-456",
                        "content": "simple string result",
                    }
                ],
            },
        }
        watcher._process_user_message(record, "user-4", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='user-4' AND event_type='tool_result'"
        ).fetchone()
        data = json.loads(row[0])
        assert "simple string result" in data["content"]

    def test_sets_session_title_from_first_prompt(self, watcher, db):
        watcher._ensure_session("user-title", "/tmp/s.jsonl")
        record = {
            "message": {"role": "user", "content": "Build me a REST API in Python"},
        }
        watcher._process_user_message(record, "user-title", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute("SELECT title FROM sessions WHERE session_id='user-title'").fetchone()
        assert row[0] == "Build me a REST API in Python"

    def test_increments_turns_for_user_message(self, watcher, db):
        watcher._ensure_session("user-turns", "/tmp/s.jsonl")
        record = {"message": {"role": "user", "content": "message one"}}
        watcher._process_user_message(record, "user-turns", "2026-01-01T00:00:00Z")

        row = db.execute("SELECT total_turns FROM sessions WHERE session_id='user-turns'").fetchone()
        assert row[0] == 1

    def test_sensitive_data_in_prompt(self, watcher, db):
        watcher._ensure_session("user-sens", "/tmp/s.jsonl")
        record = {
            "message": {"role": "user", "content": "my key is AKIAI44QH8DHBR3XYZAB"},
        }
        watcher._process_user_message(record, "user-sens", "2026-01-01T00:00:00Z")
        db.commit()

        count = _count(db, "events", "session_id='user-sens' AND event_type='sensitive_data'")
        assert count >= 1


# ---------------------------------------------------------------------------
# _process_assistant_message
# ---------------------------------------------------------------------------


class TestProcessAssistantMessage:
    def test_text_response(self, watcher, db):
        watcher._ensure_session("asst-1", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "Here is my answer."}],
                "model": "claude-sonnet-4",
                "usage": {"input_tokens": 200, "output_tokens": 80},
                "stop_reason": "end_turn",
            }
        }
        watcher._process_assistant_message(record, "asst-1", "2026-01-01T00:00:00Z")
        db.commit()

        # Should create assistant_response event
        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-1' AND event_type='assistant_response'"
        ).fetchone()
        assert row is not None
        data = json.loads(row[0])
        assert data["text"] == "Here is my answer."
        assert data["model"] == "claude-sonnet-4"
        assert data["stop_reason"] == "end_turn"

    def test_token_usage_event(self, watcher, db):
        watcher._ensure_session("asst-2", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "ok"}],
                "model": "claude-sonnet-4",
                "usage": {
                    "input_tokens": 500,
                    "output_tokens": 100,
                    "cache_read_input_tokens": 200,
                    "cache_creation_input_tokens": 50,
                },
                "stop_reason": "end_turn",
            }
        }
        watcher._process_assistant_message(record, "asst-2", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-2' AND event_type='token_usage'"
        ).fetchone()
        assert row is not None
        data = json.loads(row[0])
        assert data["input_tokens"] == 500
        assert data["output_tokens"] == 100
        assert data["cache_read_tokens"] == 200
        assert data["cache_write_tokens"] == 50

    def test_session_stats_updated(self, watcher, db):
        watcher._ensure_session("asst-3", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "response"}],
                "model": "claude-sonnet-4",
                "usage": {"input_tokens": 300, "output_tokens": 75},
            }
        }
        watcher._process_assistant_message(record, "asst-3", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT model, total_input_tokens, total_output_tokens FROM sessions WHERE session_id='asst-3'"
        ).fetchone()
        assert row[0] == "claude-sonnet-4"
        assert row[1] == 300
        assert row[2] == 75

    def test_thinking_block(self, watcher, db):
        watcher._ensure_session("asst-4", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "Let me reason about this carefully..."},
                    {"type": "text", "text": "My answer is 42."},
                ],
                "model": "claude-sonnet-4",
                "usage": {"input_tokens": 100, "output_tokens": 50},
            }
        }
        watcher._process_assistant_message(record, "asst-4", "2026-01-01T00:00:00Z")
        db.commit()

        # Should have thinking event
        row = db.execute("SELECT data_json FROM events WHERE session_id='asst-4' AND event_type='thinking'").fetchone()
        assert row is not None
        data = json.loads(row[0])
        assert "reason about this" in data["text"]
        assert data["length"] == len("Let me reason about this carefully...")

    def test_tool_use_block_bash(self, watcher, db):
        watcher._ensure_session("asst-5", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-abc",
                        "name": "Bash",
                        "input": {"command": "ls -la /tmp"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-5", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute("SELECT data_json FROM events WHERE session_id='asst-5' AND event_type='tool_use'").fetchone()
        assert row is not None
        data = json.loads(row[0])
        assert data["name"] == "Bash"
        assert data["id"] == "tool-abc"
        assert data["input_preview"] == "ls -la /tmp"

    def test_tool_use_block_read(self, watcher, db):
        watcher._ensure_session("asst-6", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-read",
                        "name": "Read",
                        "input": {"file_path": "/home/user/main.py"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-6", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute("SELECT data_json FROM events WHERE session_id='asst-6' AND event_type='tool_use'").fetchone()
        data = json.loads(row[0])
        assert data["input_preview"] == "/home/user/main.py"

    def test_tool_use_block_write(self, watcher, db):
        watcher._ensure_session("asst-7", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-write",
                        "name": "Write",
                        "input": {"file_path": "/home/user/output.txt"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-7", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute("SELECT data_json FROM events WHERE session_id='asst-7' AND event_type='tool_use'").fetchone()
        data = json.loads(row[0])
        assert data["input_preview"] == "/home/user/output.txt"

    def test_tool_use_block_edit(self, watcher, db):
        watcher._ensure_session("asst-edit", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-edit",
                        "name": "Edit",
                        "input": {"file_path": "/src/main.py"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-edit", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-edit' AND event_type='tool_use'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["input_preview"] == "/src/main.py"

    def test_tool_use_block_glob_grep(self, watcher, db):
        watcher._ensure_session("asst-glob", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-glob",
                        "name": "Glob",
                        "input": {"pattern": "**/*.py"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-glob", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-glob' AND event_type='tool_use'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["input_preview"] == "**/*.py"

    def test_tool_use_block_web_fetch(self, watcher, db):
        watcher._ensure_session("asst-web", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-web",
                        "name": "WebFetch",
                        "input": {"url": "https://example.com"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-web", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-web' AND event_type='tool_use'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["input_preview"] == "https://example.com"

    def test_tool_use_block_web_search(self, watcher, db):
        watcher._ensure_session("asst-search", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-search",
                        "name": "WebSearch",
                        "input": {"query": "python tutorial"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-search", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-search' AND event_type='tool_use'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["input_preview"] == "python tutorial"

    def test_tool_use_block_unknown_tool(self, watcher, db):
        watcher._ensure_session("asst-unk", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-unk",
                        "name": "CustomTool",
                        "input": {"key": "value", "num": 123},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-unk", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-unk' AND event_type='tool_use'"
        ).fetchone()
        data = json.loads(row[0])
        # Unknown tools get JSON-serialized input as preview
        assert "key" in data["input_preview"]
        assert "value" in data["input_preview"]

    def test_no_usage_no_crash(self, watcher, db):
        """Record without usage block should not crash."""
        watcher._ensure_session("asst-no-usage", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "response"}],
                "model": "claude-sonnet-4",
            }
        }
        watcher._process_assistant_message(record, "asst-no-usage", "2026-01-01T00:00:00Z")
        db.commit()

        # assistant_response event should still be created
        count = _count(db, "events", "session_id='asst-no-usage' AND event_type='assistant_response'")
        assert count == 1

        # No token_usage event since usage is empty
        count = _count(db, "events", "session_id='asst-no-usage' AND event_type='token_usage'")
        assert count == 0

    def test_empty_content_list(self, watcher, db):
        watcher._ensure_session("asst-empty", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [],
                "model": "claude-sonnet-4",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
        }
        watcher._process_assistant_message(record, "asst-empty", "2026-01-01T00:00:00Z")
        db.commit()

        # No assistant_response event, but token_usage should still be there
        count = _count(db, "events", "session_id='asst-empty' AND event_type='assistant_response'")
        assert count == 0
        count = _count(db, "events", "session_id='asst-empty' AND event_type='token_usage'")
        assert count == 1

    def test_multiple_content_blocks(self, watcher, db):
        """A response with thinking + text + tool_use should create multiple events."""
        watcher._ensure_session("asst-multi", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "Thinking hard..."},
                    {"type": "text", "text": "Let me check that."},
                    {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "pwd"}},
                ],
                "model": "claude-sonnet-4",
                "usage": {"input_tokens": 200, "output_tokens": 100},
                "stop_reason": "tool_use",
            }
        }
        watcher._process_assistant_message(record, "asst-multi", "2026-01-01T00:00:00Z")
        db.commit()

        events = db.execute("SELECT event_type FROM events WHERE session_id='asst-multi'").fetchall()
        event_types = [e[0] for e in events]
        assert "thinking" in event_types
        assert "assistant_response" in event_types
        assert "tool_use" in event_types
        assert "token_usage" in event_types

    def test_sensitive_data_in_response(self, watcher, db):
        watcher._ensure_session("asst-sens", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "Found key: AKIAI44QH8DHBR3XYZAB"}],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-sens", "2026-01-01T00:00:00Z")
        db.commit()

        count = _count(db, "events", "session_id='asst-sens' AND event_type='sensitive_data'")
        assert count >= 1

    def test_sensitive_data_in_tool_input(self, watcher, db):
        watcher._ensure_session("asst-tool-sens", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "Bash",
                        "input": {"command": "echo AKIAI44QH8DHBR3XYZAB"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-tool-sens", "2026-01-01T00:00:00Z")
        db.commit()

        count = _count(db, "events", "session_id='asst-tool-sens' AND event_type='sensitive_data'")
        assert count >= 1

    def test_mcp_tool_creates_mcp_call_event(self, watcher, db):
        """MCP tool_use (mcp__server__method) should also store an mcp_call event."""
        watcher._ensure_session("asst-mcp-1", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t-mcp-1",
                        "name": "mcp__filesystem__read_file",
                        "input": {"path": "/tmp/foo.txt"},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-mcp-1", "2026-01-01T00:00:00Z")
        db.commit()

        # Should have both tool_use and mcp_call events
        tool_count = _count(db, "events", "session_id='asst-mcp-1' AND event_type='tool_use'")
        mcp_count = _count(db, "events", "session_id='asst-mcp-1' AND event_type='mcp_call'")
        assert tool_count >= 1
        assert mcp_count >= 1

        # mcp_call should have parsed server/method
        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-mcp-1' AND event_type='mcp_call'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["server"] == "filesystem"
        assert data["method"] == "read_file"

    def test_mcp_alert_on_unknown_server(self, watcher, db, monkeypatch):
        """Unknown MCP server triggers sensitive_data alert when configured."""
        monkeypatch.setattr("claude_monitoring.monitor.is_mcp_alert_on_unknown", lambda: True)
        monkeypatch.setattr("claude_monitoring.monitor.get_mcp_known_servers", lambda: ["filesystem"])

        watcher._ensure_session("asst-mcp-alert", "/tmp/s.jsonl")
        record = {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t-mcp-2",
                        "name": "mcp__evil_server__steal_data",
                        "input": {},
                    }
                ],
                "model": "claude-sonnet-4",
                "usage": {},
            }
        }
        watcher._process_assistant_message(record, "asst-mcp-alert", "2026-01-01T00:00:00Z")
        db.commit()

        # Should have a sensitive_data alert for the unknown MCP server
        rows = db.execute(
            "SELECT data_json FROM events WHERE session_id='asst-mcp-alert' AND event_type='sensitive_data'"
        ).fetchall()
        assert len(rows) >= 1
        found_mcp_alert = False
        for row in rows:
            data = json.loads(row[0])
            patterns = data.get("patterns", [])
            if any("unknown_mcp_server" in p for p in patterns):
                found_mcp_alert = True
                assert data["severity"] == "high"
                assert "evil_server" in data["context"]
        assert found_mcp_alert


# ---------------------------------------------------------------------------
# _process_progress
# ---------------------------------------------------------------------------


class TestProcessProgress:
    def test_bash_progress_stored(self, watcher, db):
        watcher._ensure_session("prog-1", "/tmp/s.jsonl")
        record = {
            "data": {
                "type": "bash_progress",
                "output": "Compiling main.c...",
                "elapsedTimeSeconds": 3.5,
            }
        }
        watcher._process_progress(record, "prog-1", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='prog-1' AND event_type='bash_progress'"
        ).fetchone()
        assert row is not None
        data = json.loads(row[0])
        assert data["output"] == "Compiling main.c..."
        assert data["elapsed"] == 3.5

    def test_bash_progress_full_output(self, watcher, db):
        watcher._ensure_session("prog-2", "/tmp/s.jsonl")
        record = {
            "data": {
                "type": "bash_progress",
                "fullOutput": "Full compilation log here",
                "elapsedTimeSeconds": 10,
            }
        }
        watcher._process_progress(record, "prog-2", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='prog-2' AND event_type='bash_progress'"
        ).fetchone()
        data = json.loads(row[0])
        assert data["output"] == "Full compilation log here"

    def test_non_bash_progress_ignored(self, watcher, db):
        watcher._ensure_session("prog-3", "/tmp/s.jsonl")
        record = {
            "data": {
                "type": "other_progress",
                "output": "should be ignored",
            }
        }
        watcher._process_progress(record, "prog-3", "2026-01-01T00:00:00Z")
        db.commit()

        count = _count(db, "events", "session_id='prog-3'")
        assert count == 0

    def test_empty_output_ignored(self, watcher, db):
        watcher._ensure_session("prog-4", "/tmp/s.jsonl")
        record = {
            "data": {
                "type": "bash_progress",
                "output": "",
            }
        }
        watcher._process_progress(record, "prog-4", "2026-01-01T00:00:00Z")
        db.commit()

        count = _count(db, "events", "session_id='prog-4'")
        assert count == 0

    def test_long_output_truncated(self, watcher, db):
        watcher._ensure_session("prog-5", "/tmp/s.jsonl")
        long_output = "x" * 5000
        record = {
            "data": {
                "type": "bash_progress",
                "output": long_output,
                "elapsedTimeSeconds": 1,
            }
        }
        watcher._process_progress(record, "prog-5", "2026-01-01T00:00:00Z")
        db.commit()

        row = db.execute(
            "SELECT data_json FROM events WHERE session_id='prog-5' AND event_type='bash_progress'"
        ).fetchone()
        data = json.loads(row[0])
        assert len(data["output"]) == 2000

    def test_empty_data_no_crash(self, watcher, db):
        record = {"data": {}}
        watcher._process_progress(record, "prog-6", "2026-01-01T00:00:00Z")

    def test_missing_data_no_crash(self, watcher, db):
        record = {}
        watcher._process_progress(record, "prog-7", "2026-01-01T00:00:00Z")


# ---------------------------------------------------------------------------
# _set_session_title
# ---------------------------------------------------------------------------


class TestSetSessionTitle:
    def test_sets_title_on_first_turn(self, watcher, db):
        watcher._ensure_session("title-1", "/tmp/s.jsonl")
        watcher._set_session_title("title-1", "How to deploy to AWS")

        row = db.execute("SELECT title FROM sessions WHERE session_id='title-1'").fetchone()
        assert row[0] == "How to deploy to AWS"

    def test_does_not_overwrite_existing_title(self, watcher, db):
        watcher._ensure_session("title-2", "/tmp/s.jsonl")
        db.execute("UPDATE sessions SET title='First title' WHERE session_id='title-2'")
        db.commit()

        watcher._set_session_title("title-2", "Should not replace")

        row = db.execute("SELECT title FROM sessions WHERE session_id='title-2'").fetchone()
        assert row[0] == "First title"

    def test_truncates_long_title(self, watcher, db):
        watcher._ensure_session("title-3", "/tmp/s.jsonl")
        long_text = "word " * 50  # 250 chars
        watcher._set_session_title("title-3", long_text)

        row = db.execute("SELECT title FROM sessions WHERE session_id='title-3'").fetchone()
        assert len(row[0]) < 130
        assert row[0].endswith("...")

    def test_does_not_set_after_many_turns(self, watcher, db):
        watcher._ensure_session("title-4", "/tmp/s.jsonl")
        db.execute("UPDATE sessions SET total_turns=5 WHERE session_id='title-4'")
        db.commit()

        watcher._set_session_title("title-4", "Late title")

        row = db.execute("SELECT title FROM sessions WHERE session_id='title-4'").fetchone()
        assert row[0] is None


# ---------------------------------------------------------------------------
# JSONLFileHandler
# ---------------------------------------------------------------------------


class TestJSONLFileHandler:
    def _make_handler(self, watcher):
        from claude_monitoring.monitor import JSONLFileHandler

        return JSONLFileHandler(watcher)

    def test_on_modified_jsonl_file(self, watcher):
        handler = self._make_handler(watcher)
        event = MagicMock()
        event.is_directory = False
        event.src_path = "/tmp/session.jsonl"

        with patch.object(watcher, "process_jsonl_file") as mock_process:
            handler.on_modified(event)
            mock_process.assert_called_once_with("/tmp/session.jsonl")

    def test_on_modified_non_jsonl_file(self, watcher):
        handler = self._make_handler(watcher)
        event = MagicMock()
        event.is_directory = False
        event.src_path = "/tmp/session.txt"

        with patch.object(watcher, "process_jsonl_file") as mock_process:
            handler.on_modified(event)
            mock_process.assert_not_called()

    def test_on_modified_directory(self, watcher):
        handler = self._make_handler(watcher)
        event = MagicMock()
        event.is_directory = True
        event.src_path = "/tmp/sessions/"

        with patch.object(watcher, "process_jsonl_file") as mock_process:
            handler.on_modified(event)
            mock_process.assert_not_called()

    def test_on_created_jsonl_file(self, watcher):
        handler = self._make_handler(watcher)
        event = MagicMock()
        event.is_directory = False
        event.src_path = "/tmp/new_session.jsonl"

        with patch.object(watcher, "process_jsonl_file") as mock_process:
            handler.on_created(event)
            mock_process.assert_called_once_with("/tmp/new_session.jsonl")

    def test_on_created_non_jsonl_file(self, watcher):
        handler = self._make_handler(watcher)
        event = MagicMock()
        event.is_directory = False
        event.src_path = "/tmp/readme.md"

        with patch.object(watcher, "process_jsonl_file") as mock_process:
            handler.on_created(event)
            mock_process.assert_not_called()

    def test_on_created_directory(self, watcher):
        handler = self._make_handler(watcher)
        event = MagicMock()
        event.is_directory = True
        event.src_path = "/tmp/new_dir/"

        with patch.object(watcher, "process_jsonl_file") as mock_process:
            handler.on_created(event)
            mock_process.assert_not_called()


# ---------------------------------------------------------------------------
# Integration: full JSONL file roundtrip
# ---------------------------------------------------------------------------


class TestFullRoundtrip:
    """End-to-end test processing a realistic JSONL transcript."""

    def test_full_conversation(self, watcher, db, tmp_path):
        jsonl_path = tmp_path / "conversation.jsonl"
        records = [
            {
                "uuid": "conv-1",
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "text", "text": "Write a hello world in Python"}],
                },
                "timestamp": "2026-01-01T00:00:00.000Z",
                "sessionId": "full-conv",
                "cwd": "/home/user/project",
            },
            {
                "uuid": "conv-2",
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "The user wants a simple Python program."},
                        {"type": "text", "text": "Here is a hello world program:"},
                        {
                            "type": "tool_use",
                            "id": "write-1",
                            "name": "Write",
                            "input": {"file_path": "/home/user/project/hello.py"},
                        },
                    ],
                    "model": "claude-sonnet-4",
                    "usage": {"input_tokens": 500, "output_tokens": 200},
                    "stop_reason": "tool_use",
                },
                "timestamp": "2026-01-01T00:00:01.000Z",
                "sessionId": "full-conv",
            },
            {
                "uuid": "conv-3",
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "write-1",
                            "content": "File written successfully",
                        }
                    ],
                },
                "timestamp": "2026-01-01T00:00:02.000Z",
                "sessionId": "full-conv",
            },
            {
                "uuid": "conv-4",
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "I've created the file. Let me run it."},
                        {
                            "type": "tool_use",
                            "id": "bash-1",
                            "name": "Bash",
                            "input": {"command": "python hello.py"},
                        },
                    ],
                    "model": "claude-sonnet-4",
                    "usage": {"input_tokens": 600, "output_tokens": 150},
                    "stop_reason": "tool_use",
                },
                "timestamp": "2026-01-01T00:00:03.000Z",
                "sessionId": "full-conv",
            },
            {
                "uuid": "conv-5",
                "type": "progress",
                "data": {
                    "type": "bash_progress",
                    "output": "Hello, World!",
                    "elapsedTimeSeconds": 0.5,
                },
                "timestamp": "2026-01-01T00:00:04.000Z",
                "sessionId": "full-conv",
            },
        ]

        with open(jsonl_path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

        watcher.process_jsonl_file(str(jsonl_path))

        # Session exists
        sess = db.execute("SELECT * FROM sessions WHERE session_id='full-conv'").fetchone()
        assert sess is not None

        # Check session stats
        row = db.execute(
            "SELECT model, total_input_tokens, total_output_tokens, total_turns, title "
            "FROM sessions WHERE session_id='full-conv'"
        ).fetchone()
        assert row[0] == "claude-sonnet-4"
        assert row[1] == 1100  # 500 + 600
        assert row[2] == 350  # 200 + 150
        assert row[3] >= 1  # at least 1 user turn
        assert row[4] is not None  # title set from first user message

        # Check event types
        events = db.execute("SELECT event_type FROM events WHERE session_id='full-conv' ORDER BY timestamp").fetchall()
        event_types = [e[0] for e in events]

        assert "user_prompt" in event_types
        assert "thinking" in event_types
        assert "assistant_response" in event_types
        assert "tool_use" in event_types
        assert "token_usage" in event_types
        assert "tool_result" in event_types
        assert "bash_progress" in event_types

    def test_stop_method(self, watcher):
        """Verify the stop() method sets the internal event."""
        assert not watcher._stop.is_set()
        watcher.stop()
        assert watcher._stop.is_set()


# ---------------------------------------------------------------------------
# OpenClaw JSONL Processing
# ---------------------------------------------------------------------------

OPENCLAW_SESSION_ID = "50a4dd45-d84b-4d63-a613-b7937e30874f"

# Test data matches the real OpenClaw JSONL format exactly:
# - No "sessionId" on message records (session ID derived from filename)
# - Short "id" field is a *message* ID, not session ID
# - "parentId" links messages in a tree
# - toolCall uses "arguments" not "input"
# - toolResult has "toolCallId" and "toolName" at message level
# - usage has "input"/"output" (no _tokens suffix), "cacheRead"/"cacheWrite"
# - "stopReason" not "stop_reason"
OPENCLAW_JSONL_LINES = [
    # type:"session" — initializes session with cwd; "id" IS the session ID here
    {
        "type": "session",
        "version": 3,
        "id": OPENCLAW_SESSION_ID,
        "cwd": "/Users/rajanyadav/.openclaw/workspace",
        "timestamp": "2026-04-02T02:19:03.480Z",
    },
    # type:"model_change" — sets the model before any messages
    {
        "type": "model_change",
        "id": "91200416",
        "parentId": None,
        "timestamp": "2026-04-02T02:19:03.482Z",
        "provider": "anthropic",
        "modelId": "claude-sonnet-4-6",
    },
    # type:"message", role:"user" — has short "id" (message ID, NOT session ID)
    {
        "type": "message",
        "id": "e52abbe8",
        "parentId": "9a3f85a3",
        "timestamp": "2026-04-02T02:19:03.495Z",
        "message": {
            "role": "user",
            "content": [{"type": "text", "text": "hello, what can you do?"}],
            "timestamp": 1775096343487,
        },
    },
    # type:"message", role:"assistant" — toolCall with "arguments", usage with short keys
    {
        "type": "message",
        "id": "b32f14bf",
        "parentId": "e52abbe8",
        "timestamp": "2026-04-02T02:19:06.799Z",
        "message": {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "The user is saying hello. Let me check memory first."},
                {
                    "type": "toolCall",
                    "id": "toolu_01E4xzfD8hYTnBdg6VFFVobN",
                    "name": "memory_search",
                    "arguments": {"query": "user preferences capabilities introduction"},
                },
            ],
            "model": "claude-sonnet-4-6",
            "usage": {
                "input": 3,
                "output": 93,
                "cacheRead": 0,
                "cacheWrite": 13257,
                "totalTokens": 13353,
                "cost": {"total": 0.05111775},
            },
            "api": "anthropic-messages",
            "provider": "anthropic",
            "stopReason": "toolUse",
            "responseId": "msg_011ZhHTxqvHCvcMeNUNbidg3",
        },
    },
    # type:"message", role:"toolResult" — content is a list of text blocks
    {
        "type": "message",
        "id": "87242f6c",
        "parentId": "b32f14bf",
        "timestamp": "2026-04-02T02:19:06.962Z",
        "message": {
            "role": "toolResult",
            "toolCallId": "toolu_01E4xzfD8hYTnBdg6VFFVobN",
            "toolName": "memory_search",
            "content": [{"type": "text", "text": '{"results": [], "provider": "auto"}'}],
            "isError": False,
            "timestamp": 1775096346935,
        },
    },
    # type:"message", role:"assistant" — final text response
    {
        "type": "message",
        "id": "7034008a",
        "parentId": "87242f6c",
        "timestamp": "2026-04-02T02:19:15.356Z",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Hey! I'm your AI assistant running via OpenClaw.",
                }
            ],
            "model": "claude-sonnet-4-6",
            "usage": {
                "input": 1,
                "output": 255,
                "cacheRead": 13257,
                "cacheWrite": 138,
                "totalTokens": 13651,
                "cost": {"total": 0.008322},
            },
            "api": "anthropic-messages",
            "provider": "anthropic",
            "stopReason": "stop",
            "responseId": "msg_015fYNXoNcEa4NP6jrPnm7mz",
        },
    },
]


class TestOpenClawJSONL:
    """Tests for OpenClaw JSONL format processing — matches real file format."""

    def _jsonl_path(self, tmp_path):
        return str(tmp_path / f"{OPENCLAW_SESSION_ID}.jsonl")

    def test_full_openclaw_file(self, watcher, db, tmp_path):
        """Process a realistic OpenClaw JSONL file and verify all events land in the DB."""
        jsonl_file = tmp_path / f"{OPENCLAW_SESSION_ID}.jsonl"
        jsonl_file.write_text("\n".join(json.dumps(r) for r in OPENCLAW_JSONL_LINES) + "\n")

        watcher.process_jsonl_file(str(jsonl_file))

        # Session must exist
        assert _count(db, "sessions", "session_id=?", (OPENCLAW_SESSION_ID,)) == 1

        # All events must be under the real session ID, NOT under short message IDs
        events = _rows(db, "events", "session_id=?", (OPENCLAW_SESSION_ID,))
        event_types = [e[3] for e in events]  # event_type column

        assert "user_prompt" in event_types
        assert "assistant_response" in event_types
        assert "tool_use" in event_types
        assert "tool_result" in event_types
        assert "token_usage" in event_types
        assert "thinking" in event_types

        # No events should be filed under short message IDs
        assert _count(db, "events", "session_id='e52abbe8'") == 0
        assert _count(db, "events", "session_id='b32f14bf'") == 0

    def test_session_record_creates_session(self, watcher, db, tmp_path):
        """type:'session' record should create the session row using its 'id' field."""
        watcher._process_record(OPENCLAW_JSONL_LINES[0], self._jsonl_path(tmp_path))
        assert _count(db, "sessions", "session_id=?", (OPENCLAW_SESSION_ID,)) == 1

    def test_message_id_not_used_as_session_id(self, watcher, db, tmp_path):
        """Short message 'id' field must NOT be used as session_id."""
        # Process a message record that has id:"e52abbe8" — should NOT create
        # a session with that ID; should use filename-derived UUID instead.
        watcher._process_record(OPENCLAW_JSONL_LINES[2], self._jsonl_path(tmp_path))

        assert _count(db, "sessions", "session_id='e52abbe8'") == 0
        assert _count(db, "sessions", "session_id=?", (OPENCLAW_SESSION_ID,)) == 1

    def test_session_id_from_filename(self, watcher, db, tmp_path):
        """Records without sessionId should derive it from the JSONL filename."""
        record = {
            "type": "message",
            "id": "abc12345",
            "timestamp": "2026-04-02T10:00:01Z",
            "message": {
                "role": "user",
                "content": "test prompt without sessionId",
            },
        }
        watcher._process_record(record, self._jsonl_path(tmp_path))

        assert _count(db, "sessions", "session_id=?", (OPENCLAW_SESSION_ID,)) == 1
        assert _count(db, "events", "session_id=? AND event_type='user_prompt'", (OPENCLAW_SESSION_ID,)) == 1
        # Must NOT use the short message id
        assert _count(db, "sessions", "session_id='abc12345'") == 0

    def test_session_id_from_record_id_only_for_session_type(self, watcher, db):
        """Only type:'session' records should use their 'id' as session_id."""
        record = {
            "type": "session",
            "id": OPENCLAW_SESSION_ID,
            "timestamp": "2026-04-02T10:00:00Z",
        }
        watcher._process_record(record, "/fake/other.jsonl")
        assert _count(db, "sessions", "session_id=?", (OPENCLAW_SESSION_ID,)) == 1

    def test_toolcall_arguments_normalized_to_input(self, watcher, db, tmp_path):
        """toolCall 'arguments' field should be renamed to 'input' for tool_use events."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        watcher._process_record(OPENCLAW_JSONL_LINES[3], path)

        events = _rows(db, "events", "session_id=? AND event_type='tool_use'", (OPENCLAW_SESSION_ID,))
        assert len(events) == 1
        data = json.loads(events[0][5])  # data_json column
        assert data["name"] == "memory_search"
        assert data["id"] == "toolu_01E4xzfD8hYTnBdg6VFFVobN"
        # The "arguments" field should have been normalized to "input"
        assert data["input"] == {"query": "user preferences capabilities introduction"}
        assert "input_preview" in data

    def test_tool_result_role_processed(self, watcher, db, tmp_path):
        """role:'toolResult' messages should produce tool_result events."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        watcher._process_record(OPENCLAW_JSONL_LINES[4], path)

        events = _rows(db, "events", "session_id=? AND event_type='tool_result'", (OPENCLAW_SESSION_ID,))
        assert len(events) == 1
        data = json.loads(events[0][5])
        assert data["tool_use_id"] == "toolu_01E4xzfD8hYTnBdg6VFFVobN"

    def test_tool_result_with_list_content(self, watcher, db, tmp_path):
        """toolResult whose content is a list of text blocks should be joined."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        watcher._process_record(OPENCLAW_JSONL_LINES[4], path)

        events = _rows(db, "events", "session_id=? AND event_type='tool_result'", (OPENCLAW_SESSION_ID,))
        data = json.loads(events[0][5])
        # Content was a list: [{"type":"text","text":"..."}] — should be extracted
        assert "results" in data["content"]

    def test_usage_fields_normalized(self, watcher, db, tmp_path):
        """OpenClaw usage fields (input/output/cacheRead/cacheWrite) should map correctly."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        watcher._process_record(OPENCLAW_JSONL_LINES[3], path)

        events = _rows(db, "events", "session_id=? AND event_type='token_usage'", (OPENCLAW_SESSION_ID,))
        assert len(events) >= 1
        data = json.loads(events[0][5])
        assert data["input_tokens"] == 3
        assert data["output_tokens"] == 93
        assert data["cache_read_tokens"] == 0
        assert data["cache_write_tokens"] == 13257

    def test_stop_reason_normalized(self, watcher, db, tmp_path):
        """stopReason should be normalized to stop_reason in stored events."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        watcher._process_record(OPENCLAW_JSONL_LINES[3], path)

        events = _rows(db, "events", "session_id=? AND event_type='token_usage'", (OPENCLAW_SESSION_ID,))
        assert len(events) >= 1
        data = json.loads(events[0][5])
        assert data["stop_reason"] == "toolUse"

    def test_no_session_id_anywhere_skips_record(self, watcher, db):
        """A record with no sessionId, no id, and non-UUID filename should be skipped."""
        record = {
            "type": "message",
            "message": {"role": "user", "content": "orphan prompt"},
        }
        watcher._process_record(record, "/fake/not-a-uuid.jsonl")
        assert _count(db, "events") == 0

    def test_claude_code_records_still_work(self, watcher, db):
        """Ensure standard Claude Code JSONL records are unaffected by OpenClaw changes."""
        user_record = {
            "type": "user",
            "sessionId": "cc-session-1",
            "timestamp": "2026-03-30T10:00:00Z",
            "message": {"content": "hello from Claude Code"},
        }
        assistant_record = {
            "type": "assistant",
            "sessionId": "cc-session-1",
            "timestamp": "2026-03-30T10:00:01Z",
            "message": {
                "content": [
                    {"type": "text", "text": "Hi there!"},
                    {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}},
                ],
                "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "stop_reason": "end_turn",
            },
        }
        watcher._process_record(user_record, "/fake/cc.jsonl")
        watcher._process_record(assistant_record, "/fake/cc.jsonl")

        assert _count(db, "events", "session_id='cc-session-1' AND event_type='user_prompt'") == 1
        assert _count(db, "events", "session_id='cc-session-1' AND event_type='tool_use'") == 1
        assert _count(db, "events", "session_id='cc-session-1' AND event_type='assistant_response'") == 1

    def test_real_openclaw_jsonl_file(self, watcher, db):
        """Process the actual OpenClaw JSONL file on disk and verify events appear."""
        import os

        real_file = os.path.expanduser("~/.openclaw/agents/main/sessions/50a4dd45-d84b-4d63-a613-b7937e30874f.jsonl")
        if not os.path.exists(real_file):
            pytest.skip("Real OpenClaw JSONL file not present")

        watcher.process_jsonl_file(real_file)

        sid = "50a4dd45-d84b-4d63-a613-b7937e30874f"

        # Session must exist
        assert _count(db, "sessions", "session_id=?", (sid,)) == 1

        # Must have events under the real session ID
        events = _rows(db, "events", "session_id=?", (sid,))
        event_types = [e[3] for e in events]

        assert "user_prompt" in event_types, f"Missing user_prompt; got {set(event_types)}"
        assert "assistant_response" in event_types, f"Missing assistant_response; got {set(event_types)}"
        assert "tool_use" in event_types, f"Missing tool_use; got {set(event_types)}"
        assert "tool_result" in event_types, f"Missing tool_result; got {set(event_types)}"
        assert "token_usage" in event_types, f"Missing token_usage; got {set(event_types)}"

        # Verify events were NOT filed under short message IDs
        assert _count(db, "events", "session_id='e52abbe8'") == 0
        assert _count(db, "events", "session_id='b32f14bf'") == 0
        assert _count(db, "events", "session_id='7034008a'") == 0

        # Verify tool_use events have input data (arguments→input normalization)
        tool_events = _rows(db, "events", "session_id=? AND event_type='tool_use'", (sid,))
        for te in tool_events:
            data = json.loads(te[5])
            assert data.get("name"), f"tool_use event missing name: {data}"
            assert "input" in data, f"tool_use event missing input (arguments not normalized?): {data}"

        # Verify model was set from model_change record
        row = db.execute("SELECT model FROM sessions WHERE session_id=?", (sid,)).fetchone()
        assert row[0] == "claude-sonnet-4-6", f"Expected model 'claude-sonnet-4-6', got '{row[0]}'"

        # Verify title was set with OpenClaw prefix (cwd contains .openclaw)
        row = db.execute("SELECT title FROM sessions WHERE session_id=?", (sid,)).fetchone()
        assert row[0] is not None, "Title should be set"
        assert "OpenClaw" in row[0], f"Title should contain 'OpenClaw', got '{row[0]}'"
        assert "Telegram" in row[0], f"Title should contain 'Telegram', got '{row[0]}'"

    def test_model_change_sets_session_model(self, watcher, db, tmp_path):
        """type:'model_change' record should set the model on the session."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)  # session
        watcher._process_record(OPENCLAW_JSONL_LINES[1], path)  # model_change

        row = db.execute("SELECT model FROM sessions WHERE session_id=?", (OPENCLAW_SESSION_ID,)).fetchone()
        assert row[0] == "claude-sonnet-4-6"

    def test_model_change_without_model_id_is_noop(self, watcher, db, tmp_path):
        """model_change with no modelId should not crash or set empty model."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        record = {"type": "model_change", "id": "x", "timestamp": "2026-04-02T00:00:00Z"}
        watcher._process_record(record, path)

        row = db.execute("SELECT model FROM sessions WHERE session_id=?", (OPENCLAW_SESSION_ID,)).fetchone()
        assert row[0] is None or row[0] == ""

    def test_openclaw_title_strips_telegram_metadata(self, watcher, db, tmp_path):
        """OpenClaw sessions should strip Telegram metadata and prefix with 'OpenClaw via Telegram'."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)  # session with .openclaw cwd

        telegram_prompt = (
            "Conversation info (untrusted metadata):\n"
            "```json\n"
            '{"message_id": "4", "sender_id": "7465847486", "sender": "Aj K"}\n'
            "```\n\n"
            "Sender (untrusted metadata):\n"
            "```json\n"
            '{"label": "Aj K", "id": "7465847486", "name": "Aj K"}\n'
            "```\n\n"
            "hello, what can you do?"
        )
        record = {
            "type": "message",
            "id": "abc1",
            "timestamp": "2026-04-02T10:00:00Z",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": telegram_prompt}],
            },
        }
        watcher._process_record(record, path)

        row = db.execute("SELECT title FROM sessions WHERE session_id=?", (OPENCLAW_SESSION_ID,)).fetchone()
        assert row[0] == "OpenClaw \u00b7 Telegram: hello, what can you do?"

    def test_openclaw_title_no_metadata(self, watcher, db, tmp_path):
        """OpenClaw sessions without metadata should still get 'OpenClaw:' prefix."""
        path = self._jsonl_path(tmp_path)
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)

        record = {
            "type": "message",
            "id": "abc2",
            "timestamp": "2026-04-02T10:00:00Z",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "plain prompt no metadata"}],
            },
        }
        watcher._process_record(record, path)

        row = db.execute("SELECT title FROM sessions WHERE session_id=?", (OPENCLAW_SESSION_ID,)).fetchone()
        assert row[0] == "OpenClaw: plain prompt no metadata"

    def test_claude_code_title_not_prefixed(self, watcher, db):
        """Claude Code sessions should NOT get OpenClaw prefix in title."""
        record = {
            "type": "user",
            "sessionId": "cc-title-test",
            "timestamp": "2026-04-02T10:00:00Z",
            "cwd": "/Users/rajanyadav/Projects/myproject",
            "message": {"content": "fix the bug in main.py"},
        }
        watcher._process_record(record, "/fake/cc.jsonl")

        row = db.execute("SELECT title FROM sessions WHERE session_id='cc-title-test'").fetchone()
        assert row[0] == "fix the bug in main.py"
        assert "OpenClaw" not in row[0]

    def test_extract_openclaw_user_text_no_metadata(self):
        """Text without metadata should pass through unchanged."""
        from claude_monitoring.monitor import JSONLSessionWatcher

        text, source = JSONLSessionWatcher._extract_openclaw_user_text("hello world")
        assert text == "hello world"
        assert source == ""

    def test_extract_openclaw_user_text_with_telegram(self):
        """Telegram-wrapped text should be extracted with Telegram hint."""
        from claude_monitoring.monitor import JSONLSessionWatcher

        text = (
            "Conversation info (untrusted metadata):\n"
            '```json\n{"message_id": "4", "sender_id": "123"}\n```\n\n'
            "Sender (untrusted metadata):\n"
            '```json\n{"id": "123", "name": "Test"}\n```\n\n'
            "what is the weather?"
        )
        cleaned, source = JSONLSessionWatcher._extract_openclaw_user_text(text)
        assert cleaned == "what is the weather?"
        assert source == "Telegram"

    def test_openclaw_assistant_creates_api_call(self, watcher, db, tmp_path):
        """OpenClaw assistant messages with provider/api fields should create api_calls rows."""
        import sqlite3

        db.row_factory = sqlite3.Row
        path = str(tmp_path / f"{OPENCLAW_SESSION_ID}.jsonl")
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)  # session
        watcher._process_record(OPENCLAW_JSONL_LINES[3], path)  # assistant with usage

        rows = db.execute("SELECT * FROM api_calls WHERE session_id = ?", (OPENCLAW_SESSION_ID,)).fetchall()
        assert len(rows) >= 1
        row = rows[0]
        assert row["destination_host"] == "api.anthropic.com"
        assert row["destination_service"] == "anthropic_api"
        assert row["model"] == "claude-sonnet-4-6"
        assert row["input_tokens"] == 3
        assert row["output_tokens"] == 93
        db.row_factory = None

    def test_claude_code_assistant_does_not_create_api_call(self, watcher, db):
        """Standard Claude Code assistant messages should NOT create api_calls rows."""
        record = {
            "type": "assistant",
            "sessionId": "cc-api-test",
            "timestamp": "2026-04-03T00:00:00Z",
            "message": {
                "content": [{"type": "text", "text": "Hello!"}],
                "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "stop_reason": "end_turn",
            },
        }
        watcher._process_record(record, "/fake/cc.jsonl")

        rows = db.execute("SELECT COUNT(*) FROM api_calls WHERE session_id = 'cc-api-test'").fetchone()
        assert rows[0] == 0

    def test_openclaw_api_call_has_cost(self, watcher, db, tmp_path):
        """OpenClaw api_calls should include estimated_cost_usd from cost.total."""
        import sqlite3

        db.row_factory = sqlite3.Row
        path = str(tmp_path / f"{OPENCLAW_SESSION_ID}.jsonl")
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)
        watcher._process_record(OPENCLAW_JSONL_LINES[3], path)

        row = db.execute(
            "SELECT estimated_cost_usd FROM api_calls WHERE session_id = ?",
            (OPENCLAW_SESSION_ID,),
        ).fetchone()
        assert row is not None
        assert row["estimated_cost_usd"] > 0
        db.row_factory = None


# ---------------------------------------------------------------------------
# Agent Type Detection
# ---------------------------------------------------------------------------


class TestAgentTypeDetection:
    def test_openclaw_from_cwd(self, watcher):
        assert watcher._detect_agent_type("/Users/x/.openclaw/workspace", "") == "openclaw"

    def test_claude_code_from_jsonl_path(self, watcher):
        assert watcher._detect_agent_type("", "/Users/x/.claude/projects/foo.jsonl") == "claude_code"

    def test_cursor_from_cwd(self, watcher):
        assert watcher._detect_agent_type("/Users/x/.cursor/workspace", "") == "cursor"

    def test_unknown_when_no_match(self, watcher):
        assert watcher._detect_agent_type("/Users/x/Projects/myapp", "/tmp/session.jsonl") == "unknown"

    def test_openclaw_session_has_agent_type(self, watcher, db, tmp_path):
        """Processing an OpenClaw session record sets agent_type='openclaw' on the session."""
        path = str(tmp_path / f"{OPENCLAW_SESSION_ID}.jsonl")
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)

        row = db.execute("SELECT agent_type FROM sessions WHERE session_id = ?", (OPENCLAW_SESSION_ID,)).fetchone()
        assert row is not None
        assert row[0] == "openclaw"

    def test_claude_code_session_has_agent_type(self, watcher, db):
        """Processing a Claude Code record sets agent_type from jsonl_path."""
        record = {
            "type": "user",
            "sessionId": "cc-agent-test",
            "timestamp": "2026-04-03T00:00:00Z",
            "message": {"content": "hello"},
        }
        watcher._process_record(record, "/Users/x/.claude/projects/foo/bar.jsonl")

        row = db.execute("SELECT agent_type FROM sessions WHERE session_id = 'cc-agent-test'").fetchone()
        assert row is not None
        assert row[0] == "claude_code"


# ---------------------------------------------------------------------------
# OpenClaw Session Details (Item 4)
# ---------------------------------------------------------------------------


class TestOpenClawSessionDetails:
    def test_detect_openclaw_channel_telegram(self, watcher):
        """Telegram metadata in user prompt -> channel 'Telegram'."""
        text = 'Conversation info (untrusted metadata):\n```json\n{"message_id": "4", "sender_id": "123"}\n```\n\nhello'
        assert watcher._detect_openclaw_channel(text) == "Telegram"

    def test_detect_openclaw_channel_none(self, watcher):
        """Plain text with no metadata -> channel None."""
        assert watcher._detect_openclaw_channel("hello world") is None

    def test_tool_risk_mapping(self):
        """TOOL_RISK_MAP returns correct risk levels."""
        from claude_monitoring.constants import TOOL_RISK_MAP

        assert TOOL_RISK_MAP["Bash"] == ("critical", "Shell command execution")
        assert TOOL_RISK_MAP["Write"] == ("high", "File creation/overwrite")
        assert TOOL_RISK_MAP["Read"] == ("medium", "File read access")
        assert TOOL_RISK_MAP["WebSearch"] == ("low", "Search query")
        assert TOOL_RISK_MAP["Agent"] == ("high", "Sub-agent spawning")

    def test_openclaw_session_cost_accumulation(self, watcher, db, tmp_path):
        """Processing multiple OpenClaw assistant messages accumulates cost."""
        import sqlite3

        db.row_factory = sqlite3.Row
        path = str(tmp_path / f"{OPENCLAW_SESSION_ID}.jsonl")
        watcher._process_record(OPENCLAW_JSONL_LINES[0], path)  # session
        watcher._process_record(OPENCLAW_JSONL_LINES[3], path)  # assistant 1
        watcher._process_record(OPENCLAW_JSONL_LINES[5], path)  # assistant 2

        rows = db.execute(
            "SELECT SUM(estimated_cost_usd) as total_cost FROM api_calls WHERE session_id = ?",
            (OPENCLAW_SESSION_ID,),
        ).fetchone()
        assert rows["total_cost"] > 0
        db.row_factory = None
