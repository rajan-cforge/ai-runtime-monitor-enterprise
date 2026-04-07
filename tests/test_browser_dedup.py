# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Tests for browser session deduplication."""

import hashlib
import sqlite3

import pytest

from claude_monitoring.db import init_db


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _content_hash(text):
    return hashlib.sha256(text[:200].encode()).hexdigest()[:16]


class TestContentHashDedup:
    def test_same_content_within_hour_rejected(self, db):
        """Same content from same conversation within 1 hour should be rejected."""
        text = "Hello this is a test message"
        ch = _content_hash(text)
        db.execute(
            """INSERT INTO browser_sessions
               (service, url, title, conversation_id, visit_time,
                duration_seconds, source, event_type, content_text, content_hash)
               VALUES ('Claude Web', 'https://claude.ai/chat/abc', 'Test', 'abc',
                '2026-04-07T08:00:00Z', 0, 'extension', 'user_prompt', ?, ?)""",
            (text, ch),
        )
        db.commit()
        # Check if dedup query finds it
        existing = db.execute(
            """SELECT id FROM browser_sessions
               WHERE conversation_id = 'abc' AND event_type = 'user_prompt' AND content_hash = ?
               AND visit_time > datetime('2026-04-07T08:30:00Z', '-1 hour')
               LIMIT 1""",
            (ch,),
        ).fetchone()
        assert existing is not None  # Found = would be rejected

    def test_different_content_accepted(self, db):
        text1 = "First message"
        text2 = "Completely different message"
        ch1 = _content_hash(text1)
        ch2 = _content_hash(text2)
        assert ch1 != ch2

    def test_same_content_after_hour_accepted(self, db):
        text = "Repeated message"
        ch = _content_hash(text)
        db.execute(
            """INSERT INTO browser_sessions
               (service, url, conversation_id, visit_time,
                duration_seconds, source, event_type, content_text, content_hash)
               VALUES ('Claude Web', 'url', 'abc', '2026-04-07 06:00:00', 0, 'extension', 'user_prompt', ?, ?)""",
            (text, ch),
        )
        db.commit()
        # 3 hours later — record at 06:00, query window is 08:00-09:00
        existing = db.execute(
            """SELECT id FROM browser_sessions
               WHERE conversation_id = 'abc' AND event_type = 'user_prompt' AND content_hash = ?
               AND visit_time > datetime('2026-04-07 09:00:00', '-1 hour')
               LIMIT 1""",
            (ch,),
        ).fetchone()
        assert existing is None  # Not found = would be accepted


class TestChromeHistoryDedup:
    def test_same_url_within_60s_rejected(self, db):
        url = "https://claude.ai/chat/abc"
        db.execute(
            """INSERT INTO browser_sessions
               (service, url, conversation_id, visit_time, duration_seconds)
               VALUES ('Claude Web', ?, 'abc', '2026-04-07T08:00:00Z', 10)""",
            (url,),
        )
        db.commit()
        existing = db.execute(
            """SELECT id FROM browser_sessions
               WHERE url = ? AND ABS(strftime('%s', visit_time) - strftime('%s', ?)) < 60
               LIMIT 1""",
            (url, "2026-04-07T08:00:30Z"),
        ).fetchone()
        assert existing is not None  # Would be rejected

    def test_different_urls_accepted(self, db):
        db.execute(
            """INSERT INTO browser_sessions
               (service, url, visit_time, duration_seconds)
               VALUES ('ChatGPT', 'https://chatgpt.com/c/111', '2026-04-07T08:00:00Z', 10)""",
        )
        db.commit()
        existing = db.execute(
            """SELECT id FROM browser_sessions
               WHERE url = ? AND ABS(strftime('%s', visit_time) - strftime('%s', ?)) < 60
               LIMIT 1""",
            ("https://chatgpt.com/c/222", "2026-04-07T08:00:30Z"),
        ).fetchone()
        assert existing is None  # Different URL = accepted


class TestDurationCalculation:
    def test_span_not_sum(self, db):
        """Duration should be time span (last - first), not sum of all durations."""
        for i in range(5):
            db.execute(
                """INSERT INTO browser_sessions
                   (service, url, conversation_id, visit_time, duration_seconds)
                   VALUES ('Claude Web', 'url', 'conv1', ?, 3600)""",
                (f"2026-04-07T0{i}:00:00Z",),
            )
        db.commit()
        row = db.execute("""
            SELECT CAST((strftime('%s', MAX(visit_time)) - strftime('%s', MIN(visit_time))) AS INTEGER) as span,
                   SUM(duration_seconds) as sum_dur
            FROM browser_sessions WHERE conversation_id='conv1'
        """).fetchone()
        # Span should be 4 hours = 14400 seconds
        assert row["span"] == 14400
        # Sum would be 5 * 3600 = 18000 — wrong
        assert row["sum_dur"] == 18000
        # Span is correct, sum is inflated
        assert row["span"] < row["sum_dur"]

    def test_content_hash_column_exists(self, db):
        cols = [r["name"] for r in db.execute("PRAGMA table_info(browser_sessions)").fetchall()]
        assert "content_hash" in cols
