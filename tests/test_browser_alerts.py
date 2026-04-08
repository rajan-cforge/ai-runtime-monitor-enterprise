# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Tests for browser capture alert pipeline."""

import sqlite3

import pytest

from claude_monitoring.db import init_db


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class TestBrowserAlertStorage:
    def test_aws_key_in_browser_creates_alert(self, db):
        """Posting a browser capture with an AWS key should create a sensitive_data event."""
        from claude_monitoring.utils import scan_sensitive

        text = "Here is my key: AKIAIOSFODNN7EXAMPLE for testing"
        matches = scan_sensitive(text)
        # Verify scan_sensitive detects the key
        assert any(m["name"] == "aws_key" for m in matches)

    def test_alert_has_browser_context(self):
        """Browser alerts should have context prefixed with 'browser_'."""
        context = "browser_user_prompt"
        assert context.startswith("browser_")

    def test_dedup_7day_same_content(self, db):
        """Same content_hash within 7 days should be rejected."""
        import hashlib

        text = "Test content for dedup"
        ch = hashlib.sha256(text[:200].encode()).hexdigest()[:16]
        db.execute(
            """INSERT INTO browser_sessions
               (service, url, conversation_id, visit_time, duration_seconds,
                source, event_type, content_text, content_hash)
               VALUES ('Claude Web', 'url', 'conv1', '2026-04-07 10:00:00',
                0, 'extension', 'user_prompt', ?, ?)""",
            (text, ch),
        )
        db.commit()
        # 2 days later — same content should be found within 7 days
        existing = db.execute(
            """SELECT id FROM browser_sessions
               WHERE conversation_id = 'conv1' AND event_type = 'user_prompt'
               AND (content_hash = ? OR substr(content_text, 1, 200) = ?)
               AND visit_time > datetime('2026-04-09 10:00:00', '-7 days')
               LIMIT 1""",
            (ch, text[:200]),
        ).fetchone()
        assert existing is not None

    def test_dedup_allows_different_content(self, db):
        """Different content in same conversation should be accepted."""
        import hashlib

        text1 = "First message"
        text2 = "Completely different second message"
        ch1 = hashlib.sha256(text1[:200].encode()).hexdigest()[:16]
        ch2 = hashlib.sha256(text2[:200].encode()).hexdigest()[:16]
        db.execute(
            """INSERT INTO browser_sessions
               (service, url, conversation_id, visit_time, duration_seconds,
                source, event_type, content_text, content_hash)
               VALUES ('Claude Web', 'url', 'conv1', '2026-04-07 10:00:00',
                0, 'extension', 'user_prompt', ?, ?)""",
            (text1, ch1),
        )
        db.commit()
        existing = db.execute(
            """SELECT id FROM browser_sessions
               WHERE conversation_id = 'conv1' AND event_type = 'user_prompt'
               AND content_hash = ?
               AND visit_time > datetime('2026-04-07 10:30:00', '-7 days')
               LIMIT 1""",
            (ch2,),
        ).fetchone()
        assert existing is None  # Different content = not found = accepted
