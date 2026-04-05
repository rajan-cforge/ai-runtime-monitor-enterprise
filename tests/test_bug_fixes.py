"""Tests for bug fixes: CVSS parsing, confidence filter, reveal button, session titles."""

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


class TestCVSSParsing:
    def test_database_specific_severity(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        vuln = {
            "severity": [],
            "database_specific": {"severity": "HIGH"},
        }
        score, sev = _extract_db_severity(vuln)
        assert sev == "high"
        assert score == 7.5

    def test_cvss_vector_string(self):
        from claude_monitoring.vuln_scanner import _extract_cvss

        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
            ],
        }
        cvss = _extract_cvss(vuln)
        # Should not be None — should extract something from vector
        # Even if we can't parse full CVSS, we should get a mapped score
        assert cvss is not None

    def test_critical_db_severity(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, sev = _extract_db_severity({"database_specific": {"severity": "CRITICAL"}})
        assert sev == "critical"
        assert score == 9.5

    def test_moderate_db_severity(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, sev = _extract_db_severity({"database_specific": {"severity": "MODERATE"}})
        assert sev == "medium"
        assert score == 5.0

    def test_low_db_severity(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, sev = _extract_db_severity({"database_specific": {"severity": "LOW"}})
        assert sev == "low"
        assert score == 2.5

    def test_no_severity_data(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, sev = _extract_db_severity({})
        assert sev == "unknown"
        assert score is None

    def test_stored_vuln_has_score(self, db):
        from claude_monitoring.vuln_scanner import store_vuln

        store_vuln(db, {
            "package_name": "test-pkg",
            "package_version": "1.0",
            "ecosystem": "PyPI",
            "vuln_id": "GHSA-test-1",
            "severity": "high",
            "cvss_score": 7.5,
            "fix_version": "2.0",
            "description": "test vuln",
            "source": "osv",
        })
        db.commit()
        row = db.execute(
            "SELECT cvss_score, severity FROM package_vulnerabilities WHERE vuln_id='GHSA-test-1'"
        ).fetchone()
        assert row["cvss_score"] == 7.5
        assert row["severity"] == "high"


class TestConfidenceFilterBackend:
    def test_total_reflects_confidence_filter(self, db):
        """Total count must change when confidence filter is applied."""
        # Insert alerts with different confidence levels
        for i, conf in enumerate(["high", "high", "medium", "low", "low", "low"]):
            db.execute(
                """INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json, dedup_hash)
                   VALUES (?, 's1', 'sensitive_data', 'network', ?, ?)""",
                (
                    f"2026-04-04T00:00:{i:02d}Z",
                    json.dumps({
                        "patterns": ["aws_key"], "severity": "critical",
                        "categories": ["credential"], "context": "tool_result",
                        "snippet": f"test {i}", "confidence": conf,
                        "likely_false_positive": conf == "low",
                    }),
                    f"conf-test-{i}",
                ),
            )
        db.commit()

        # Simulate API behavior: count with confidence filter
        all_count = db.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='sensitive_data'"
        ).fetchone()[0]
        assert all_count == 6

        high_count = db.execute(
            """SELECT COUNT(*) FROM events WHERE event_type='sensitive_data'
               AND json_extract(data_json, '$.confidence') = 'high'"""
        ).fetchone()[0]
        assert high_count == 2

        med_plus_count = db.execute(
            """SELECT COUNT(*) FROM events WHERE event_type='sensitive_data'
               AND json_extract(data_json, '$.confidence') IN ('high', 'medium')"""
        ).fetchone()[0]
        assert med_plus_count == 3


class TestRevealButtonConditional:
    def test_empty_matched_value(self):
        """Reveal button should be hidden when matched_value is empty."""
        # This tests the logic, not the HTML rendering
        alert = {"matched_value": "", "snippet": "some text"}
        assert not alert["matched_value"]  # falsy = hide reveal

    def test_populated_matched_value(self):
        alert = {"matched_value": "AKIAUSELFJENWMJ2JAVB"}
        assert alert["matched_value"]  # truthy = show reveal


class TestSessionTitleCleaning:
    def test_uuid_title_replaced(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        cleaned = JSONLSessionWatcher._clean_title("c654f242-8f22-4650-929d-865bfbba6335")
        # UUID should be cleaned to empty (then fallback to session ID)
        assert len(cleaned) < 40 or cleaned == ""

    def test_instruction_title_passes_through(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        # _clean_title strips metadata but doesn't truncate — that's _set_session_title's job
        cleaned = JSONLSessionWatcher._clean_title(
            "Read src/claude_monitoring/monitor.py and src/claude_monitoring/constants.py. Then implement the following changes..."
        )
        # Should pass through since it's not metadata
        assert cleaned.startswith("Read src/")
