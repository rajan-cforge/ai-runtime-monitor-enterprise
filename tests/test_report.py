"""Tests for report.py — summary report generation in HTML, Markdown, and CSV."""

import sqlite3

import pytest

from claude_monitoring.report import (
    _gather_period_stats,
    _render_csv,
    _render_markdown,
    _render_standalone_html,
    generate_summary_report,
)


@pytest.fixture()
def report_db(tmp_path):
    """Create a test SQLite DB with schema and sample data for reports."""
    db_path = tmp_path / "report_test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Create required tables
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        start_time TEXT,
        cwd TEXT,
        model TEXT,
        total_cost REAL DEFAULT 0,
        total_input_tokens INTEGER DEFAULT 0,
        total_output_tokens INTEGER DEFAULT 0,
        total_turns INTEGER DEFAULT 0,
        jsonl_path TEXT,
        last_activity TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        source_layer TEXT NOT NULL,
        data_json TEXT NOT NULL
    )""")

    # Insert sample sessions (use recent timestamps)
    conn.execute(
        "INSERT INTO sessions VALUES (?, datetime('now', '-1 day'), ?, ?, 0, ?, ?, ?, NULL, datetime('now'))",
        ("sess-1", "/home/user/project-alpha", "claude-sonnet-4", 5000, 3000, 10),
    )
    conn.execute(
        "INSERT INTO sessions VALUES (?, datetime('now', '-2 days'), ?, ?, 0, ?, ?, ?, NULL, datetime('now', '-1 day'))",
        ("sess-2", "/home/user/project-beta", "claude-haiku-4", 2000, 1000, 5),
    )

    # Insert tool use events
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now'), ?, 'tool_use', 'network', ?)",
        ("sess-1", '{"name": "Read"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now'), ?, 'tool_use', 'network', ?)",
        ("sess-1", '{"name": "Edit"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now'), ?, 'tool_use', 'network', ?)",
        ("sess-1", '{"name": "Read"}'),
    )

    # Insert token usage events
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now'), ?, 'token_usage', 'network', ?)",
        ("sess-1", '{"input_tokens": 500, "output_tokens": 300}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now', '-1 day'), ?, 'token_usage', 'network', ?)",
        ("sess-2", '{"input_tokens": 200, "output_tokens": 100}'),
    )

    # Insert alert events
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now'), ?, 'sensitive_data', 'network', ?)",
        ("sess-1", '{"severity": "high", "pattern": "aws_key"}'),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (datetime('now'), ?, 'sensitive_data', 'network', ?)",
        ("sess-1", '{"severity": "medium", "pattern": "phone"}'),
    )

    conn.commit()
    return db_path, conn


class TestGatherPeriodStats:
    def test_returns_expected_keys(self, report_db):
        db_path, conn = report_db
        stats = _gather_period_stats(conn, 7)
        assert "sessions" in stats
        assert "models" in stats
        assert "tools" in stats
        assert "projects" in stats
        assert "alerts" in stats
        assert "daily" in stats
        assert "generated_at" in stats

    def test_session_counts(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        assert stats["sessions"]["count"] == 2
        assert stats["sessions"]["turns"] == 15
        assert stats["sessions"]["input_tokens"] == 7000
        assert stats["sessions"]["output_tokens"] == 4000

    def test_models_breakdown(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        model_names = [m["model"] for m in stats["models"]]
        assert "claude-sonnet-4" in model_names
        assert "claude-haiku-4" in model_names

    def test_tools_breakdown(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        tool_names = [t["tool"] for t in stats["tools"]]
        assert "Read" in tool_names
        assert "Edit" in tool_names

    def test_projects_breakdown(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        cwds = [p["cwd"] for p in stats["projects"]]
        assert "/home/user/project-alpha" in cwds

    def test_alerts_breakdown(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        severities = [a["severity"] for a in stats["alerts"]]
        assert "high" in severities
        assert "medium" in severities

    def test_daily_breakdown(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        assert len(stats["daily"]) >= 1


class TestGenerateSummaryReport:
    def test_html_format(self, report_db):
        db_path, _ = report_db
        html = generate_summary_report(db_path, period_days=7, fmt="html")
        assert "<!DOCTYPE html>" in html
        assert "AI Runtime Monitor" in html
        assert "Sessions" in html
        assert "chart-daily" in html
        assert "chart-tools" in html

    def test_markdown_format(self, report_db):
        db_path, _ = report_db
        md = generate_summary_report(db_path, period_days=7, fmt="markdown")
        assert "# AI Runtime Monitor Report" in md
        assert "| Metric | Value |" in md
        assert "## Overview" in md

    def test_csv_format(self, report_db):
        db_path, _ = report_db
        csv_out = generate_summary_report(db_path, period_days=7, fmt="csv")
        assert "day,input_tokens,output_tokens" in csv_out

    def test_default_format_is_markdown(self, report_db):
        db_path, _ = report_db
        result = generate_summary_report(db_path, period_days=7, fmt="other")
        assert "# AI Runtime Monitor Report" in result


class TestRenderMarkdown:
    def test_models_table(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        md = _render_markdown(stats, 7)
        assert "## Models" in md
        assert "claude-sonnet-4" in md

    def test_tools_table(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        md = _render_markdown(stats, 7)
        assert "## Top Tools" in md
        assert "Read" in md

    def test_projects_table(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        md = _render_markdown(stats, 7)
        assert "## Projects" in md

    def test_alerts_table(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        md = _render_markdown(stats, 7)
        assert "## Alerts" in md
        assert "high" in md

    def test_daily_breakdown_table(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        md = _render_markdown(stats, 7)
        assert "## Daily Breakdown" in md

    def test_empty_stats_no_sections(self):
        """When there's no data, optional sections should not appear."""
        stats = {
            "sessions": {"count": 0, "turns": 0, "input_tokens": 0, "output_tokens": 0},
            "models": [],
            "tools": [],
            "projects": [],
            "alerts": [],
            "daily": [],
            "generated_at": "2026-01-01T00:00:00Z",
        }
        md = _render_markdown(stats, 7)
        assert "## Models" not in md
        assert "## Top Tools" not in md
        assert "## Projects" not in md
        assert "## Alerts" not in md
        assert "## Daily Breakdown" not in md
        assert "## Overview" in md


class TestRenderStandaloneHtml:
    def test_contains_html_structure(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        html = _render_standalone_html(stats, 7)
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "chart.js" in html.lower()

    def test_contains_stats(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        html = _render_standalone_html(stats, 7)
        assert "Sessions" in html
        assert "Total Turns" in html
        assert "Input Tokens" in html

    def test_contains_alert_box(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        html = _render_standalone_html(stats, 7)
        assert "alert-box" in html
        assert "alerts" in html.lower()

    def test_no_alerts_empty_alert_div(self):
        stats = {
            "sessions": {"count": 0, "turns": 0, "input_tokens": 0, "output_tokens": 0},
            "models": [],
            "tools": [],
            "projects": [],
            "alerts": [],
            "daily": [],
            "generated_at": "2026-01-01T00:00:00Z",
        }
        html = _render_standalone_html(stats, 7)
        # With no alerts, the alert_html variable should be empty string
        # (the CSS class definition is still in <style>, but no <div class="alert-box"> in body)
        assert '<div class="alert-box">' not in html

    def test_models_table_rows(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        html = _render_standalone_html(stats, 7)
        assert "claude-sonnet-4" in html

    def test_projects_table_rows(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        html = _render_standalone_html(stats, 7)
        assert "project-alpha" in html


class TestRenderCsv:
    def test_csv_header(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        csv_out = _render_csv(stats)
        lines = csv_out.strip().splitlines()
        assert lines[0].strip() == "day,input_tokens,output_tokens"

    def test_csv_data_rows(self, report_db):
        _, conn = report_db
        stats = _gather_period_stats(conn, 7)
        csv_out = _render_csv(stats)
        lines = csv_out.strip().split("\n")
        # Header + at least one data row
        assert len(lines) >= 2

    def test_csv_empty_daily(self):
        stats = {
            "daily": [],
            "generated_at": "2026-01-01T00:00:00Z",
        }
        csv_out = _render_csv(stats)
        lines = csv_out.strip().split("\n")
        assert len(lines) == 1  # Just header
        assert "day" in lines[0]

    def test_csv_handles_none_tokens(self):
        stats = {
            "daily": [{"day": "2026-01-01", "input_tokens": None, "output_tokens": None}],
            "generated_at": "2026-01-01T00:00:00Z",
        }
        csv_out = _render_csv(stats)
        assert "2026-01-01,0,0" in csv_out
