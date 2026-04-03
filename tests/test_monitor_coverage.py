"""Tests for monitor.py utility functions: compute_forecast, detect_plan_info, etc.

Covers uncovered paths in monitor.py for coverage improvement.
"""

import json
import sqlite3
from unittest.mock import patch

import pytest

from claude_monitoring import config


@pytest.fixture(autouse=True)
def _reset_config():
    config.reset()
    yield
    config.reset()


def _create_test_db(tmp_path):
    """Create a minimal test DB with the events table."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        source_layer TEXT NOT NULL,
        data_json TEXT NOT NULL
    )""")
    conn.commit()
    return conn


class TestComputeForecast:
    def test_empty_db_returns_defaults(self, tmp_path):
        from claude_monitoring.monitor import compute_forecast

        db = _create_test_db(tmp_path)
        result = compute_forecast(db)
        assert result["daily_burn_rate"] == 0
        assert result["avg_7d_burn"] == 0
        assert result["daily_breakdown"] == []
        assert result["days_remaining"] is None
        assert result["burn_trend"] == "stable"
        db.close()

    def test_with_token_usage_data(self, tmp_path):
        from claude_monitoring.monitor import compute_forecast

        db = _create_test_db(tmp_path)

        # Insert 10 days of token usage
        for i in range(10):
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 1000, "output_tokens": 500})),
            )
        db.commit()

        result = compute_forecast(db)
        assert result["daily_burn_rate"] > 0
        assert result["avg_7d_burn"] > 0
        assert len(result["daily_breakdown"]) > 0
        assert result["burn_trend"] == "stable"
        db.close()

    def test_increasing_trend(self, tmp_path):
        from claude_monitoring.monitor import compute_forecast

        db = _create_test_db(tmp_path)

        # Need 7+ distinct days. Earlier 4 days: low usage, recent 3 days: high usage
        # Use multiple events per day to ensure clear totals
        for i in [13, 12, 11, 10]:
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 100, "output_tokens": 50})),
            )
        for i in [9, 8, 7]:
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 100, "output_tokens": 50})),
            )
        for i in [3, 2, 1]:
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 50000, "output_tokens": 30000})),
            )
        # Also add days 6, 5, 4 with low usage to have enough data points
        for i in [6, 5, 4]:
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 100, "output_tokens": 50})),
            )
        db.commit()

        result = compute_forecast(db)
        assert result["burn_trend"] == "increasing"
        db.close()

    def test_decreasing_trend(self, tmp_path):
        from claude_monitoring.monitor import compute_forecast

        db = _create_test_db(tmp_path)

        # Recent 3 days: very low usage, earlier 4 days: very high usage
        for i in [7, 6, 5, 4]:
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 50000, "output_tokens": 30000})),
            )
        for i in [3, 2, 1]:
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 100, "output_tokens": 50})),
            )
        db.commit()

        result = compute_forecast(db)
        assert result["burn_trend"] == "decreasing"
        db.close()

    def test_subscription_forecast(self, tmp_path):
        from claude_monitoring import monitor

        db = _create_test_db(tmp_path)

        # Insert some usage
        for i in range(5):
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 1000, "output_tokens": 500})),
            )
        db.commit()

        old_plan = monitor.plan_info.copy()
        try:
            monitor.plan_info = {"is_subscription": True, "plan_tier": "pro"}
            result = monitor.compute_forecast(db)
            assert result["monthly_limit"] is not None
            assert result["monthly_limit"] == 45_000_000
            assert "plan_label" in result
        finally:
            monitor.plan_info = old_plan
        db.close()

    def test_subscription_days_remaining_zero(self, tmp_path):
        from claude_monitoring import monitor

        db = _create_test_db(tmp_path)

        # Insert massive usage to exhaust the plan
        for i in range(5):
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 50_000_000, "output_tokens": 50_000_000})),
            )
        db.commit()

        old_plan = monitor.plan_info.copy()
        try:
            monitor.plan_info = {"is_subscription": True, "plan_tier": "free"}
            result = monitor.compute_forecast(db)
            assert result["days_remaining"] == 0
        finally:
            monitor.plan_info = old_plan
        db.close()

    def test_subscription_unknown_tier_defaults_to_pro(self, tmp_path):
        from claude_monitoring import monitor

        db = _create_test_db(tmp_path)

        for i in range(3):
            db.execute(
                "INSERT INTO events (timestamp, event_type, source_layer, data_json) "
                "VALUES (datetime('now', ? || ' days'), 'token_usage', 'network', ?)",
                (str(-i), json.dumps({"input_tokens": 1000, "output_tokens": 500})),
            )
        db.commit()

        old_plan = monitor.plan_info.copy()
        try:
            monitor.plan_info = {"is_subscription": True, "plan_tier": "unknown_tier_xyz"}
            result = monitor.compute_forecast(db)
            # Should fallback to pro limits
            assert result["monthly_limit"] == 45_000_000
        finally:
            monitor.plan_info = old_plan
        db.close()


class TestDetectPlanInfo:
    def test_no_files_assumes_subscription(self, tmp_path):
        from claude_monitoring.monitor import detect_plan_info

        with patch("claude_monitoring.monitor.Path.home", return_value=tmp_path):
            result = detect_plan_info()
        assert result["is_subscription"] is True

    def test_stats_cache_all_zero_cost(self, tmp_path):
        from claude_monitoring.monitor import detect_plan_info

        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        stats_path = claude_dir / "stats-cache.json"
        stats_path.write_text(
            json.dumps(
                {
                    "modelUsage": {
                        "claude-sonnet-4": {"costUSD": 0},
                        "claude-haiku-4": {"costUSD": 0},
                    }
                }
            )
        )

        with patch("claude_monitoring.monitor.Path.home", return_value=tmp_path):
            result = detect_plan_info()
        assert result["is_subscription"] is True

    def test_credentials_with_subscription_type(self, tmp_path):
        from claude_monitoring.monitor import detect_plan_info

        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        creds_path = claude_dir / ".credentials.json"
        creds_path.write_text(
            json.dumps(
                {
                    "claudeAiOauth": {
                        "subscriptionType": "max_5x",
                        "rateLimitTier": "tier4",
                    }
                }
            )
        )

        with patch("claude_monitoring.monitor.Path.home", return_value=tmp_path):
            result = detect_plan_info()
        assert result["is_subscription"] is True
        assert result["plan_tier"] == "max_5x"

    def test_credentials_rate_tier_fallback(self, tmp_path):
        from claude_monitoring.monitor import detect_plan_info

        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        creds_path = claude_dir / ".credentials.json"
        creds_path.write_text(
            json.dumps(
                {
                    "claudeAiOauth": {
                        "rateLimitTier": "tier3",
                    }
                }
            )
        )

        with patch("claude_monitoring.monitor.Path.home", return_value=tmp_path):
            result = detect_plan_info()
        assert result["plan_tier"] == "tier3"

    def test_api_key_file_exists_not_subscription(self, tmp_path):
        from claude_monitoring.monitor import detect_plan_info

        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        api_key = claude_dir / "api_key"
        api_key.write_text("sk-ant-test123")

        with patch("claude_monitoring.monitor.Path.home", return_value=tmp_path):
            result = detect_plan_info()
        # Has an API key file and no other indicators
        assert result["is_subscription"] is False

    def test_corrupt_stats_file_handled(self, tmp_path):
        from claude_monitoring.monitor import detect_plan_info

        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        stats_path = claude_dir / "stats-cache.json"
        stats_path.write_text("not valid json{{{")

        with patch("claude_monitoring.monitor.Path.home", return_value=tmp_path):
            result = detect_plan_info()
        # Should not crash
        assert isinstance(result, dict)


class TestFormatUptime:
    def test_none_returns_unknown(self):
        from claude_monitoring.monitor import _format_uptime

        assert _format_uptime(None) == "unknown"

    def test_seconds(self):
        import time

        from claude_monitoring.monitor import _format_uptime

        result = _format_uptime(time.time() - 30)
        assert result.endswith("s")

    def test_minutes(self):
        import time

        from claude_monitoring.monitor import _format_uptime

        result = _format_uptime(time.time() - 300)
        assert result.endswith("m")

    def test_hours(self):
        import time

        from claude_monitoring.monitor import _format_uptime

        result = _format_uptime(time.time() - 7200)
        assert "h" in result
        assert "m" in result


class TestPushLiveEvent:
    def test_push_and_read(self):
        from claude_monitoring.monitor import live_feed, live_feed_lock, push_live_event

        with live_feed_lock:
            initial_len = len(live_feed)

        push_live_event({"type": "test", "data": "hello"})

        with live_feed_lock:
            assert len(live_feed) > initial_len


class TestLoadDashboardHtml:
    def test_returns_string(self):
        from claude_monitoring.monitor import DASHBOARD_HTML

        assert isinstance(DASHBOARD_HTML, str)
        assert len(DASHBOARD_HTML) > 0


class TestDetectAgentType:
    def test_claude_code_detected(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        result = JSONLSessionWatcher._detect_agent_type("/Users/user/.claude/projects", None)
        assert result == "claude_code"

    def test_openclaw_detected(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        result = JSONLSessionWatcher._detect_agent_type(None, "/Users/user/.openclaw/agents/main/sessions/test.jsonl")
        assert result == "openclaw"

    def test_unknown_agent(self):
        from claude_monitoring.monitor import JSONLSessionWatcher

        result = JSONLSessionWatcher._detect_agent_type("/tmp/random", "/tmp/random.jsonl")
        assert result == "unknown"
