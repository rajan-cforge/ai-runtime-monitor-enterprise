# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for lifecycle.py — PID files, stale state detection, ProxyManager.

These tests are the core defense against "last night's bug": the monitor
dying and leaving mitmdump + system proxy stuck. Every failure mode has a
test. We monkeypatch `os.kill`, `subprocess.run`, and the paths so the
tests never touch real system proxy state.
"""

from __future__ import annotations

import logging
import os
import signal
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring import lifecycle


@pytest.fixture()
def tmp_output_dir(tmp_path, monkeypatch):
    """Redirect lifecycle paths to a tmp dir so tests never touch real state."""
    monkeypatch.setattr(lifecycle, "get_output_dir", lambda: tmp_path)
    # config helpers also need redirect if imported elsewhere
    monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
    # Phase 2: reset the singleton logger so each test gets a fresh
    # RotatingFileHandler pointing at the tmp_path log directory.
    lifecycle._LOGGER_CACHE = None
    named = logging.getLogger("ai-runtime-monitor")
    for h in list(named.handlers):
        try:
            h.close()
        except Exception:
            pass
        named.removeHandler(h)
    yield tmp_path
    lifecycle._LOGGER_CACHE = None
    for h in list(named.handlers):
        try:
            h.close()
        except Exception:
            pass
        named.removeHandler(h)


# ─────────────────────────────────────────────────────────────
# PID file basics
# ─────────────────────────────────────────────────────────────


class TestPidFiles:
    def test_write_and_read(self, tmp_output_dir):
        pid_file = tmp_output_dir / "test.pid"
        lifecycle.write_pid_file(pid_file, 12345)
        assert lifecycle.read_pid_file(pid_file) == 12345

    def test_write_creates_parent_dir(self, tmp_output_dir):
        pid_file = tmp_output_dir / "sub" / "test.pid"
        lifecycle.write_pid_file(pid_file, 99)
        assert pid_file.exists()
        assert pid_file.read_text() == "99"

    def test_read_missing_returns_none(self, tmp_output_dir):
        assert lifecycle.read_pid_file(tmp_output_dir / "nope.pid") is None

    def test_read_malformed_returns_none(self, tmp_output_dir):
        pid_file = tmp_output_dir / "bad.pid"
        pid_file.write_text("not-a-number")
        assert lifecycle.read_pid_file(pid_file) is None

    def test_write_has_600_perms(self, tmp_output_dir):
        pid_file = tmp_output_dir / "test.pid"
        lifecycle.write_pid_file(pid_file, 1)
        assert oct(pid_file.stat().st_mode)[-3:] == "600"

    def test_remove_is_idempotent(self, tmp_output_dir):
        pid_file = tmp_output_dir / "gone.pid"
        lifecycle.remove_pid_file(pid_file)  # doesn't exist
        pid_file.write_text("1")
        lifecycle.remove_pid_file(pid_file)
        lifecycle.remove_pid_file(pid_file)  # second call
        assert not pid_file.exists()


class TestIsPidAlive:
    def test_self_is_alive(self):
        assert lifecycle.is_pid_alive(os.getpid()) is True

    def test_dead_pid_returns_false(self):
        # Pick an obviously invalid PID
        assert lifecycle.is_pid_alive(999999999) is False

    def test_negative_or_zero_returns_false(self):
        assert lifecycle.is_pid_alive(0) is False
        assert lifecycle.is_pid_alive(-1) is False
        assert lifecycle.is_pid_alive(None) is False


class TestIsMitmproxyProcess:
    def test_dead_pid_returns_false(self):
        assert lifecycle.is_mitmproxy_process(999999999) is False

    def test_self_is_not_mitmproxy(self):
        # Current Python process running pytest is not mitmdump
        assert lifecycle.is_mitmproxy_process(os.getpid()) is False

    def test_mock_cmdline_matches(self):
        fake_result = MagicMock(stdout="/usr/bin/python /path/mitmdump --listen-port 9080\n")
        with (
            patch.object(lifecycle, "is_pid_alive", return_value=True),
            patch("claude_monitoring.lifecycle.subprocess.run", return_value=fake_result),
        ):
            assert lifecycle.is_mitmproxy_process(12345) is True

    def test_mock_cmdline_doesnt_match(self):
        fake_result = MagicMock(stdout="/usr/bin/vim /tmp/file.txt\n")
        with (
            patch.object(lifecycle, "is_pid_alive", return_value=True),
            patch("claude_monitoring.lifecycle.subprocess.run", return_value=fake_result),
        ):
            assert lifecycle.is_mitmproxy_process(12345) is False


# ─────────────────────────────────────────────────────────────
# Heartbeat
# ─────────────────────────────────────────────────────────────


class TestHeartbeat:
    def test_write_and_read_fresh(self, tmp_output_dir):
        lifecycle.write_heartbeat()
        age = lifecycle.heartbeat_age_seconds()
        assert age is not None
        assert age < 5  # just wrote it

    def test_missing_returns_none(self, tmp_output_dir):
        assert lifecycle.heartbeat_age_seconds() is None

    def test_malformed_returns_none(self, tmp_output_dir):
        lifecycle.get_heartbeat_file().write_text("not-iso")
        assert lifecycle.heartbeat_age_seconds() is None


# ─────────────────────────────────────────────────────────────
# Preferences
# ─────────────────────────────────────────────────────────────


class TestPreferences:
    def test_missing_returns_empty_dict(self, tmp_output_dir):
        assert lifecycle.read_preferences() == {}

    def test_write_then_read_roundtrip(self, tmp_output_dir):
        lifecycle.write_preferences({"auto_enable_proxy": True, "port": 9080})
        assert lifecycle.read_preferences() == {"auto_enable_proxy": True, "port": 9080}

    def test_write_has_600_perms(self, tmp_output_dir):
        lifecycle.write_preferences({"foo": "bar"})
        assert oct(lifecycle.get_preferences_file().stat().st_mode)[-3:] == "600"

    def test_malformed_returns_empty(self, tmp_output_dir):
        lifecycle.get_preferences_file().write_text("{not valid json")
        assert lifecycle.read_preferences() == {}


# ─────────────────────────────────────────────────────────────
# System proxy helpers
# ─────────────────────────────────────────────────────────────


class TestSystemProxyHelpers:
    def test_disable_calls_networksetup(self):
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert lifecycle.disable_system_proxy() is True
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "networksetup"
            assert "-setsecurewebproxystate" in args
            assert "off" in args

    def test_disable_swallows_exception(self):
        with patch("claude_monitoring.lifecycle.subprocess.run", side_effect=OSError("boom")):
            assert lifecycle.disable_system_proxy() is False

    def test_enabled_detection(self):
        out = "Enabled: Yes\nServer: 127.0.0.1\nPort: 9080\n"
        with patch(
            "claude_monitoring.lifecycle.subprocess.run",
            return_value=MagicMock(stdout=out),
        ):
            assert lifecycle.is_system_proxy_enabled_for_port(9080) is True

    def test_enabled_wrong_port(self):
        out = "Enabled: Yes\nPort: 8888\n"
        with patch(
            "claude_monitoring.lifecycle.subprocess.run",
            return_value=MagicMock(stdout=out),
        ):
            assert lifecycle.is_system_proxy_enabled_for_port(9080) is False

    def test_enabled_disabled(self):
        with patch(
            "claude_monitoring.lifecycle.subprocess.run",
            return_value=MagicMock(stdout="Enabled: No"),
        ):
            assert lifecycle.is_system_proxy_enabled_for_port(9080) is False


# ─────────────────────────────────────────────────────────────
# Stale state detection — the core of crash resilience
# ─────────────────────────────────────────────────────────────


class TestDetectStaleState:
    def test_clean_state_returns_empty(self, tmp_output_dir):
        """Fresh install, no PID files, no proxy — no fixes needed."""
        with patch("claude_monitoring.lifecycle.is_system_proxy_enabled_for_port", return_value=False):
            fixes = lifecycle.detect_stale_state()
        assert fixes == []

    def test_monitor_alive_proxy_alive_no_fixes(self, tmp_output_dir):
        """Healthy state: monitor and proxy both running. Don't touch them."""
        lifecycle.write_pid_file(lifecycle.get_monitor_pid_file(), os.getpid())
        lifecycle.write_pid_file(lifecycle.get_proxy_pid_file(), os.getpid())

        with (
            patch("claude_monitoring.lifecycle.is_mitmproxy_process", return_value=True),
            patch("claude_monitoring.lifecycle.is_system_proxy_enabled_for_port", return_value=True),
        ):
            fixes = lifecycle.detect_stale_state()
        assert fixes == []

    def test_kills_orphan_mitmproxy(self, tmp_output_dir):
        """Last night's bug: monitor dead, mitmproxy alive, system proxy stuck."""
        lifecycle.write_pid_file(lifecycle.get_proxy_pid_file(), 54321)
        # No monitor PID file → monitor is "dead"

        killed: list[tuple[int, int]] = []

        def fake_kill(pid, sig):
            killed.append((pid, sig))

        def fake_alive_for_orphan(pid):
            # Orphan mitmproxy alive until we "kill" it (after SIGTERM received)
            return pid == 54321 and not any(k[0] == 54321 and k[1] == signal.SIGKILL for k in killed)

        with (
            patch("claude_monitoring.lifecycle.is_mitmproxy_process", return_value=True),
            patch.object(lifecycle, "is_pid_alive", side_effect=fake_alive_for_orphan),
            patch("claude_monitoring.lifecycle.os.kill", side_effect=fake_kill),
            patch(
                "claude_monitoring.lifecycle.is_system_proxy_enabled_for_port",
                return_value=True,
            ),
            patch("claude_monitoring.lifecycle.disable_system_proxy", return_value=True) as mock_disable,
            patch("claude_monitoring.lifecycle.log_crash_event"),
            patch("claude_monitoring.lifecycle.time.sleep"),
        ):
            fixes = lifecycle.detect_stale_state()

        # Should have SIGTERM'd the orphan
        assert any(sig == signal.SIGTERM for _pid, sig in killed)
        assert any("orphan" in f.lower() for f in fixes)
        # Should have disabled system proxy
        assert mock_disable.called
        assert any("system proxy" in f.lower() for f in fixes)

    def test_disables_stuck_system_proxy_when_monitor_dead(self, tmp_output_dir):
        """System proxy is on but monitor is dead — disable the proxy."""
        with (
            patch(
                "claude_monitoring.lifecycle.is_system_proxy_enabled_for_port",
                return_value=True,
            ),
            patch("claude_monitoring.lifecycle.disable_system_proxy", return_value=True) as mock_disable,
            patch("claude_monitoring.lifecycle.log_crash_event"),
        ):
            fixes = lifecycle.detect_stale_state()

        assert mock_disable.called
        assert any("system proxy" in f.lower() for f in fixes)

    def test_removes_stale_monitor_pid_file(self, tmp_output_dir):
        """Monitor PID file points to dead process — remove it."""
        lifecycle.write_pid_file(lifecycle.get_monitor_pid_file(), 999999999)

        with (
            patch("claude_monitoring.lifecycle.is_system_proxy_enabled_for_port", return_value=False),
            patch("claude_monitoring.lifecycle.log_crash_event"),
        ):
            fixes = lifecycle.detect_stale_state()

        assert not lifecycle.get_monitor_pid_file().exists()
        assert any("stale" in f.lower() for f in fixes)


class TestCrashTelemetry:
    def test_log_crash_event_creates_table(self, tmp_output_dir, monkeypatch):
        """First call creates the crashes table and inserts a row."""
        import sqlite3

        db_path = tmp_output_dir / "test.db"
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_output_dir)
        from claude_monitoring.db import init_db

        init_db(db_path).close()

        lifecycle.log_crash_event("orphan_mitmdump", "pid=12345")

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT reason, details FROM crashes").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][0] == "orphan_mitmdump"
        assert rows[0][1] == "pid=12345"

    def test_recent_crash_count(self, tmp_output_dir, monkeypatch):

        db_path = tmp_output_dir / "test.db"
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_output_dir)
        from claude_monitoring.db import init_db

        init_db(db_path).close()

        for _ in range(3):
            lifecycle.log_crash_event("test", "")

        assert lifecycle.recent_crash_count(days=7) == 3


# ─────────────────────────────────────────────────────────────
# ProxyManager — lifecycle of the mitmdump subprocess
# ─────────────────────────────────────────────────────────────


class TestProxyManager:
    def test_start_spawns_subprocess(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        fake_proc = MagicMock()
        fake_proc.pid = 12345
        fake_proc.poll.return_value = None

        with (
            patch("claude_monitoring.lifecycle.subprocess.Popen", return_value=fake_proc) as mock_popen,
            patch("claude_monitoring.lifecycle.read_pid_file", return_value=None),
        ):
            assert pm.start() is True

        mock_popen.assert_called_once()
        assert pm.pid() == 12345

    def test_start_adopts_existing_live_proxy(self, tmp_output_dir):
        """If mitmdump is already running, don't spawn a duplicate."""
        lifecycle.write_pid_file(lifecycle.get_proxy_pid_file(), 99999)
        pm = lifecycle.ProxyManager()

        with (
            patch("claude_monitoring.lifecycle.is_mitmproxy_process", return_value=True),
            patch("claude_monitoring.lifecycle.subprocess.Popen") as mock_popen,
        ):
            assert pm.start() is True

        mock_popen.assert_not_called()
        assert pm.pid() == 99999

    def test_is_alive_with_live_subprocess(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        pm._proc = MagicMock()
        pm._proc.poll.return_value = None  # still running
        assert pm.is_alive() is True

    def test_is_alive_with_dead_subprocess(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        pm._proc = MagicMock()
        pm._proc.poll.return_value = 1  # exited with code 1
        assert pm.is_alive() is False

    def test_stop_terminates_subprocess(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        pm._proc = MagicMock()
        pm._proc.pid = 12345

        # is_pid_alive is called multiple times in the loop; return True once
        # then False forever.
        alive_state = [True]

        def fake_alive(pid):
            if alive_state[0]:
                alive_state[0] = False
                return True
            return False

        with (
            patch("claude_monitoring.lifecycle.is_pid_alive", side_effect=fake_alive),
            patch("claude_monitoring.lifecycle.os.kill") as mock_kill,
            patch("claude_monitoring.lifecycle.disable_system_proxy") as mock_disable,
            patch("claude_monitoring.lifecycle.time.sleep"),
        ):
            pm.stop(disable_proxy=True)

        mock_kill.assert_called_with(12345, signal.SIGTERM)
        mock_disable.assert_called_once()

    def test_stop_force_kills_stubborn_process(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        pm._proc = MagicMock()
        pm._proc.pid = 12345

        # Process stays alive through SIGTERM — needs SIGKILL
        kill_calls: list[int] = []

        def fake_kill(pid, sig):
            kill_calls.append(sig)

        with (
            patch("claude_monitoring.lifecycle.is_pid_alive", return_value=True),
            patch("claude_monitoring.lifecycle.os.kill", side_effect=fake_kill),
            patch("claude_monitoring.lifecycle.disable_system_proxy"),
            patch("claude_monitoring.lifecycle.time.sleep"),
            patch("claude_monitoring.lifecycle.time.time", side_effect=[0, 0, 999]),
        ):
            pm.stop(disable_proxy=False, timeout=0.1)

        assert signal.SIGTERM in kill_calls
        assert signal.SIGKILL in kill_calls

    def test_stop_removes_pid_file(self, tmp_output_dir):
        lifecycle.write_pid_file(lifecycle.get_proxy_pid_file(), 12345)
        pm = lifecycle.ProxyManager()

        with (
            patch("claude_monitoring.lifecycle.is_pid_alive", return_value=False),
            patch("claude_monitoring.lifecycle.disable_system_proxy"),
        ):
            pm.stop()

        assert not lifecycle.get_proxy_pid_file().exists()

    def test_restart_respects_max_count(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        pm._restart_count = pm.MAX_RESTARTS
        with patch("claude_monitoring.lifecycle.subprocess.Popen") as mock_popen:
            assert pm.restart() is False
        mock_popen.assert_not_called()

    def test_reset_restart_count(self, tmp_output_dir):
        pm = lifecycle.ProxyManager()
        pm._restart_count = 2
        pm.reset_restart_count()
        assert pm._restart_count == 0


# ─────────────────────────────────────────────────────────────
# Phase 2: rotating log file + stdio redirect
# ─────────────────────────────────────────────────────────────


class TestLogging:
    def test_log_dir_created(self, tmp_output_dir):
        lifecycle.get_logger()
        assert lifecycle.get_log_dir().exists()

    def test_logger_writes_to_file(self, tmp_output_dir):
        lifecycle._LOGGER_CACHE = None
        logger = lifecycle.get_logger()
        logger.info("test message 12345")
        for h in logger.handlers:
            h.flush()
        content = lifecycle.get_log_path().read_text()
        assert "test message 12345" in content

    def test_logger_is_singleton(self, tmp_output_dir):
        lifecycle._LOGGER_CACHE = None
        a = lifecycle.get_logger()
        b = lifecycle.get_logger()
        assert a is b
        assert len(a.handlers) == 1  # not duplicated

    def test_stream_to_logger_redirect(self, tmp_output_dir):
        lifecycle._LOGGER_CACHE = None
        logger = lifecycle.get_logger()
        stream = lifecycle._StreamToLogger(logger)
        stream.write("line one\n")
        stream.write("line two\n")
        stream.flush()
        for h in logger.handlers:
            h.flush()
        content = lifecycle.get_log_path().read_text()
        assert "line one" in content
        assert "line two" in content

    def test_redirect_stdio_to_log(self, tmp_output_dir, monkeypatch):
        import sys

        lifecycle._LOGGER_CACHE = None
        orig_stdout = sys.stdout
        try:
            lifecycle.redirect_stdio_to_log()
            print("daemon mode test")
            sys.stdout.flush()
        finally:
            sys.stdout = orig_stdout
        logger = logging.getLogger("ai-runtime-monitor")
        for h in logger.handlers:
            h.flush()
        content = lifecycle.get_log_path().read_text()
        assert "daemon mode test" in content
