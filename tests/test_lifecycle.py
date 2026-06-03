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
import subprocess
import sys
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
            patch("claude_monitoring.lifecycle.kill_orphan_mitmproxy", return_value=[]),
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

    def test_start_kills_orphan_before_spawning(self, tmp_output_dir):
        """When a zombie mitmdump holds the proxy port, start() must kill
        it before spawning — otherwise the new mitmdump dies with
        EADDRINUSE and the watchdog falls into a 30-second flap loop."""
        pm = lifecycle.ProxyManager()
        killed: list[int] = []

        def fake_kill_orphans(port, exclude_pid=None, **kw):
            killed.append(port)
            return [98765]

        fake_proc = MagicMock()
        fake_proc.pid = 55555
        fake_proc.poll.return_value = None

        with (
            patch("claude_monitoring.lifecycle.read_pid_file", return_value=None),
            patch("claude_monitoring.lifecycle.kill_orphan_mitmproxy", side_effect=fake_kill_orphans) as mock_kill,
            patch("claude_monitoring.lifecycle.subprocess.Popen", return_value=fake_proc),
        ):
            assert pm.start() is True

        mock_kill.assert_called_once()
        assert killed == [lifecycle.get_proxy_port()]


class TestOrphanMitmproxyCleanup:
    def test_find_orphan_parses_lsof_output(self, tmp_output_dir):
        # lsof output: first line is header, subsequent lines are
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        sample = (
            "COMMAND  PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
            "Python  4682 rajanyadav    7u  IPv6 0xcf851315a5526bc9      0t0  TCP *:9080 (LISTEN)\n"
        )
        completed = MagicMock()
        completed.stdout = sample

        with (
            patch("claude_monitoring.lifecycle.subprocess.run", return_value=completed),
            patch("claude_monitoring.lifecycle.is_mitmproxy_process", return_value=True),
        ):
            pids = lifecycle.find_orphan_mitmproxy_on_port(9080)
        assert pids == [4682]

    def test_find_orphan_excludes_our_pid(self, tmp_output_dir):
        sample = (
            "COMMAND  PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
            "Python  4682 rajanyadav    7u  IPv6 0xcf851315a5526bc9      0t0  TCP *:9080 (LISTEN)\n"
        )
        completed = MagicMock()
        completed.stdout = sample
        with (
            patch("claude_monitoring.lifecycle.subprocess.run", return_value=completed),
            patch("claude_monitoring.lifecycle.is_mitmproxy_process", return_value=True),
        ):
            pids = lifecycle.find_orphan_mitmproxy_on_port(9080, exclude_pid=4682)
        assert pids == []

    def test_find_orphan_ignores_non_mitmproxy_processes(self, tmp_output_dir):
        sample = (
            "COMMAND  PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
            "someapp 1111 rajanyadav    7u  IPv6 0xcf851315a5526bc9      0t0  TCP *:9080 (LISTEN)\n"
        )
        completed = MagicMock()
        completed.stdout = sample
        with (
            patch("claude_monitoring.lifecycle.subprocess.run", return_value=completed),
            patch("claude_monitoring.lifecycle.is_mitmproxy_process", return_value=False),
        ):
            pids = lifecycle.find_orphan_mitmproxy_on_port(9080)
        assert pids == []

    def test_find_orphan_returns_empty_on_lsof_error(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.subprocess.run", side_effect=OSError("boom")):
            assert lifecycle.find_orphan_mitmproxy_on_port(9080) == []

    def test_kill_orphan_signals_victims_and_waits(self, tmp_output_dir):
        victims_killed: list[tuple[int, int]] = []

        def fake_kill(pid, sig):
            victims_killed.append((pid, sig))

        # is_pid_alive returns True once (first-pass wait), then False
        alive_calls = [True, True, False, False]

        def fake_alive(pid):
            return alive_calls.pop(0) if alive_calls else False

        with (
            patch("claude_monitoring.lifecycle.find_orphan_mitmproxy_on_port", return_value=[4682]),
            patch("claude_monitoring.lifecycle.os.kill", side_effect=fake_kill),
            patch("claude_monitoring.lifecycle.is_pid_alive", side_effect=fake_alive),
            patch("claude_monitoring.lifecycle.time.sleep"),
        ):
            killed = lifecycle.kill_orphan_mitmproxy(9080, timeout=0.5)

        assert killed == [4682]
        assert (4682, signal.SIGTERM) in victims_killed

    def test_kill_orphan_escalates_to_sigkill(self, tmp_output_dir):
        kill_signals: list[int] = []

        def fake_kill(pid, sig):
            kill_signals.append(sig)

        with (
            patch("claude_monitoring.lifecycle.find_orphan_mitmproxy_on_port", return_value=[4682]),
            patch("claude_monitoring.lifecycle.os.kill", side_effect=fake_kill),
            # Always alive → forces SIGKILL escalation
            patch("claude_monitoring.lifecycle.is_pid_alive", return_value=True),
            patch("claude_monitoring.lifecycle.time.sleep"),
            patch("claude_monitoring.lifecycle.time.time", side_effect=[0, 0, 999, 999]),
        ):
            lifecycle.kill_orphan_mitmproxy(9080, timeout=0.1)

        assert signal.SIGTERM in kill_signals
        assert signal.SIGKILL in kill_signals

    def test_kill_orphan_returns_empty_when_no_victims(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.find_orphan_mitmproxy_on_port", return_value=[]):
            assert lifecycle.kill_orphan_mitmproxy(9080) == []


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


# ─────────────────────────────────────────────────────────────
# Shutdown ordering — cleanup_for_shutdown (lifecycle reliability)
# ─────────────────────────────────────────────────────────────


class TestCleanupForShutdown:
    """The atomic shutdown helper.

    `cleanup_for_shutdown` is called as the FIRST action in every shutdown
    path (signal handler, atexit) so the user is never left with a stuck
    proxy or stale PID file even if launchd's KillTimeout interrupts the
    slower mitmdump SIGTERM step. See docs/design/lifecycle-reliability.md.
    """

    def test_removes_pid_file_and_disables_proxy(self, tmp_output_dir):
        pid_file = tmp_output_dir / "monitor.pid"
        pid_file.write_text("12345")
        with patch.object(lifecycle, "disable_system_proxy", return_value=True) as mock_disable:
            lifecycle.cleanup_for_shutdown(pid_file)
        assert not pid_file.exists()
        mock_disable.assert_called_once()

    def test_removes_pid_before_disabling_proxy(self, tmp_output_dir):
        """The fast/unconditional PID removal must precede the proxy disable.

        Pinning the order in a test (not just by code reading) so a future
        refactor that swaps the two `with suppress()` blocks fails CI rather
        than silently changing the invariant the design doc relies on.
        """
        pid_file = tmp_output_dir / "monitor.pid"
        pid_file.write_text("12345")
        ordering: list[str] = []

        def fake_remove(path):
            ordering.append(f"remove({path.name})")
            path.unlink(missing_ok=True)

        def fake_disable():
            ordering.append("disable_proxy")
            return True

        with (
            patch.object(lifecycle, "remove_pid_file", side_effect=fake_remove),
            patch.object(lifecycle, "disable_system_proxy", side_effect=fake_disable),
        ):
            lifecycle.cleanup_for_shutdown(pid_file)
        assert ordering == ["remove(monitor.pid)", "disable_proxy"]

    def test_swallows_remove_pid_errors(self, tmp_output_dir):
        pid_file = tmp_output_dir / "monitor.pid"
        pid_file.write_text("12345")
        with (
            patch.object(lifecycle, "remove_pid_file", side_effect=OSError("boom")),
            patch.object(lifecycle, "disable_system_proxy", return_value=True) as mock_disable,
        ):
            lifecycle.cleanup_for_shutdown(pid_file)  # must not raise
        mock_disable.assert_called_once()

    def test_swallows_disable_proxy_errors(self, tmp_output_dir):
        pid_file = tmp_output_dir / "monitor.pid"
        pid_file.write_text("12345")
        with patch.object(lifecycle, "disable_system_proxy", side_effect=RuntimeError("boom")):
            lifecycle.cleanup_for_shutdown(pid_file)  # must not raise
        assert not pid_file.exists()

    def test_idempotent_with_missing_pid_file(self, tmp_output_dir):
        pid_file = tmp_output_dir / "nope.pid"
        with patch.object(lifecycle, "disable_system_proxy", return_value=True) as mock_disable:
            lifecycle.cleanup_for_shutdown(pid_file)
            lifecycle.cleanup_for_shutdown(pid_file)
        assert mock_disable.call_count == 2

    def test_proxy_disable_runs_even_if_pid_remove_raises(self, tmp_output_dir):
        """Critical ordering property: an exception in step 1 must not skip step 2.

        If the PID file removal raises (e.g. permissions weirdness on shutdown),
        the user's network must still be cleaned up. This is the inverse of the
        bug that caused 20 stuck_system_proxy events in the log.
        """
        pid_file = tmp_output_dir / "monitor.pid"
        pid_file.write_text("12345")
        with (
            patch.object(lifecycle, "remove_pid_file", side_effect=OSError("permission")),
            patch.object(lifecycle, "disable_system_proxy", return_value=True) as mock_disable,
        ):
            lifecycle.cleanup_for_shutdown(pid_file)
        mock_disable.assert_called_once()


# ─────────────────────────────────────────────────────────────
# Bind retry — bind_with_retry (lifecycle reliability)
# ─────────────────────────────────────────────────────────────


class TestBindWithRetry:
    """Retry the dashboard bind on EADDRINUSE.

    Without retry, the launchd KeepAlive restart loop hits the previous
    instance's still-LISTEN-ing socket and dies on the first attempt
    (~10 occurrences in the log). With bounded backoff, restart races
    converge cleanly. See docs/design/lifecycle-reliability.md.
    """

    def test_returns_on_first_success(self):
        sentinel = object()
        factory = MagicMock(return_value=sentinel)
        with patch.object(lifecycle.time, "sleep") as mock_sleep:
            result = lifecycle.bind_with_retry(factory, port=9081)
        assert result is sentinel
        factory.assert_called_once()
        mock_sleep.assert_not_called()

    def test_retries_on_eaddrinuse_then_succeeds(self):
        import errno as _errno

        sentinel = object()
        factory = MagicMock(
            side_effect=[
                OSError(_errno.EADDRINUSE, "Address already in use"),
                OSError(_errno.EADDRINUSE, "Address already in use"),
                sentinel,
            ]
        )
        with (
            patch.object(lifecycle.time, "sleep") as mock_sleep,
            patch.object(lifecycle, "_identify_port_holder", return_value="python(12345)"),
        ):
            result = lifecycle.bind_with_retry(factory, port=9081)
        assert result is sentinel
        assert factory.call_count == 3
        assert mock_sleep.call_count == 2  # one sleep per retry

    def test_raises_after_max_attempts(self):
        import errno as _errno

        factory = MagicMock(side_effect=OSError(_errno.EADDRINUSE, "boom"))
        with (
            patch.object(lifecycle.time, "sleep"),
            patch.object(lifecycle, "_identify_port_holder", return_value="unknown"),
            pytest.raises(OSError) as excinfo,
        ):
            lifecycle.bind_with_retry(factory, port=9081, max_attempts=3)
        assert excinfo.value.errno == _errno.EADDRINUSE
        assert factory.call_count == 3

    def test_does_not_retry_on_other_oserror(self):
        import errno as _errno

        factory = MagicMock(side_effect=OSError(_errno.EACCES, "denied"))
        with (
            patch.object(lifecycle.time, "sleep") as mock_sleep,
            pytest.raises(OSError) as excinfo,
        ):
            lifecycle.bind_with_retry(factory, port=9081)
        assert excinfo.value.errno == _errno.EACCES
        factory.assert_called_once()
        mock_sleep.assert_not_called()

    def test_uses_configured_backoff_schedule(self):
        """First two retry sleeps must come from BIND_RETRY_BACKOFF_SECONDS in order."""
        import errno as _errno

        sentinel = object()
        factory = MagicMock(
            side_effect=[
                OSError(_errno.EADDRINUSE, ""),
                OSError(_errno.EADDRINUSE, ""),
                sentinel,
            ]
        )
        with (
            patch.object(lifecycle.time, "sleep") as mock_sleep,
            patch.object(lifecycle, "_identify_port_holder", return_value="unknown"),
        ):
            lifecycle.bind_with_retry(factory, port=9081)
        assert mock_sleep.call_args_list[0].args[0] == lifecycle.BIND_RETRY_BACKOFF_SECONDS[0]
        assert mock_sleep.call_args_list[1].args[0] == lifecycle.BIND_RETRY_BACKOFF_SECONDS[1]

    def test_logs_port_holder_on_retry(self, caplog):
        import errno as _errno

        sentinel = object()
        factory = MagicMock(side_effect=[OSError(_errno.EADDRINUSE, ""), sentinel])
        with (
            patch.object(lifecycle.time, "sleep"),
            patch.object(lifecycle, "_identify_port_holder", return_value="python(99999)"),
            caplog.at_level(logging.WARNING, logger="ai-runtime-monitor"),
        ):
            lifecycle.bind_with_retry(factory, port=9081)
        assert any("python(99999)" in rec.message for rec in caplog.records)


class TestIdentifyPortHolder:
    """The diagnostic lsof query used by bind_with_retry — never load-bearing."""

    def test_returns_unknown_on_lsof_failure(self):
        with patch("claude_monitoring.lifecycle.subprocess.run", side_effect=OSError("no lsof")):
            assert lifecycle._identify_port_holder(9081, "127.0.0.1") == "unknown"

    def test_returns_unknown_on_empty_output(self):
        fake = MagicMock(stdout="")
        with patch("claude_monitoring.lifecycle.subprocess.run", return_value=fake):
            assert lifecycle._identify_port_holder(9081, "127.0.0.1") == "unknown"

    def test_parses_lsof_header_and_first_row(self):
        fake = MagicMock(
            stdout=(
                "COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME\n"
                "Python  12345 user   7u  IPv4 0x1234     0t0  TCP 127.0.0.1:9081 (LISTEN)\n"
            )
        )
        with patch("claude_monitoring.lifecycle.subprocess.run", return_value=fake):
            holder = lifecycle._identify_port_holder(9081, "127.0.0.1")
        assert "Python" in holder and "12345" in holder


# ─────────────────────────────────────────────────────────────
# Empirical regression test — pins PR #73's failure shape
#
# PR #73 added ``--listen-host ::`` to the mitmdump cmdline,
# assuming the macOS BSD default IPV6_V6ONLY=0 would make a
# single ``::`` socket accept both stacks. mitmproxy 12.x (the
# installed version) explicitly sets IPV6_V6ONLY=1, so the
# result was a single IPv6-only socket and IPv4 connections
# were refused — including from macOS system proxy which is
# always configured at an IPv4 host. PR #74 reverted it.
#
# This test runs a real mitmdump subprocess on a random high
# port and asserts via ``lsof`` that BOTH IPv4 and IPv6 LISTEN
# entries exist. Any future change that ever collapses to
# single-stack fails immediately at CI time instead of in
# production. The test that *should* have existed before
# PR #73 — its absence is what let the regression through.
# ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="mitmproxy 12.x sets IPV6_V6ONLY=1 explicitly on its sockets; "
    "on Linux this blocks dual-stack in the same way. A separate test "
    "pinning Linux dual-stack behaviour is not yet authored.",
)
class TestMitmdumpDualStackOnMacOS:
    """Regression test for PR #73's failure mode. Real subprocess; ~5s."""

    @staticmethod
    def _pick_free_high_port() -> int:
        """Bind to port 0 to let the OS pick an unused port, close,
        return the number."""
        import socket as _socket

        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _lsof_listen_entries(self, pid: int) -> tuple[list[str], str | None]:
        """Return ``(LISTEN_lines, error_or_None)``.

        Returning the error rather than swallowing it lets the caller
        include lsof failures in the assertion message, so CI failures
        are diagnosable instead of misleadingly attributed to "no IPv4
        bind seen". Per code-reviewer (80% confidence).
        """
        try:
            result = subprocess.run(
                ["lsof", "-nP", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return [], f"lsof invocation failed: {exc!r}"
        return [line for line in result.stdout.splitlines() if "LISTEN" in line], None

    def test_default_invocation_binds_both_ipv4_and_ipv6(self):
        """With mitmproxy 12.x's default behaviour (no explicit
        ``--listen-host``), both IPv4 and IPv6 LISTEN entries must be
        present on the chosen port. The PR #73 regression failed this
        because ``--listen-host ::`` collapsed to a single IPv6-only
        listener.
        """
        import shutil
        import time

        if shutil.which("mitmdump") is None:
            pytest.skip("mitmdump not installed in this environment")

        port = self._pick_free_high_port()
        proc = subprocess.Popen(
            ["mitmdump", "--listen-port", str(port), "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # Poll up to 5s for the listeners to appear
            ipv4_seen = ipv6_seen = False
            entries: list[str] = []
            last_lsof_error: str | None = None
            deadline = time.time() + 5
            while time.time() < deadline:
                entries, last_lsof_error = self._lsof_listen_entries(proc.pid)
                for line in entries:
                    if f":{port}" not in line:
                        continue
                    if "IPv4" in line:
                        ipv4_seen = True
                    if "IPv6" in line:
                        ipv6_seen = True
                if ipv4_seen and ipv6_seen:
                    break
                time.sleep(0.2)

            # Include any lsof error in the assertion message so a CI
            # failure points at the real cause rather than implying the
            # bind didn't happen.
            diag = f" (lsof error: {last_lsof_error})" if last_lsof_error else ""
            assert ipv4_seen, (
                f"mitmdump on port {port} did not bind IPv4 LISTEN — "
                f"this is the PR #73 regression shape.{diag} "
                f"Lsof entries: {entries!r}"
            )
            assert ipv6_seen, (
                f"mitmdump on port {port} did not bind IPv6 LISTEN — "
                f"any dual-stack change must keep IPv6 too.{diag} "
                f"Lsof entries: {entries!r}"
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                # SIGKILL is near-instant on macOS, but under extreme
                # load wait() can still raise. Swallow it — at this
                # point the process is going down regardless, and an
                # uncaught TimeoutExpired here would mask the real
                # assertion failure above. Per code-reviewer (85%).
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
