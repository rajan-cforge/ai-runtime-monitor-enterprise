"""Watchdog must honor explicit ``--stop`` and not respawn mitmdump.

**Symptom this guards against (issue #98, 4th gap):** when the user invokes
``ai-monitor --stop``, ``ProxyManager.stop()`` SIGTERM's mitmdump and sets
``_stopped = True``. Without a guard, the watchdog loop's next tick sees
``is_alive() == False`` and respawns mitmdump as an orphan that survives
the monitor process. Empirical proof from 2026-06-08 user session:

::

    Shutting down...
    ⚠ Watchdog: mitmdump died — disabling system proxy
    ✅ Watchdog: mitmdump restarted              ← THIS IS THE BUG

The fix exposes ``ProxyManager.was_explicitly_stopped()`` and gates the
watchdog's respawn + healthy-streak counter on it.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from claude_monitoring.lifecycle import ProxyManager


class TestExplicitStopFlag:
    """The flag exists, defaults False, flips True after ``stop()``."""

    def test_default_false(self, tmp_path) -> None:
        pm = ProxyManager(log_path=tmp_path / "mitm.log")
        assert pm.was_explicitly_stopped() is False

    def test_stop_sets_the_flag(self, tmp_path) -> None:
        pm = ProxyManager(log_path=tmp_path / "mitm.log")
        # `stop()` with no live PID is a no-op for kill; it still latches.
        pm.stop(disable_proxy=False)
        assert pm.was_explicitly_stopped() is True


class TestWatchdogHonorsExplicitStop:
    """Simulate the watchdog tick: a ProxyManager that's been explicitly
    stopped must NOT trigger the restart branch."""

    def test_explicitly_stopped_pm_skips_restart_branch(self, tmp_path) -> None:
        """The watchdog loop's condition is::

            if pm is not None and not pm.is_alive() and not pm.was_explicitly_stopped():
                ... restart ...

        When the user has invoked `--stop`, ``was_explicitly_stopped()`` is True
        AND ``is_alive()`` is False (because ``_stopped`` short-circuits it).
        The watchdog must skip the restart branch."""
        pm = ProxyManager(log_path=tmp_path / "mitm.log")
        pm.stop(disable_proxy=False)

        # Replicate the watchdog's three-part condition
        should_restart = pm is not None and not pm.is_alive() and not pm.was_explicitly_stopped()
        assert should_restart is False, "watchdog would respawn mitmdump after explicit --stop — issue #98"

    def test_dead_but_not_explicitly_stopped_DOES_trigger_restart(self, tmp_path, monkeypatch) -> None:
        """Inverse case: if mitmdump genuinely crashed (not via `stop()`),
        the watchdog SHOULD restart it. Guard must not over-suppress."""
        pm = ProxyManager(log_path=tmp_path / "mitm.log")
        # Simulate: process is dead but `stop()` was never called.
        # Force is_alive() to False without flipping _stopped.
        monkeypatch.setattr(pm, "is_alive", lambda: False)

        should_restart = pm is not None and not pm.is_alive() and not pm.was_explicitly_stopped()
        assert should_restart is True, (
            "watchdog must restart genuinely-crashed mitmdump — the guard "
            "should only suppress explicit-stop, not all-cause death"
        )


class TestWatchdogLoopIntegration:
    """End-to-end shape check: import the watchdog loop's restart predicate
    from the patched code and verify the guard is in place. Catches
    regressions where someone removes the ``was_explicitly_stopped()``
    check from ``monitor.py``."""

    def test_monitor_watchdog_loop_imports_was_explicitly_stopped(self) -> None:
        """Static guard: the watchdog code must reference the guard method.
        Cheap but catches the regression class where the fix gets reverted."""
        import inspect

        from claude_monitoring import monitor

        source = inspect.getsource(monitor)
        assert "was_explicitly_stopped" in source, (
            "monitor.py must call pm.was_explicitly_stopped() in the watchdog "
            "loop — issue #98 (4th gap). The watchdog races against `--stop` "
            "without this guard and resurrects mitmdump as an orphan."
        )


class TestRestartSemanticsAfterStop:
    """If the user does ``--stop`` followed by ``--start`` (a typical
    recovery flow), the ProxyManager should be able to spawn again —
    the explicit-stop latch must clear on a successful start. (Documented
    here as a contract; the existing start path already does
    ``self._stopped = False`` in :meth:`start`.)"""

    def test_start_clears_explicit_stop_latch(self, tmp_path, monkeypatch) -> None:
        pm = ProxyManager(log_path=tmp_path / "mitm.log")
        pm.stop(disable_proxy=False)
        assert pm.was_explicitly_stopped() is True

        # Mock the actual subprocess.Popen so we don't really spawn mitmdump
        fake_proc = MagicMock()
        fake_proc.pid = 99999
        fake_proc.poll.return_value = None
        monkeypatch.setattr(
            "claude_monitoring.lifecycle.subprocess.Popen",
            MagicMock(return_value=fake_proc),
        )
        # The orphan-port check would normally inspect the system; stub it.
        monkeypatch.setattr(
            "claude_monitoring.lifecycle.kill_orphan_mitmproxy",
            MagicMock(return_value=[]),
        )
        # write_pid_file writes under output_dir — point it at tmp.
        from claude_monitoring import lifecycle

        monkeypatch.setattr(lifecycle, "get_proxy_pid_file", lambda: tmp_path / "mitm.pid")

        pm.start()
        assert pm.was_explicitly_stopped() is False, (
            "a successful start() must clear the explicit-stop latch — "
            "otherwise the watchdog would refuse to monitor the freshly-"
            "spawned mitmdump for crashes"
        )


# ─────────────────────────────────────────────────────────────
# Issue #98 follow-up — task #181 leg 2
# Watchdog symmetry: disabling system proxy on mitmdump death MUST be
# paired with re-enabling on a successful restart (iff the user
# originally had it on). Regression: 2026-06-10, capture was silently
# off for ~2 hours after pytest false-positive deaths disabled the
# proxy and the watchdog never restored it.
# ─────────────────────────────────────────────────────────────


class TestWatchdogRestoresSystemProxyOnRestart:
    """Leg 2 — symmetric proxy re-enable.

    The watchdog calls ``disable_system_proxy()`` whenever pm.is_alive()
    returns False. After ``pm.restart()`` succeeds, the watchdog MUST
    re-enable the system proxy IF the user originally had it on for
    this port — otherwise the daemon silently stops capturing desktop-
    app traffic until the user notices and runs --enable-system-proxy.
    """

    def test_monitor_watchdog_calls_enable_system_proxy_on_restart(self) -> None:
        """Static guard: the watchdog source must call the lifecycle helper
        that owns the disable + restart + re-enable trio. Either
        ``handle_mitmdump_death_and_restart`` (the consolidated helper used
        today) or a direct ``enable_system_proxy`` reference proves the
        restore path exists. Static check is enough because the actual
        call is gated on observed pre-disable state."""
        import inspect

        from claude_monitoring import monitor

        source = inspect.getsource(monitor)
        watchdog_start = source.find("def _watchdog_loop")
        assert watchdog_start != -1, "monitor.py must define _watchdog_loop"
        watchdog_src = source[watchdog_start : watchdog_start + 4000]
        # Also assert the lifecycle helper itself does the re-enable —
        # belt-and-suspenders against someone removing the restore branch
        # there too.
        from claude_monitoring import lifecycle

        lifecycle_src = inspect.getsource(lifecycle)
        watchdog_calls_helper = (
            "handle_mitmdump_death_and_restart" in watchdog_src or "enable_system_proxy" in watchdog_src
        )
        assert watchdog_calls_helper, (
            "watchdog must invoke the re-enable path — task #181 leg 2. "
            "Without this the daemon silently stops capturing desktop-app "
            "traffic after any restart cycle."
        )
        assert "enable_system_proxy_for_port" in lifecycle_src, (
            "lifecycle.handle_mitmdump_death_and_restart must call "
            "enable_system_proxy_for_port when proxy was on pre-disable."
        )
