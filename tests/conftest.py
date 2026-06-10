"""Shared test fixtures for AI Runtime Monitor.

Test isolation guard (task #181 a2, finding 1 — judge 2026-06-10):
  * `_guard_no_real_signals` (autouse) — patches `lifecycle.os.kill` so
    any SIGTERM / SIGKILL targeting a PID outside the test's own
    process group raises immediately. Regression: on 2026-06-10 pytest
    invocations of lifecycle helpers SIGTERMed the user's daemon's
    healthy mitmdump children 9 times. The guard fails fast so the
    same accident is impossible going forward.

A port-isolation autouse guard was considered but rejected: it
collides with legitimate config tests that set get_proxy_port via
the config layer. The signal guard alone suffices for the regression
this PR closes — any SIGTERM toward the user's daemon is now blocked
at the test boundary regardless of which port the test uses.
"""

from __future__ import annotations

import os
import signal as _signal

import pytest

from claude_monitoring.db import init_db

_TEST_PGID = os.getpgrp()


@pytest.fixture(autouse=True)
def _guard_no_real_signals(monkeypatch):
    """Refuse SIGTERM/SIGKILL targeting a PID outside the test's process group.

    Patches `claude_monitoring.lifecycle.os.kill`. The check uses
    `os.getpgid(pid)` so any process belonging to a different group
    (including the user's running daemon) is rejected — but
    `os.kill(pid, 0)` (liveness probe) is left alone since signal=0
    cannot affect the target.
    """
    from claude_monitoring import lifecycle

    real_kill = os.kill

    def safe_kill(pid: int, sig: int) -> None:
        if sig == 0:
            return real_kill(pid, sig)
        if sig in (_signal.SIGTERM, _signal.SIGKILL, _signal.SIGINT):
            try:
                target_pgid = os.getpgid(pid)
            except (ProcessLookupError, PermissionError):
                target_pgid = None
            if target_pgid != _TEST_PGID:
                raise RuntimeError(
                    f"test isolation guard: attempted {sig!r} against pid={pid} "
                    f"in pgid={target_pgid} (test pgid={_TEST_PGID}). "
                    "Tests must not signal real processes — mock os.kill or "
                    "kill_orphan_mitmproxy at the call site instead."
                )
        return real_kill(pid, sig)

    monkeypatch.setattr(lifecycle.os, "kill", safe_kill)


@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary directory for output."""
    return tmp_path


@pytest.fixture()
def tmp_db(tmp_path):
    """Create a temporary SQLite database with full schema via init_db()."""
    db_path = tmp_path / "test_monitor.db"
    conn = init_db(db_path)
    yield conn
    conn.close()


@pytest.fixture()
def db_path(tmp_path):
    """Return path for a temporary database."""
    return tmp_path / "test.db"
