"""P1.3 File 4 — TestScanLock.

Per the directive §7.1.2 + Rajan's 2026-06-05 ratifications:

- File-based + in-process lock
- Non-blocking acquire (returns False if held)
- chmod 600 on the lock file (CLAUDE.md mandatory)
- JSON contents: pid, started_at, trigger
- Stale-lock detection: dead PID OR age > 600s
- Release on normal exit AND on exception (release() is idempotent)
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.orchestrator.lock import (
    VALID_TRIGGERS,
    ScanLock,
)


class TestScanLock:
    def test_acquire_on_clean_state_returns_true_writes_chmod_600(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        assert lock.acquire("on_demand") is True
        assert (tmp_path / ".lock").exists()
        mode = (tmp_path / ".lock").stat().st_mode & 0o777
        assert mode == 0o600
        # Contents are JSON with the expected keys
        data = json.loads((tmp_path / ".lock").read_text())
        assert data["pid"] == os.getpid()
        assert isinstance(data["started_at"], float)
        assert data["trigger"] == "on_demand"
        lock.release()

    def test_acquire_when_live_lock_held_returns_false(self, tmp_path: Path) -> None:
        """Second instance attempting acquire returns False; does NOT
        modify or unlink the existing lock file."""
        path = tmp_path / ".lock"
        first = ScanLock(lock_path=path)
        first.acquire("on_demand")
        try:
            content_before = path.read_text()
            second = ScanLock(lock_path=path)
            assert second.acquire("on_demand") is False
            assert path.read_text() == content_before
        finally:
            first.release()

    def test_release_unlinks_and_is_idempotent(self, tmp_path: Path) -> None:
        path = tmp_path / ".lock"
        lock = ScanLock(lock_path=path)
        lock.acquire("on_demand")
        lock.release()
        assert not path.exists()
        # Idempotent — second release is a no-op
        lock.release()
        assert not path.exists()

    def test_stale_lock_by_dead_pid_is_replaced(self, tmp_path: Path) -> None:
        path = tmp_path / ".lock"
        # Create a stale lock pointing to a definitely-dead PID
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"pid": 999999, "started_at": time.time(), "trigger": "on_demand"}))
        path.chmod(0o600)
        lock = ScanLock(lock_path=path)
        assert lock.acquire("on_demand") is True
        # Replaced with our own PID
        assert json.loads(path.read_text())["pid"] == os.getpid()
        lock.release()

    def test_stale_lock_by_age_is_replaced(self, tmp_path: Path) -> None:
        path = tmp_path / ".lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        # Pretend a scan started 700s ago (> 600s threshold)
        path.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time() - 700, "trigger": "on_demand"}))
        path.chmod(0o600)
        lock = ScanLock(lock_path=path)
        assert lock.acquire("on_demand") is True
        lock.release()

    def test_invalid_trigger_raises_value_error(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        with pytest.raises(ValueError, match="trigger"):
            lock.acquire("bogus")

    def test_valid_triggers_set_is_locked(self) -> None:
        """Per Rajan's 2026-06-05 ratification: all three required."""
        assert frozenset({"scheduled", "on_demand", "cli"}) == VALID_TRIGGERS
