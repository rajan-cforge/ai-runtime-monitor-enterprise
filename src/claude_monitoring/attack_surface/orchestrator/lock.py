"""`ScanLock` — file-based + in-process lock for non-overlapping discovery scans.

Per the v0.2.2 implementation directive §7.1.2: only one scan runs at a
time on a given host. The lock is non-blocking — a second invocation
that arrives while a scan is in progress returns `False` from
:meth:`acquire` and the caller short-circuits.

**File contents** (JSON; chmod 600):

- ``pid`` — current process ID
- ``started_at`` — float Unix timestamp at acquire time
- ``trigger`` — one of ``"scheduled"`` / ``"on_demand"`` / ``"cli"``

**Stale lock detection** — if the lock file exists but either (a) the
PID is no longer alive or (b) ``started_at`` is older than
:attr:`STALE_THRESHOLD_SEC` (600s, matching the P1.5 finalizer cutoff),
the lock is treated as abandoned and forcibly released.

**Thread-safety:** an in-process :class:`threading.Lock` is held in
addition to the file lock so that two threads inside the same daemon
process cannot both acquire (the file-only check would race).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger("ai-runtime-monitor.attack_surface.orchestrator.lock")


VALID_TRIGGERS: frozenset[str] = frozenset({"scheduled", "on_demand", "cli"})
"""Locked trigger vocabulary per Rajan's 2026-06-05 ratification."""


class ScanLock:
    """File-based + in-process scan lock.

    Args:
        lock_path: Filesystem path for the lock file. Default
            ``~/claude_watch_output/.discovery.lock`` (mirrors the
            existing monitor.pid precedent).
    """

    STALE_THRESHOLD_SEC: int = 600
    """Lock files older than this (by `started_at`) are treated as
    abandoned by a crashed daemon. Matches P1.5's `finalize_crashed_runs`
    cutoff."""

    _process_lock: threading.Lock = threading.Lock()
    """Class-level in-process guard. A single daemon process cannot
    acquire twice even from different threads."""

    def __init__(self, lock_path: Path | str | None = None) -> None:
        if lock_path is None:
            lock_path = Path.home() / "claude_watch_output" / ".discovery.lock"
        self.lock_path = Path(lock_path)
        self._held = False

    def acquire(self, trigger: str) -> bool:
        """Acquire the lock non-blocking. Return True on success.

        Validates `trigger` against the locked vocabulary. Stale-locks
        (dead PID OR older than STALE_THRESHOLD_SEC) are forcibly
        released and replaced. The lock file is written chmod 600.
        """
        if trigger not in VALID_TRIGGERS:
            raise ValueError(f"ScanLock.acquire: trigger must be one of {sorted(VALID_TRIGGERS)}, got {trigger!r}")
        if not self._process_lock.acquire(blocking=False):
            return False
        try:
            if self.lock_path.exists():
                if self._is_stale():
                    logger.warning("scan-lock: stale lock at %s; replacing", self.lock_path)
                    self.lock_path.unlink()
                else:
                    self._process_lock.release()
                    return False
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "pid": os.getpid(),
                "started_at": time.time(),
                "trigger": trigger,
            }
            self.lock_path.write_text(json.dumps(payload))
            self.lock_path.chmod(0o600)
            self._held = True
            return True
        except Exception:
            # Release the in-process guard so the next attempt isn't blocked
            # by a half-acquired state.
            if self._process_lock.locked():
                self._process_lock.release()
            raise

    def release(self) -> None:
        """Release the lock if held. Idempotent — calling on an unheld
        lock is a no-op (supports the `finally` cleanup pattern)."""
        if not self._held:
            return
        try:
            if self.lock_path.exists():
                self.lock_path.unlink()
        except OSError as exc:
            logger.warning("scan-lock: failed to remove %s: %s", self.lock_path, exc)
        finally:
            self._held = False
            if self._process_lock.locked():
                self._process_lock.release()

    def read_holder_trigger(self) -> str | None:
        """Return the trigger of the current lock holder, or ``None`` if
        no lock file exists / can't be parsed.

        Added in P4.5: the scheduler reads this on ``acquire()=False`` so
        it can emit the spec §8.6 / directive L585 deferral log line
        (``"Scheduled scan deferred — on-demand scan in progress"``)
        only when the holder is actually an on-demand or cli scan.
        """
        if not self.lock_path.exists():
            return None
        try:
            data = json.loads(self.lock_path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        trigger = data.get("trigger")
        return trigger if isinstance(trigger, str) else None

    def _is_stale(self) -> bool:
        try:
            data = json.loads(self.lock_path.read_text())
        except (OSError, json.JSONDecodeError):
            return True  # corrupt file → treat as stale
        pid = data.get("pid")
        started_at = data.get("started_at", 0.0)
        if isinstance(started_at, (int, float)) and (time.time() - started_at > self.STALE_THRESHOLD_SEC):
            return True
        if not isinstance(pid, int) or not _pid_alive(pid):
            return True
        return False


def _pid_alive(pid: int) -> bool:
    """Best-effort check whether PID is currently alive.

    Mirrors `persistence/migrations.py`'s daemon-alive heuristic:
    `os.kill(pid, 0)` doesn't send a signal but raises if the process
    is gone. On unknown OSError (permission etc.) treat as alive
    (conservative — won't claim a stale-PID lock just because we can't
    introspect it).
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True
