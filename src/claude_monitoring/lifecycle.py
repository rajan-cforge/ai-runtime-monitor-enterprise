# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Process lifecycle management for AI Runtime Monitor.

This module is the single source of truth for:
  - PID file creation/cleanup for the monitor and mitmproxy
  - Stale state detection (orphan mitmdump, stuck system proxy)
  - Managing mitmproxy as a supervised child with health checks
  - Heartbeat file for external liveness detection

Everything here is safe to call from OUTSIDE the running process. That's
the point: if the monitor crashes (SIGKILL, OOM, segfault), the next
invocation of `ai-monitor --start` must be able to detect the wreckage
and clean it up before starting fresh. We cannot rely on atexit hooks
because those don't run on abnormal termination.

The crashes table in the DB tracks every orphan detection so `--status`
can warn the user if their setup is unstable.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from claude_monitoring.config import get_output_dir, get_proxy_port

# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────


def get_monitor_pid_file() -> Path:
    return get_output_dir() / "monitor.pid"


def get_proxy_pid_file() -> Path:
    return get_output_dir() / "mitmproxy.pid"


def get_heartbeat_file() -> Path:
    return get_output_dir() / ".heartbeat"


def get_preferences_file() -> Path:
    return get_output_dir() / ".preferences.json"


# ─────────────────────────────────────────────────────────────
# PID file operations
# ─────────────────────────────────────────────────────────────


def write_pid_file(pid_file: Path, pid: int) -> None:
    """Write a PID to a file with chmod 600. Parent dir is created if needed."""
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(pid))
    try:
        os.chmod(str(pid_file), 0o600)
    except OSError:
        pass


def read_pid_file(pid_file: Path) -> int | None:
    """Return the PID in a file, or None if missing/malformed."""
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return None


def remove_pid_file(pid_file: Path) -> None:
    try:
        pid_file.unlink(missing_ok=True)
    except OSError:
        pass


def is_pid_alive(pid: int) -> bool:
    """Return True if a process with the given PID currently exists.

    Uses kill(pid, 0) which is the canonical Unix idiom: no signal sent,
    but ESRCH is raised if the PID doesn't exist. EPERM means the PID
    exists but belongs to another user (still "alive" from our POV).
    """
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        return True  # EPERM — process exists, just not ours


def is_mitmproxy_process(pid: int) -> bool:
    """Best-effort check that a PID belongs to mitmdump and not some
    recycled PID belonging to another program.

    Uses `ps` to read the command line. Returns True if mitmdump or
    our watch.py addon module appears. Returns False on any error
    (fail-safe: don't kill processes we're not sure about).
    """
    if not is_pid_alive(pid):
        return False
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
        cmdline = result.stdout.lower()
        return "mitmdump" in cmdline or "claude_monitoring.watch" in cmdline
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# Heartbeat
# ─────────────────────────────────────────────────────────────


def write_heartbeat() -> None:
    """Update the heartbeat file with the current UTC timestamp.

    The heartbeat is checked by `_detect_stale_state` and by `--status`.
    If the file is older than HEARTBEAT_STALE_SECONDS but the monitor
    PID file exists, something is wrong (process hung in a way that
    prevents the watchdog thread from running).
    """
    try:
        get_heartbeat_file().write_text(datetime.now(timezone.utc).isoformat())
    except OSError:
        pass


def heartbeat_age_seconds() -> float | None:
    hb = get_heartbeat_file()
    if not hb.exists():
        return None
    try:
        ts = datetime.fromisoformat(hb.read_text().strip())
        return (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return None


HEARTBEAT_STALE_SECONDS = 120  # watchdog writes every 30s; 120s is generous


# ─────────────────────────────────────────────────────────────
# System proxy helpers (macOS networksetup)
# ─────────────────────────────────────────────────────────────


def disable_system_proxy() -> bool:
    """Disable the macOS system HTTPS proxy on Wi-Fi.

    Runs `networksetup -setsecurewebproxystate Wi-Fi off`. Returns True
    on apparent success, False otherwise. Safe to call even when the
    system proxy is already off.
    """
    try:
        subprocess.run(
            ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"],
            capture_output=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


def is_system_proxy_enabled_for_port(port: int | None = None) -> bool:
    port = port or get_proxy_port()
    try:
        result = subprocess.run(
            ["networksetup", "-getsecurewebproxy", "Wi-Fi"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "Enabled: Yes" in result.stdout and str(port) in result.stdout
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# Crash telemetry (DB logging)
# ─────────────────────────────────────────────────────────────


def log_crash_event(reason: str, details: str = "") -> None:
    """Record a crash/orphan detection event in the crashes table.

    This is best-effort — if the DB is unavailable we silently skip.
    Called by `_detect_stale_state` whenever it finds wreckage.
    """
    try:
        from claude_monitoring.db import get_thread_db

        conn = get_thread_db()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS crashes ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "timestamp TEXT NOT NULL, "
                "reason TEXT NOT NULL, "
                "details TEXT)"
            )
            conn.execute(
                "INSERT INTO crashes (timestamp, reason, details) VALUES (?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), reason, details),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def recent_crash_count(days: int = 7) -> int:
    try:
        from claude_monitoring.db import get_thread_db

        conn = get_thread_db()
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM crashes WHERE timestamp > datetime('now', ?)",
                (f"-{int(days)} days",),
            ).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()
    except Exception:
        return 0


# ─────────────────────────────────────────────────────────────
# Stale state detection — the most important function in this module
# ─────────────────────────────────────────────────────────────


def detect_stale_state() -> list[str]:
    """Clean up orphan processes and stuck system proxy from previous runs.

    Called at the start of every `ai-monitor --start`. Returns a list of
    human-readable descriptions of what was fixed. Every fix is also
    logged to the crashes table for telemetry.

    The fixes run in this order:
      1. Kill orphan mitmdump if PID file points to a live mitmproxy process
      2. Disable system proxy if the monitor PID file is stale (dead monitor)
      3. Remove stale PID files so the new instance starts clean
      4. Remove stale heartbeat file

    Everything here is defensive. We never raise exceptions to the caller;
    at worst we return an incomplete list of fixes.
    """
    fixes: list[str] = []

    monitor_pid_file = get_monitor_pid_file()
    proxy_pid_file = get_proxy_pid_file()

    monitor_pid = read_pid_file(monitor_pid_file)
    proxy_pid = read_pid_file(proxy_pid_file)

    monitor_alive = monitor_pid is not None and is_pid_alive(monitor_pid)
    proxy_alive = proxy_pid is not None and is_mitmproxy_process(proxy_pid)

    # Case 1: orphan mitmproxy (PID file points to a live mitmdump but
    # monitor is dead). This is last night's bug — kill the orphan.
    if proxy_alive and not monitor_alive:
        try:
            os.kill(proxy_pid, signal.SIGTERM)
            # Give it a second to terminate gracefully
            for _ in range(10):
                if not is_pid_alive(proxy_pid):
                    break
                time.sleep(0.1)
            if is_pid_alive(proxy_pid):
                os.kill(proxy_pid, signal.SIGKILL)
            fixes.append(f"killed orphaned mitmdump (PID {proxy_pid})")
            log_crash_event("orphan_mitmdump", f"pid={proxy_pid}")
        except OSError:
            pass

    # Case 2: stuck system proxy — if we're about to start and the
    # system proxy is ON but there's no live monitor, disable it so the
    # user's network isn't silently routed through a dead proxy.
    if is_system_proxy_enabled_for_port() and not monitor_alive:
        if disable_system_proxy():
            fixes.append("disabled stuck system proxy (no live monitor)")
            log_crash_event("stuck_system_proxy", "")

    # Case 3: stale PID files from a crashed previous run
    if monitor_pid and not monitor_alive:
        remove_pid_file(monitor_pid_file)
        # Don't count this as a "fix" unless it implies a crash — if the
        # PID file exists but the process is dead, there was a crash.
        if monitor_pid > 0:
            log_crash_event("stale_monitor_pid", f"pid={monitor_pid}")
            fixes.append(f"removed stale monitor PID file (was {monitor_pid})")

    if proxy_pid and not proxy_alive:
        remove_pid_file(proxy_pid_file)

    # Case 4: stale heartbeat
    age = heartbeat_age_seconds()
    if age is not None and age > HEARTBEAT_STALE_SECONDS and not monitor_alive:
        try:
            get_heartbeat_file().unlink(missing_ok=True)
        except OSError:
            pass

    return fixes


# ─────────────────────────────────────────────────────────────
# Preferences (persistent user settings)
# ─────────────────────────────────────────────────────────────


def read_preferences() -> dict:
    path = get_preferences_file()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def write_preferences(prefs: dict) -> None:
    path = get_preferences_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prefs, indent=2))
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────
# ProxyManager — supervises mitmdump as a child subprocess
# ─────────────────────────────────────────────────────────────


class ProxyManager:
    """Owns the mitmdump subprocess lifecycle.

    Responsibilities:
      - Start mitmdump via `python -m claude_monitoring.watch --start`
      - Write its PID to the proxy PID file
      - Health-check via Popen.poll() + PID check
      - Stop gracefully on SIGTERM, force-kill after timeout
      - Disable system proxy when mitmdump dies (optional)
      - Restart with exponential backoff up to a max count

    The instance is used from the monitor process. The watchdog thread
    calls is_alive() periodically. If mitmdump died, the watchdog calls
    restart() which handles backoff and gives up after MAX_RESTARTS.
    """

    MAX_RESTARTS = 3
    RESTART_BACKOFF_SECONDS = (1, 5, 30)

    def __init__(self, log_path: Path | None = None):
        self._proc: subprocess.Popen | None = None
        self._restart_count = 0
        self._log_path = log_path
        self._stopped = False  # set True by explicit stop()

    def start(self) -> bool:
        """Spawn mitmdump. Returns True on apparent success.

        If mitmdump is already running (detected via PID file), reuses
        that instance rather than spawning a duplicate.
        """
        # If there's already a live mitmdump for us, adopt it instead of
        # spawning a duplicate. This makes --start idempotent after a
        # partial crash where the subprocess outlived the parent.
        existing = read_pid_file(get_proxy_pid_file())
        if existing and is_mitmproxy_process(existing):
            self._proc = None  # We don't own it directly but we track via PID
            return True

        cmd = [sys.executable, "-m", "claude_monitoring.watch", "--start"]
        stdout = stderr = subprocess.DEVNULL
        if self._log_path:
            log_fh = open(self._log_path, "ab")
            stdout = stderr = log_fh  # type: ignore[assignment]

        try:
            self._proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,  # new process group
            )
            write_pid_file(get_proxy_pid_file(), self._proc.pid)
            self._stopped = False
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_alive(self) -> bool:
        """Return True if mitmdump is running (via Popen.poll() or PID file)."""
        if self._stopped:
            return False
        if self._proc is not None:
            return self._proc.poll() is None
        # Adopted-PID case
        pid = read_pid_file(get_proxy_pid_file())
        return pid is not None and is_mitmproxy_process(pid)

    def pid(self) -> int | None:
        if self._proc is not None:
            return self._proc.pid
        return read_pid_file(get_proxy_pid_file())

    def stop(self, disable_proxy: bool = True, timeout: float = 5.0) -> None:
        """Stop mitmdump and optionally disable the system proxy.

        Graceful SIGTERM first, SIGKILL after ``timeout`` seconds.
        Always removes the PID file. Safe to call multiple times.
        """
        self._stopped = True
        pid = self.pid()
        if pid is not None and is_pid_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
                deadline = time.time() + timeout
                while time.time() < deadline and is_pid_alive(pid):
                    time.sleep(0.1)
                if is_pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        if self._proc is not None:
            try:
                self._proc.wait(timeout=1)
            except (subprocess.TimeoutExpired, Exception):
                pass
            self._proc = None

        remove_pid_file(get_proxy_pid_file())

        if disable_proxy:
            disable_system_proxy()

    def restart(self) -> bool:
        """Attempt to restart after a crash. Uses exponential backoff.

        Returns True on success, False if we've hit MAX_RESTARTS.
        """
        if self._restart_count >= self.MAX_RESTARTS:
            return False
        backoff = self.RESTART_BACKOFF_SECONDS[min(self._restart_count, len(self.RESTART_BACKOFF_SECONDS) - 1)]
        time.sleep(backoff)
        self._restart_count += 1
        return self.start()

    def reset_restart_count(self) -> None:
        """Call periodically from a healthy state to allow future recovery."""
        self._restart_count = 0
