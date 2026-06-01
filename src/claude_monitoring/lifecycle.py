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
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TypeVar

from claude_monitoring.config import get_output_dir, get_proxy_port

# ─────────────────────────────────────────────────────────────
# Logging — rotating file logger (Phase 2)
# ─────────────────────────────────────────────────────────────

LOG_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
LOG_BACKUP_COUNT = 5
_LOGGER_CACHE: logging.Logger | None = None


def get_log_dir() -> Path:
    return get_output_dir() / "logs"


def get_log_path() -> Path:
    return get_log_dir() / "monitor.log"


def get_logger() -> logging.Logger:
    """Return a singleton logger that writes to ~/claude_watch_output/logs/monitor.log
    with rotation (50MB × 5 = 250MB max). Safe to call multiple times."""
    global _LOGGER_CACHE
    if _LOGGER_CACHE is not None:
        return _LOGGER_CACHE
    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("ai-runtime-monitor")
    logger.setLevel(logging.INFO)
    # Don't add duplicate handlers if get_logger() is called twice
    if not logger.handlers:
        handler = RotatingFileHandler(
            str(get_log_path()),
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    _LOGGER_CACHE = logger
    return logger


class _StreamToLogger:
    """File-like wrapper that redirects writes to a logger.

    Used in --daemon mode so existing print() calls end up in the log file
    without rewriting every call site.
    """

    def __init__(self, logger: logging.Logger, level: int = logging.INFO):
        self._logger = logger
        self._level = level
        self._buffer = ""

    def write(self, data: str) -> int:
        if not isinstance(data, str):
            data = str(data)
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line.strip():
                self._logger.log(self._level, line.rstrip())
        return len(data)

    def flush(self) -> None:
        if self._buffer.strip():
            self._logger.log(self._level, self._buffer.rstrip())
            self._buffer = ""


def redirect_stdio_to_log() -> None:
    """Redirect sys.stdout and sys.stderr to the rotating log file.

    Call this at the start of main() when --daemon is set. All existing
    print() and traceback output will end up in the log.
    """
    logger = get_logger()
    sys.stdout = _StreamToLogger(logger, logging.INFO)  # type: ignore[assignment]
    sys.stderr = _StreamToLogger(logger, logging.ERROR)  # type: ignore[assignment]


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


def find_orphan_mitmproxy_on_port(port: int, *, exclude_pid: int | None = None) -> list[int]:
    """Return PIDs of mitmproxy-like processes LISTENing on ``port``.

    Excludes ``exclude_pid`` (our own mitmdump) so the watchdog doesn't
    kill its own child. Used to clean up zombies from previous runs
    that outlived their parent monitor and are still holding the proxy
    port — the failure mode that caused the 30-second watchdog flap
    (EADDRINUSE every restart attempt).

    Fail-closed: returns empty list on any error.
    """
    try:
        result = subprocess.run(
            ["lsof", "-n", "-i", f":{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return []
    pids: list[int] = []
    for line in result.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        if exclude_pid is not None and pid == exclude_pid:
            continue
        if is_mitmproxy_process(pid):
            pids.append(pid)
    return pids


def kill_orphan_mitmproxy(port: int, *, exclude_pid: int | None = None, timeout: float = 3.0) -> list[int]:
    """SIGTERM (then SIGKILL) any orphan mitmproxy bound to ``port``.

    Returns the list of PIDs that were killed — useful for logging
    and tests. Waits up to ``timeout`` seconds for graceful shutdown
    before escalating to SIGKILL.
    """
    victims = find_orphan_mitmproxy_on_port(port, exclude_pid=exclude_pid)
    for pid in victims:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue
    if not victims:
        return victims
    deadline = time.time() + timeout
    while time.time() < deadline and any(is_pid_alive(p) for p in victims):
        time.sleep(0.1)
    for pid in victims:
        if is_pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    return victims


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


def cleanup_for_shutdown(pid_file: Path) -> None:
    """Atomically remove the PID file and disable the system proxy.

    Run as the FIRST action in every shutdown path (signal handler and
    atexit). Even if a slower cleanup step is interrupted by SIGKILL or
    launchd's KillTimeout, the user is never left with a stuck system
    proxy or a stale PID file — the two failure modes most frequently
    observed in monitor.log (60+ combined occurrences before this fix).

    Both steps are independent and idempotent: a failure in the PID
    removal must not prevent the proxy disable. Errors are suppressed
    because the caller is on its way out anyway.
    """
    with suppress(Exception):
        remove_pid_file(pid_file)
    with suppress(Exception):
        disable_system_proxy()


_T = TypeVar("_T")

# Backoff schedule for dashboard bind retries (seconds). Five attempts
# total = ~7.5s of retry coverage, calibrated against launchd's
# ThrottleInterval=10s and the typical 1–3s window for a SIGKILL'd
# Python process to release its socket. See
# docs/design/lifecycle-reliability.md.
BIND_RETRY_BACKOFF_SECONDS: tuple[float, ...] = (0.5, 1.0, 2.0, 4.0)


def _identify_port_holder(port: int, address: str) -> str:
    """Best-effort lsof query for who currently LISTENs on ``address:port``.

    Used purely for diagnostic logging during bind retries — never
    load-bearing. Returns ``"unknown"`` on any failure so the log line
    stays compact and readable.

    An empty ``address`` falls back to ``127.0.0.1`` so the lsof filter
    does not collapse to ``@:port`` (which matches every interface and
    would surface unrelated processes in the log).
    """
    if not address:
        address = "127.0.0.1"
    try:
        result = subprocess.run(
            ["lsof", "-n", "-i", f"@{address}:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    for line in result.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 2:
            return f"{parts[0]}({parts[1]})"
    return "unknown"


def bind_with_retry(
    server_factory: Callable[[], _T],
    *,
    port: int,
    address: str = "127.0.0.1",
    max_attempts: int = 5,
    logger: logging.Logger | None = None,
) -> _T:
    """Invoke ``server_factory()`` and retry on EADDRINUSE with bounded backoff.

    Without this, a fast restart loop (launchd KeepAlive after a crash)
    races the previous instance's still-LISTEN-ing dashboard socket and
    fails immediately. ``allow_reuse_address`` (SO_REUSEADDR) covers
    TIME_WAIT but not active LISTEN — so a retry loop is the right tool.

    Non-EADDRINUSE OSErrors are re-raised immediately (permission denied
    etc. won't fix themselves with backoff). On the final attempt the
    original OSError is propagated with full traceback.

    When ``max_attempts`` exceeds the length of ``BIND_RETRY_BACKOFF_SECONDS``,
    additional attempts clamp to the final entry (currently 4s) — calls
    after the schedule never sleep longer than the last documented value.
    """
    log = logger or get_logger()
    last_exc: OSError | None = None
    for attempt in range(max_attempts):
        try:
            return server_factory()
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            last_exc = exc
            if attempt == max_attempts - 1:
                break
            backoff = BIND_RETRY_BACKOFF_SECONDS[min(attempt, len(BIND_RETRY_BACKOFF_SECONDS) - 1)]
            holder = _identify_port_holder(port, address)
            log.warning(
                "dashboard bind EADDRINUSE port=%d holder=%s attempt=%d/%d backoff=%.1fs",
                port,
                holder,
                attempt + 1,
                max_attempts,
                backoff,
            )
            time.sleep(backoff)
    # Loop only exits via `break` after a final EADDRINUSE, which always
    # assigns last_exc. Use an explicit guard rather than `assert` so the
    # invariant survives `python -O` (assert statements are stripped).
    if last_exc is None:
        raise RuntimeError("bind_with_retry exhausted attempts without recording an error")
    raise last_exc


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
    # Phase 2: also emit to the rotating log file so crashes are visible
    # in `ai-monitor --logs` even if the DB is unreachable.
    try:
        get_logger().error("crash: %s %s", reason, details)
    except Exception:
        pass
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
        # Default log path: ~/claude_watch_output/logs/mitmproxy.log
        # Capturing mitmdump's stderr is essential for debugging crash loops
        # like the one we hit under launchd (where mitmdump can fail to find
        # its binary, confdir, or port and die silently).
        if log_path is None:
            try:
                log_dir = get_output_dir() / "logs"
                log_dir.mkdir(parents=True, exist_ok=True)
                log_path = log_dir / "mitmproxy.log"
            except Exception:
                pass
        self._log_path = log_path
        self._stopped = False  # set True by explicit stop()

    def start(self) -> bool:
        """Spawn mitmdump. Returns True on apparent success.

        If mitmdump is already running (detected via PID file), reuses
        that instance rather than spawning a duplicate. Before spawning
        a new one, kills any orphan mitmproxy holding the proxy port —
        PID file tracking alone is insufficient because zombies from
        previous monitor crashes may hold the port without a matching
        PID file entry. This is the root cause of the 30-second watchdog
        flap loop.
        """
        # If there's already a live mitmdump for us, adopt it instead of
        # spawning a duplicate. This makes --start idempotent after a
        # partial crash where the subprocess outlived the parent.
        existing = read_pid_file(get_proxy_pid_file())
        if existing and is_mitmproxy_process(existing):
            self._proc = None  # We don't own it directly but we track via PID
            return True

        # Orphan cleanup: scan for any mitmproxy bound to our port that
        # we don't own. Must run BEFORE the spawn attempt because the
        # new mitmdump will fail with EADDRINUSE otherwise.
        try:
            proxy_port = get_proxy_port()
            kill_orphan_mitmproxy(proxy_port, exclude_pid=None)
        except Exception:
            pass

        cmd = [sys.executable, "-m", "claude_monitoring.watch", "--start"]
        stdout: int | object = subprocess.DEVNULL
        stderr: int | object = subprocess.DEVNULL
        if self._log_path is not None:
            try:
                log_fh = open(self._log_path, "ab")
                stdout = log_fh
                stderr = log_fh
            except OSError:
                pass

        # Build a clean env that includes the venv bin dir. Under launchd,
        # PATH may not include the venv, which causes `os.execvp("mitmdump")`
        # inside watch.py to fail with FileNotFoundError — exactly the silent
        # death we saw in the restart loop.
        env = os.environ.copy()
        venv_bin = str(Path(sys.executable).parent)
        if venv_bin not in env.get("PATH", ""):
            env["PATH"] = venv_bin + ":" + env.get("PATH", "")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,  # new process group
                env=env,
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


# ─────────────────────────────────────────────────────────────
# LaunchAgent service management (Phase 3)
# ─────────────────────────────────────────────────────────────

LAUNCH_AGENT_LABEL = "com.gocloudforge.ai-runtime-monitor"


def get_plist_path() -> Path:
    """The LaunchAgent plist path. Lives in ~/Library/LaunchAgents/ which
    is where per-user LaunchAgents are loaded from at login."""
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"


def generate_plist(
    python_path: str,
    with_proxy: bool = True,
) -> str:
    """Build the LaunchAgent plist XML.

    KeepAlive + SuccessfulExit=false means launchd restarts us on crash
    but respects a clean --stop. ThrottleInterval=10 prevents crash loops
    from eating CPU. RunAtLoad=true starts on login.
    """
    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    program_args = [python_path, "-m", "claude_monitoring.monitor", "--start"]
    if with_proxy:
        program_args.append("--with-proxy")
    program_args.append("--daemon")

    args_xml = "\n        ".join(f"<string>{a}</string>" for a in program_args)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        {args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{log_dir}/service-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/service-stderr.log</string>
    <key>WorkingDirectory</key>
    <string>{Path.home()}</string>
</dict>
</plist>
"""


def _wait_for_pid_to_exit(pid: int | None, timeout: float = 10.0) -> bool:
    """Block until the PID is no longer alive, or ``timeout`` seconds pass.

    Returns True if the pid exited cleanly, False on timeout. Safe to call
    with ``pid=None`` (returns True immediately).
    """
    if not pid:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


def _wait_for_monitor_http(port: int | None = None, timeout: float = 15.0) -> bool:
    """Poll the monitor's HTTP endpoint until it returns 200, or timeout.

    Uses ``http.client`` directly to bypass the macOS system proxy, matching
    the _is_monitor_running() probe in status.py. Returns True on success.
    """
    import http.client

    port = port or get_proxy_port() + 1  # dashboard port is proxy_port + 1 by convention
    # Actually dashboard port comes from config
    from claude_monitoring.config import get_dashboard_port as _gdp

    port = _gdp()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def install_service(with_system_proxy: bool = False, wait_for_http: bool = True) -> tuple[bool, str]:
    """Write the LaunchAgent plist, load it, and wait for the monitor to be ready.

    Idempotent: if the service is already installed and running, this cleanly
    stops the old instance, writes the new plist, and launches a fresh process.
    Waits up to 15s for the monitor's HTTP endpoint to return 200 before
    declaring success, so callers can immediately hit the dashboard.

    If ``with_system_proxy`` is True, stores a preference so the service's
    --start path enables the system proxy on startup.
    """
    import sys as _sys

    plist_path = get_plist_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)

    # If a previous version is loaded, kill it cleanly first so the new
    # process starts with no port conflicts and no stale PID files.
    was_running = False
    try:
        result = subprocess.run(
            ["launchctl", "list", LAUNCH_AGENT_LABEL],
            capture_output=True,
            text=True,
            timeout=5,
        )
        was_running = result.returncode == 0
    except Exception:
        pass

    if was_running and plist_path.exists():
        # Unload (sends SIGTERM, waits for exit)
        try:
            subprocess.run(
                ["launchctl", "unload", str(plist_path)],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass
        # Wait for the old monitor process to fully exit so we don't race
        # on port 9081/9080 or the PID file.
        old_mpid = read_pid_file(get_monitor_pid_file())
        _wait_for_pid_to_exit(old_mpid, timeout=10)
        # Also nuke any orphan mitmdump that somehow survived
        old_ppid = read_pid_file(get_proxy_pid_file())
        if old_ppid and is_pid_alive(old_ppid):
            try:
                os.kill(old_ppid, signal.SIGTERM)
            except OSError:
                pass
            _wait_for_pid_to_exit(old_ppid, timeout=5)
        # Remove stale PID files so the new instance starts fresh
        remove_pid_file(get_monitor_pid_file())
        remove_pid_file(get_proxy_pid_file())

    # Write the plist (after cleanup so the new instance sees fresh state)
    plist_content = generate_plist(python_path=_sys.executable)
    plist_path.write_text(plist_content)

    # Persist the user's preference about system proxy auto-enable
    prefs = read_preferences()
    prefs["auto_enable_system_proxy"] = bool(with_system_proxy)
    write_preferences(prefs)

    # Load the new plist — launchctl spawns the process (RunAtLoad=true)
    try:
        result = subprocess.run(
            ["launchctl", "load", str(plist_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, f"launchctl load failed: {result.stderr.strip()}"
    except Exception as exc:
        return False, f"launchctl load error: {exc}"

    # Wait for the monitor to actually serve HTTP — otherwise the user
    # sees "installed" but then --status says "Monitor: Stopped" while
    # the process is still starting up.
    if wait_for_http:
        ready = _wait_for_monitor_http(timeout=15)
        if not ready:
            return True, (
                f"Service installed at {plist_path}, but monitor HTTP "
                "didn't respond within 15s. Check `ai-monitor --logs`."
            )

    return True, f"Service installed at {plist_path}"


def uninstall_service() -> tuple[bool, str]:
    """Unload the LaunchAgent, wait for the process to exit, remove the plist.

    Also disables the system proxy (since the service owned it) and cleans
    up any stale PID files. Idempotent — safe to call multiple times.
    """
    plist_path = get_plist_path()
    if not plist_path.exists():
        disable_system_proxy()
        # Belt-and-suspenders: kill any orphan processes from a prior install
        for pid_file in (get_monitor_pid_file(), get_proxy_pid_file()):
            pid = read_pid_file(pid_file)
            if pid and is_pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            remove_pid_file(pid_file)
        return True, "Service was not installed"

    # Remember the running PIDs before we unload so we can wait for them
    old_mpid = read_pid_file(get_monitor_pid_file())
    old_ppid = read_pid_file(get_proxy_pid_file())

    try:
        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass

    # Wait for both the monitor and mitmproxy to actually exit
    _wait_for_pid_to_exit(old_mpid, timeout=10)
    _wait_for_pid_to_exit(old_ppid, timeout=5)
    if old_ppid and is_pid_alive(old_ppid):
        try:
            os.kill(old_ppid, signal.SIGKILL)
        except OSError:
            pass

    try:
        plist_path.unlink()
    except OSError:
        pass
    remove_pid_file(get_monitor_pid_file())
    remove_pid_file(get_proxy_pid_file())
    disable_system_proxy()
    return True, "Service uninstalled"


def restart_service() -> tuple[bool, str]:
    """Restart the service via ``launchctl kickstart -k``.

    kickstart -k sends SIGTERM, waits for the process to exit, then relaunches
    it — the canonical way to restart a LaunchAgent without touching the plist.
    Falls back to an uninstall+install cycle if the service isn't loaded.
    Waits for the monitor HTTP to respond before returning.
    """
    plist_path = get_plist_path()
    if not plist_path.exists():
        return False, "Service is not installed. Run: ai-monitor --install-service"

    # kickstart only kills the direct LaunchAgent child (the monitor).
    # Any mitmdump grandchildren that outlived the previous monitor
    # will keep holding port 9080, making the restarted monitor spawn
    # new mitmdumps that immediately die with EADDRINUSE. Nuke them
    # first so the new monitor gets a clean port.
    try:
        proxy_port = get_proxy_port()
        kill_orphan_mitmproxy(proxy_port, exclude_pid=None)
    except Exception:
        pass

    # kickstart needs the domain/target format: gui/<uid>/<label>
    try:
        uid = os.getuid()
        target = f"gui/{uid}/{LAUNCH_AGENT_LABEL}"
        result = subprocess.run(
            ["launchctl", "kickstart", "-k", target],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            # Fallback: unload + load cycle
            subprocess.run(
                ["launchctl", "unload", str(plist_path)],
                capture_output=True,
                timeout=10,
            )
            time.sleep(0.5)
            result = subprocess.run(
                ["launchctl", "load", str(plist_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False, f"launchctl reload failed: {result.stderr.strip()}"
    except Exception as exc:
        return False, f"launchctl kickstart error: {exc}"

    # Wait for the new instance's HTTP to come up
    ready = _wait_for_monitor_http(timeout=15)
    if not ready:
        return True, "Service restarted, but monitor HTTP didn't respond within 15s. Check `ai-monitor --logs`."
    return True, "Service restarted"


def is_service_installed() -> bool:
    return get_plist_path().exists()


def is_service_loaded() -> bool:
    """True if launchctl lists our label as loaded."""
    try:
        result = subprocess.run(
            ["launchctl", "list", LAUNCH_AGENT_LABEL],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_service_state() -> dict:
    """Return service state dict: installed, loaded, pid, last_exit_code.

    Reads `launchctl list <label>` plist-style output. Best-effort — any
    error returns a safe default.
    """
    state: dict = {
        "installed": is_service_installed(),
        "loaded": False,
        "pid": None,
        "last_exit_code": None,
    }
    if not state["installed"]:
        return state
    try:
        result = subprocess.run(
            ["launchctl", "list", LAUNCH_AGENT_LABEL],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            state["loaded"] = True
            # Parse the awkward launchctl list output
            for line in result.stdout.splitlines():
                line = line.strip().rstrip(";")
                if '"PID"' in line and "=" in line:
                    try:
                        state["pid"] = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        pass
                elif '"LastExitStatus"' in line and "=" in line:
                    try:
                        state["last_exit_code"] = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        pass
    except Exception:
        pass
    return state


# ─────────────────────────────────────────────────────────────
# User notifications (macOS) — audit finding C4
# ─────────────────────────────────────────────────────────────


def _escape_applescript_string(s: str) -> str:
    """Escape `s` for embedding inside an AppleScript `"..."` string literal.

    This is NOT bash escaping. The argv-list passes the script as a single
    argv element to `osascript -e`, so OS shell metacharacters are inert.
    What matters is closing the AppleScript string literal — only `"` and
    `\\` can break out of it.
    """
    return s.replace("\\", "\\\\").replace('"', '\\"')


def notify(title: str, body: str) -> None:
    """Display a native macOS notification via `osascript`.

    Uses argv-list invocation (never `shell=True`) and escapes AppleScript
    string-literal metacharacters in both `title` and `body`. Failures are
    swallowed: a missing osascript (non-darwin CI runner) or a permission
    denial must not crash the caller.
    """
    applescript = (
        f'display notification "{_escape_applescript_string(body)}" with title "{_escape_applescript_string(title)}"'
    )
    try:
        subprocess.run(
            ["osascript", "-e", applescript],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass
