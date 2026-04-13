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
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

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


def install_service(with_system_proxy: bool = False) -> tuple[bool, str]:
    """Write the LaunchAgent plist and load it via launchctl.

    Returns (success, message). If with_system_proxy is True, stores a
    preference so the service's --start path enables the system proxy
    on startup.
    """
    import sys as _sys

    plist_path = get_plist_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_content = generate_plist(python_path=_sys.executable)
    plist_path.write_text(plist_content)

    # Persist the user's preference about system proxy auto-enable
    prefs = read_preferences()
    prefs["auto_enable_system_proxy"] = bool(with_system_proxy)
    write_preferences(prefs)

    # Unload first in case an older version is already loaded, then load
    try:
        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass
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
    return True, f"Service installed at {plist_path}"


def uninstall_service() -> tuple[bool, str]:
    """Unload the LaunchAgent and remove its plist.

    Also disables the system proxy (since the service owned it).
    """
    plist_path = get_plist_path()
    if not plist_path.exists():
        disable_system_proxy()
        return True, "Service was not installed"
    try:
        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass
    try:
        plist_path.unlink()
    except OSError:
        pass
    disable_system_proxy()
    return True, "Service uninstalled"


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
