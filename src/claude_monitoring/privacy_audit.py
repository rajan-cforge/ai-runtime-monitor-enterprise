"""P5.1a privacy verification audit modes — ``--network-audit`` + ``--read-audit``.

Spec §10.7 + directive §7.5.5 require operator-runnable verification of
Vigil's privacy claims. This module ships two of the three audit modes;
the third (``--db-audit``) is P5.1b — security-C4, separate human-
reviewed PR (Rajan ratified 2026-06-14).

Design (judge p5.1.a2 APPROVE-WITH-FIX 2026-06-14):

``--network-audit`` — process-tree-wide observation, NOT main-process only.

  Main-process layer: ``sys.addaudithook("socket.connect")`` catches every
  socket.connect from the main Vigil interpreter — sits under urllib,
  httpx, requests, and raw socket calls. Faithful to directive §7.5.5
  line 1041 "Audit log is source of truth."

  Process-tree layer: periodic ``lsof -nP -i`` snapshots filtered to Vigil
  pids during the scan. Required because ``mitmdump`` runs as a separate
  subprocess (``ProxyManager``) and Vigil discovery scans spawn outbound
  subprocesses (``npm list -g``, ``brew list``). An in-process hook
  cannot see either; without process-tree coverage the audit emits a
  false all-clear on exactly the connections that matter. The judge
  caught this on p5.1.a1 → a2 — addressed here.

  End-of-scan ``lsof -nP -p $PID`` snapshot remains as defense-in-depth.

``--read-audit`` — ``sys.addaudithook("open")`` filtered to Vigil-owned
paths + scan-walked paths. Excludes stdlib + site-packages per directive
§7.5.5 "NOT INCLUDED: stdlib internal reads, third-party library
internal reads." Target: 50-100 entries per discovery scan.

Phase C empirical-ratchet conditions (Rajan condition 1):
  - Real OSV.dev query (main-process path) captured.
  - Real mitmproxy-initiated connection captured (subprocess path).
  - At least one tool-subprocess outbound (e.g. npm) captured.
  - --read-audit count falls in 50-100 range per spec §7.5.5.
"""

from __future__ import annotations

import json
import logging
import os
import re as _re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("ai-runtime-monitor.privacy_audit")


# Polling cadence for the process-tree lsof watcher during a network audit.
# Short enough to catch short-lived subprocess connections; long enough not
# to spawn 100s of lsof processes for a typical 60s scan.
_LSOF_POLL_INTERVAL_SEC = 2.0


@dataclass(frozen=True)
class _NetworkEvent:
    """Single network event captured by either the in-process hook or
    the OS-level lsof watcher."""

    source: str  # "hook" | "lsof"
    pid: int
    host: str
    port: int | None
    family: str  # "inet" | "inet6" | "unix" | "other"
    timestamp: float


@dataclass(frozen=True)
class _ReadEvent:
    """Single file-open event captured by the in-process audit hook."""

    pid: int
    path: str
    timestamp: float


@dataclass
class _AuditState:
    """Per-mode mutable state. Lives for the duration of one scan."""

    network_events: list[_NetworkEvent] = field(default_factory=list)
    read_events: list[_ReadEvent] = field(default_factory=list)
    tracked_pids: set[int] = field(default_factory=set)
    stop_event: threading.Event = field(default_factory=threading.Event)


# Module-level state so the audit hook (a free function registered with
# `sys.addaudithook`) can append events. Production usage runs one
# audit mode per process invocation, so a module-level instance is fine.
_state: _AuditState | None = None


# ---------------------------------------------------------------------------
# Path filter for --read-audit
# ---------------------------------------------------------------------------


def _vigil_source_root() -> Path:
    """Return the parent dir of this module — the root of Vigil source."""
    return Path(__file__).resolve().parent


def _looks_like_vigil_owned_path(path_str: str) -> bool:
    """Whether ``path_str`` is a read Vigil's code explicitly chose to make.

    Per directive §7.5.5 "Tracks reads where Vigil-controlled code chooses
    the path." INCLUDED: paths under the Vigil source tree, the
    ``claude_watch_output`` data dir, user-config files, and the scan-
    walked external paths (extension dirs, package manifests). EXCLUDED:
    stdlib paths, site-packages, system framework reads.

    The filter errs on the side of inclusion at the Vigil-source boundary
    (we want to see what Vigil read) and errs on the side of exclusion
    at the stdlib boundary (10,000+ noisy entries otherwise).
    """
    try:
        p = Path(path_str).resolve()
    except (OSError, RuntimeError):
        return False
    s = str(p)
    # Hard excludes — these dominate the noise volume.
    excludes = (
        "/site-packages/",
        "/dist-packages/",
        ".pyenv/",
        "/python3.",  # framework reads
        "/Frameworks/",  # macOS framework reads
        "/Library/Caches/",
        "/.cache/",
    )
    for exc in excludes:
        if exc in s:
            return False
    # Include: Vigil source tree.
    vigil_root = str(_vigil_source_root())
    if s.startswith(vigil_root):
        return True
    # Include: claude_watch_output (the operator's data dir — Vigil's DB lives here).
    if "claude_watch_output" in s:
        return True
    # Include: typical scan-walked locations.
    scan_paths = (
        "/.config/",
        "/.claude/",
        "/.cursor/",
        "/Library/Application Support/",
        "/.vscode/",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "Pipfile.lock",
        "manifest.json",
    )
    return any(sp in s for sp in scan_paths)


# ---------------------------------------------------------------------------
# Audit hooks (registered with sys.addaudithook)
# ---------------------------------------------------------------------------


def _socket_connect_hook(event: str, args: tuple) -> None:
    """Capture every ``socket.connect`` call from the main Vigil interpreter.

    Fires for any socket — urllib/httpx/requests/raw — because all of
    them ultimately call ``socket.connect`` (or the equivalent syscall
    that triggers the audit event). Subprocess connections do NOT fire
    here; the lsof watcher catches those.
    """
    if event != "socket.connect" or _state is None:
        return
    if not args:
        return
    sock, addr = args[0], args[1] if len(args) > 1 else None
    family_str, host, port = _decode_socket_address(sock, addr)
    _state.network_events.append(
        _NetworkEvent(
            source="hook",
            pid=os.getpid(),
            host=host,
            port=port,
            family=family_str,
            timestamp=time.time(),
        )
    )


def _decode_socket_address(sock, addr) -> tuple[str, str, int | None]:
    """Decode an audit-event address tuple to ``(family, host, port)``.

    ``sock`` is the socket object; ``addr`` is the connect target. We
    avoid resolving DNS or doing any I/O — capture the literal address
    Vigil tried to connect to.
    """
    import socket as _socket

    try:
        family = sock.family
    except AttributeError:
        family = None
    if family == _socket.AF_INET and isinstance(addr, tuple) and len(addr) >= 2:
        return ("inet", str(addr[0]), int(addr[1]))
    if family == _socket.AF_INET6 and isinstance(addr, tuple) and len(addr) >= 2:
        return ("inet6", str(addr[0]), int(addr[1]))
    if family == _socket.AF_UNIX and isinstance(addr, (str, bytes)):
        host = addr.decode("utf-8", errors="replace") if isinstance(addr, bytes) else addr
        return ("unix", host, None)
    # Unknown family or weird address — capture what we have rather than drop.
    return ("other", repr(addr), None)


def _open_hook(event: str, args: tuple) -> None:
    """Capture every ``open`` call from the main Vigil interpreter,
    filtered to Vigil-owned + scan-walked paths."""
    if event != "open" or _state is None:
        return
    if not args:
        return
    path = args[0]
    if not isinstance(path, (str, bytes, os.PathLike)):
        return
    path_str = os.fspath(path) if not isinstance(path, str) else path
    if not _looks_like_vigil_owned_path(path_str):
        return
    _state.read_events.append(_ReadEvent(pid=os.getpid(), path=path_str, timestamp=time.time()))


# ---------------------------------------------------------------------------
# Process-tree lsof watcher (the judge a2 fix)
# ---------------------------------------------------------------------------


def _collect_vigil_pids() -> set[int]:
    """Return the set of pids belonging to Vigil's process tree.

    Includes:
      - The main daemon process (self).
      - mitmdump's pid via the ProxyManager singleton when running.
      - Any descendants reachable via ``ps``.

    Falls back gracefully if any of these aren't available (e.g. in a
    unit test where neither mitmdump nor a daemon is running). The
    audit log records what it can see.
    """
    pids: set[int] = {os.getpid()}
    # mitmdump pid — read from ProxyManager when available.
    try:
        from claude_monitoring import monitor as _monitor

        pm = getattr(_monitor, "_PROXY_MANAGER", None)
        mitm_pid = getattr(pm, "mitmdump_pid", None) if pm is not None else None
        if isinstance(mitm_pid, int) and mitm_pid > 0:
            pids.add(mitm_pid)
    except Exception:
        pass
    # Descendants via `ps` — best-effort, macOS + Linux.
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=,ppid="],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        parent_map: dict[int, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                child, parent = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            parent_map[child] = parent
        # Walk children of any tracked pid.
        frontier = set(pids)
        while frontier:
            next_frontier: set[int] = set()
            for pid, parent in parent_map.items():
                if parent in frontier and pid not in pids:
                    pids.add(pid)
                    next_frontier.add(pid)
            frontier = next_frontier
    except (OSError, subprocess.SubprocessError):
        pass
    return pids


def _lsof_snapshot(pids: set[int]) -> list[_NetworkEvent]:
    """Run ``lsof -nP -i`` once and return events for processes in ``pids``.

    Output format on macOS + Linux:
      ``COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME``
    where NAME is e.g. ``host:443 (ESTABLISHED)`` for established
    connections. We capture (pid, host, port, family) and filter to the
    tracked pids.
    """
    if not pids:
        return []
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-i"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    events: list[_NetworkEvent] = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        if pid not in pids:
            continue
        type_field = parts[4]  # IPv4 / IPv6
        name_field = parts[8]
        family_str = "inet" if "IPv4" in type_field else "inet6" if "IPv6" in type_field else "other"
        host, port = _parse_lsof_name(name_field)
        events.append(
            _NetworkEvent(
                source="lsof",
                pid=pid,
                host=host,
                port=port,
                family=family_str,
                timestamp=time.time(),
            )
        )
    return events


def _parse_lsof_name(name: str) -> tuple[str, int | None]:
    """Parse the ``NAME`` column of ``lsof -nP -i`` to ``(host, port)``.

    Examples:
      ``"127.0.0.1:8080->127.0.0.1:443 (ESTABLISHED)"``
      → host=``"127.0.0.1:443"``, port=443 (the remote end)
      ``"*:9080 (LISTEN)"``
      → host=``"*:9080"``, port=9080 (listening, no remote)
    """
    name = name.split(" ", 1)[0]  # strip state suffix like "(ESTABLISHED)"
    # Established: split on "->"; remote end is what matters for egress audit.
    if "->" in name:
        remote = name.split("->", 1)[1]
        return _split_host_port(remote)
    return _split_host_port(name)


def _split_host_port(token: str) -> tuple[str, int | None]:
    """Split a ``host:port`` token, supporting IPv6 ``[::1]:443``."""
    if token.startswith("["):
        end = token.find("]")
        if end == -1:
            return (token, None)
        host = token[1:end]
        rest = token[end + 1 :]
        if rest.startswith(":"):
            try:
                return (host, int(rest[1:]))
            except ValueError:
                return (host, None)
        return (host, None)
    if ":" in token:
        host, _, port_str = token.rpartition(":")
        try:
            return (host, int(port_str))
        except ValueError:
            return (host, None)
    return (token, None)


def _process_tree_lsof_watcher(state: _AuditState) -> None:
    """Background thread: poll lsof every ``_LSOF_POLL_INTERVAL_SEC``
    seconds, refresh the tracked-pid set each cycle, append events to
    ``state``. Exits when ``state.stop_event`` is set."""
    while not state.stop_event.is_set():
        state.tracked_pids = _collect_vigil_pids()
        events = _lsof_snapshot(state.tracked_pids)
        # De-duplicate against what we already have — same (pid, host,
        # port, family) from the same cycle is one logical event.
        seen = {(e.pid, e.host, e.port, e.family) for e in state.network_events if e.source == "lsof"}
        for e in events:
            key = (e.pid, e.host, e.port, e.family)
            if key not in seen:
                state.network_events.append(e)
                seen.add(key)
        state.stop_event.wait(_LSOF_POLL_INTERVAL_SEC)


# ---------------------------------------------------------------------------
# Public mode entry points
# ---------------------------------------------------------------------------


def network_audit_mode() -> int:
    """Run a discovery scan with full process-tree network observation.

    Returns process exit code (0 on success). Prints a structured audit
    report to stdout.
    """
    global _state
    _state = _AuditState()
    sys.addaudithook(_socket_connect_hook)
    watcher = threading.Thread(
        target=_process_tree_lsof_watcher,
        args=(_state,),
        daemon=True,
        name="PrivacyAuditLsofWatcher",
    )
    watcher.start()
    try:
        from claude_monitoring.discovery_scheduler import run_discover

        rc = run_discover(json_out=False)
    finally:
        _state.stop_event.set()
        watcher.join(timeout=_LSOF_POLL_INTERVAL_SEC * 2)
    print("\n=== Vigil network audit ===")
    print(f"  events captured: {len(_state.network_events)}")
    print(f"  tracked pids:    {sorted(_state.tracked_pids)}")
    print()
    for e in _state.network_events:
        port_str = f":{e.port}" if e.port is not None else ""
        print(f"  [{e.source:4s}] pid={e.pid} {e.family} {e.host}{port_str}")
    print()
    print("  Acceptance check (directive line 1623): no GoCloudForge egress.")
    hits = [e for e in _state.network_events if "gocloudforge" in e.host.lower() or "cforge" in e.host.lower()]
    if hits:
        print(f"  ! FAIL — {len(hits)} GoCloudForge connection(s) observed")
        return 1
    print("  PASS — no GoCloudForge hostnames in audit log.")
    return rc


def read_audit_mode() -> int:
    """Run a discovery scan with verbose filesystem logging.

    Returns process exit code. Prints a structured audit report
    showing every Vigil-owned file read during the scan."""
    global _state
    _state = _AuditState()
    sys.addaudithook(_open_hook)
    try:
        from claude_monitoring.discovery_scheduler import run_discover

        rc = run_discover(json_out=False)
    finally:
        pass
    print("\n=== Vigil read audit ===")
    print(f"  events captured: {len(_state.read_events)}")
    print()
    # Deduplicate identical (path) reads so the operator sees a clean inventory.
    unique_paths: dict[str, int] = {}
    for e in _state.read_events:
        unique_paths[e.path] = unique_paths.get(e.path, 0) + 1
    for path, count in sorted(unique_paths.items()):
        suffix = f"  (read {count}x)" if count > 1 else ""
        print(f"  {path}{suffix}")
    print()
    print(f"  Distinct paths: {len(unique_paths)}")
    return rc


def reset_state_for_testing() -> None:
    """Test hook: reset the module-level audit state. Production never calls this."""
    global _state
    _state = None


def get_state_for_testing() -> _AuditState | None:
    """Test hook: read the current state. Production never calls this."""
    return _state


def install_socket_hook_for_testing() -> _AuditState:
    """Test hook: install only the socket hook (no scan), return state."""
    global _state
    _state = _AuditState()
    sys.addaudithook(_socket_connect_hook)
    return _state


def install_open_hook_for_testing() -> _AuditState:
    """Test hook: install only the open hook (no scan), return state."""
    global _state
    _state = _AuditState()
    sys.addaudithook(_open_hook)
    return _state


def serialize_audit_log_json() -> str:
    """Return the captured audit log as JSON. Used by tests and by the
    ``TestNoGoCloudForgeEgress`` acceptance assertion."""
    if _state is None:
        return json.dumps({"network_events": [], "read_events": []})
    return json.dumps(
        {
            "network_events": [
                {
                    "source": e.source,
                    "pid": e.pid,
                    "host": e.host,
                    "port": e.port,
                    "family": e.family,
                }
                for e in _state.network_events
            ],
            "read_events": [{"pid": e.pid, "path": e.path} for e in _state.read_events],
        }
    )


# ---------------------------------------------------------------------------
# P5.1b: --db-audit + reusable redact_value_for_display() primitive
# ---------------------------------------------------------------------------
#
# Phase A ratified (judge p5.1b.a2 APPROVE 2026-06-14) on top of Rajan
# 2026-06-14 reserved-decision ratification:
#
#   - Redact-by-default with explicit allowlist (fail-closed). Column-name
#     denylists were rejected at p5.1.a1 (sensitivity lives in values, not
#     names).
#   - Capture tables: schema + row count + NO sample rows. There is no
#     safe "masked sample" shortcut for tables that store raw matched
#     values (sensitive_patterns) or verbatim captured content.
#   - Attack-surface + operational tables: enumerate every column in
#     SAFE_COLUMNS_BY_TABLE with one of:
#       "raw" — structurally-safe enum/timestamp/integer/boolean
#       "masked" — free-text or _json that flows through the masker
#                  pipeline UNCONDITIONALLY (judge p5.1b.a1 Finding A:
#                  masking must not be gated on scan_sensitive firing,
#                  because SENSITIVE_PATTERNS carries no path/username
#                  shape — /Users/<username>/ would render raw)
#       "opaque_id" — hash digest / opaque identifier, displayable as-is
#   - Unknown (table, column) → "[REDACTED]" fail-closed default. The
#     check_db_audit_classification.py CI gate ensures the literal stays
#     complete; the runtime fail-closed is the second layer.
#   - redact_value_for_display() is the SHARED primitive; P5.2 exports
#     (JSON/CSV/MD) must consume it rather than re-derive a second
#     leaky path (Rajan condition 2).


# The masker pipeline for (b) "masked" columns.
#
# Step 1: home-dir normalization. SENSITIVE_PATTERNS in constants.py:218
# has NO path/username shape — only credential/token/PII patterns — so we
# strip user paths here, BEFORE the credential masker runs. This is the
# Finding-A fix verbatim.
#
# Step 2: mask_value() from security.py — credential-shape masking.
# Step 3: scan_sensitive() as the ESCALATION trigger, never the gate.
#   If anything is still detected after steps 1+2, the cell becomes
#   "[REDACTED]" rather than leak a partially-masked value.


_HOME_DIR_PATTERNS = [
    # Order matters — most-specific first.
    (_re.compile(r"/Users/([^/\s\"]+)"), r"/Users/<USER>"),
    (_re.compile(r"/home/([^/\s\"]+)"), r"/home/<USER>"),
    (_re.compile(r"/root\b"), r"/root"),
    # Windows: backslashes need escaping in the regex AND the substitution.
    (_re.compile(r"C:\\Users\\([^\\\s\"]+)", _re.IGNORECASE), r"C:\\Users\\<USER>"),
]


def _normalize_home_paths(text: str) -> str:
    """Replace every `/Users/<name>/...` / `/home/<name>/...` /
    `C:\\Users\\<name>\\...` prefix with `<USER>` so a "masked" column
    cannot leak a real username verbatim.

    Runs BEFORE mask_value() so the username token never reaches the
    credential masker (which would leave it unchanged because no
    credential pattern matches a username).
    """
    if not text:
        return text
    out = text
    for pattern, repl in _HOME_DIR_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _mask_unconditionally(value: object) -> str:
    """Run the full masker pipeline on ``value`` for a (masked) column.

    Pipeline (Finding-A fix from judge p5.1b.a1):
      1. ``str(value)``
      2. ``_normalize_home_paths()`` — strip usernames from any
         `/Users/<name>/` / `/home/<name>/` / `C:\\Users\\<name>` prefix.
      3. ``mask_value()`` — credential-shape masker from security.py.
      4. ``scan_sensitive()`` — escalation check. If any token-shape
         pattern still fires on the masked output, render "[REDACTED]"
         instead of risking a partially-masked leak.

    ``scan_sensitive`` is the ESCALATION trigger, never the GATE on
    whether to mask at all (per memory
    `feedback_masking_must_be_unconditional_not_gated.md`).
    """
    from claude_monitoring.security import mask_value
    from claude_monitoring.utils import scan_sensitive

    raw = "" if value is None else str(value)
    if not raw:
        return ""
    normalized = _normalize_home_paths(raw)
    masked = mask_value(normalized)
    # Escalation check — if anything is STILL token-shaped after masking,
    # don't risk a partial leak; render the whole cell as redacted.
    try:
        hits = scan_sensitive(masked, names_only=True)
    except Exception:
        # Scanner failure is itself untrusted state — fail-closed.
        return "[REDACTED]"
    if hits:
        return "[REDACTED]"
    return masked


# Capture tables: schema + row-count + ZERO samples. The audit prints
# "no samples (capture-table policy)" for each. These are tables where
# sensitive_patterns / verbatim captured content / raw command lines
# live; there is no safe masked-sample shortcut.

CAPTURE_TABLES_NO_SAMPLES: frozenset[str] = frozenset(
    {
        "api_calls",
        "events",
        "browser_sessions",
        "sessions",
        "processes",
        "connections",
        "file_events",
        "agent_dependencies",
        "crashes",  # Finding B from p5.1b.a1: tracebacks can embed paths.
    }
)


# Per-column display policy. "raw" → str(value). "masked" → masker
# pipeline (unconditional + scan_sensitive escalation). "opaque_id" →
# str(value) (digests are non-reversible by display).
#
# Any column NOT listed here renders "[REDACTED]" (fail-closed default).
# The check_db_audit_classification.py CI gate ensures every column in
# every table on main is enumerated here so the fail-closed never has
# to catch a real production column at runtime.

SAFE_COLUMNS_BY_TABLE: dict[str, dict[str, str]] = {
    # Attack-surface tables (per Rajan 2026-06-14 + Phase A classification).
    "assets": {
        "id": "opaque_id",
        "type": "raw",
        "parent_asset_id": "opaque_id",
        "name": "masked",
        "version": "raw",
        "install_path": "masked",
        "source": "raw",
        "first_seen": "raw",
        "last_seen": "raw",
        "last_scanned": "raw",
        "current_state": "masked",
        "ontology_tags": "raw",
        "risk_score": "raw",
        "risk_band": "raw",
        "risk_factors": "masked",
        "is_vigil_component": "raw",
    },
    "asset_history": {
        "asset_id": "opaque_id",
        "scan_timestamp": "raw",
        "state_snapshot": "masked",
        "changes_from_previous": "masked",
        "discovery_run_id": "raw",
    },
    "asset_cves": {
        "asset_id": "opaque_id",
        "cve_id": "raw",
        "severity": "raw",
        "published": "raw",
        "description": "masked",
        "cve_references": "masked",
        "discovered_at": "raw",
    },
    "cve_cache": {
        "package_ecosystem": "raw",
        "package_name": "masked",
        "cve_id": "raw",
        "severity": "raw",
        "affected_versions": "masked",
        "description": "masked",
        "cve_references": "masked",
        "published": "raw",
        "fetched_at": "raw",
    },
    "discovery_runs": {
        "id": "raw",
        "started_at": "raw",
        "completed_at": "raw",
        "trigger": "raw",
        "assets_discovered": "raw",
        "new_assets": "raw",
        "removed_assets": "raw",
        "new_cves": "raw",
        "errors": "masked",
    },
    "permission_grants": {
        "integration": "masked",
        "granted_at": "raw",
        "granted_scope": "masked",
    },
    "schema_meta": {
        "version": "raw",
        "applied_at": "raw",
        "description": "raw",
    },
    # Operational / cache tables — case-by-case per Phase A.
    # P9.3 schema 0.2.2.003: alert_dismissals → alert_triage. Verdict TEXT
    # (operator label, no credential content); reason masked as before;
    # created_at is the audit-trail timestamp.
    "alert_triage": {
        "id": "raw",
        "event_id": "raw",
        "verdict": "raw",
        "reason": "masked",
        "created_at": "raw",
    },
    "extension_heartbeats": {
        "id": "raw",
        "hostname": "masked",
        "last_seen": "raw",
        "user_matches": "raw",
        "assistant_matches": "raw",
        "captures_sent": "raw",
        "selector_failure": "raw",
    },
    "intel_source_status": {
        "name": "raw",
        "last_attempt": "raw",
        "last_success": "raw",
        "last_error": "masked",
        "record_count": "raw",
        "updated_at": "raw",
    },
    "scan_history": {
        "id": "raw",
        "timestamp": "raw",
        "packages_scanned": "raw",
        "vulns_found": "raw",
        "sources": "masked",
    },
    "file_positions": {
        "file_path": "masked",
        "byte_offset": "raw",
        "last_read": "raw",
    },
    "environment_packages": {
        "id": "raw",
        "scan_timestamp": "raw",
        "package_name": "masked",
        "package_version": "raw",
        "manager": "raw",
        "source": "raw",
    },
    "package_maintainer_history": {
        "id": "raw",
        "package_name": "masked",
        "manager": "raw",
        "scan_timestamp": "raw",
        "maintainer_data": "masked",
        "publisher": "masked",
        "version": "raw",
    },
    "package_registry_cache": {
        "id": "raw",
        "package_name": "masked",
        "manager": "raw",
        "fetch_timestamp": "raw",
        "metadata": "masked",
    },
    "package_vulnerabilities": {
        "id": "raw",
        "scan_timestamp": "raw",
        "package_name": "masked",
        "package_version": "raw",
        "ecosystem": "raw",
        "vuln_id": "raw",
        "aliases": "masked",
        "severity": "raw",
        "cvss_score": "raw",
        "fix_version": "raw",
        "description": "masked",
        "source": "raw",
        "published": "raw",
        "modified": "raw",
    },
    "package_watchlist": {
        "id": "raw",
        "package_name": "masked",
        "manager": "raw",
        "watch_reason": "masked",
        "added_timestamp": "raw",
        "priority": "raw",
        "last_checked": "raw",
        "check_interval_hours": "raw",
    },
    "threat_iocs": {
        "id": "raw",
        "ioc_type": "raw",
        "ioc_value": "masked",
        "threat_type": "raw",
        "malware_family": "masked",
        "confidence": "raw",
        "source": "raw",
        "first_seen": "raw",
        "fetch_timestamp": "raw",
    },
}


def redact_value_for_display(table: str, column: str, value: object) -> str:
    """Return the display string for a single column value.

    Capture tables raise ``ValueError`` — caller must consult
    ``CAPTURE_TABLES_NO_SAMPLES`` before invoking; capture-table policy is
    "no samples at all," not "samples masked." That signature is the
    safety guard: it's impossible to call this primitive on a capture
    table by accident and get back a value.

    For non-capture tables:
      - ``raw`` columns → ``str(value)`` (structurally-safe types).
      - ``opaque_id`` columns → ``str(value)`` (digests are non-reversible).
      - ``masked`` columns → masker pipeline (UNCONDITIONAL home-dir
        normalization → ``mask_value`` → ``scan_sensitive`` escalation).
      - Unknown ``(table, column)`` → ``"[REDACTED]"`` (fail-closed).

    P5.2 export paths must call this function rather than re-derive a
    second leaky path (Rajan condition 2, 2026-06-14).
    """
    if table in CAPTURE_TABLES_NO_SAMPLES:
        raise ValueError(
            f"redact_value_for_display called for capture table {table!r}; "
            "caller must check CAPTURE_TABLES_NO_SAMPLES first and print "
            "'no samples (capture-table policy)' instead."
        )
    table_policy = SAFE_COLUMNS_BY_TABLE.get(table)
    if table_policy is None:
        return "[REDACTED]"
    column_policy = table_policy.get(column)
    if column_policy is None:
        return "[REDACTED]"
    if column_policy in ("raw", "opaque_id"):
        return "" if value is None else str(value)
    if column_policy == "masked":
        return _mask_unconditionally(value)
    # Unknown policy literal — fail-closed.
    return "[REDACTED]"


def db_audit_mode() -> int:
    """P5.1b: print the schema + row counts (and per-policy samples) of
    every table in monitor.db.

    Capture tables (``CAPTURE_TABLES_NO_SAMPLES``) print schema + count
    only; the line ``no samples (capture-table policy)`` distinguishes
    "we chose not to show samples" from "table is empty" (CONTRACT §5
    data-truthfulness).

    Other tables print up to 5 sample rows with each cell routed
    through ``redact_value_for_display``.
    """
    import sqlite3

    from claude_monitoring.db import get_db_path

    db_path = get_db_path()
    if not Path(db_path).exists():
        print(f"\n=== Vigil --db-audit ===\n  monitor.db not found at {db_path}")
        return 0
    conn = sqlite3.connect(db_path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        print("\n=== Vigil --db-audit ===")
        print(f"  db_path: {db_path}")
        print(f"  tables:  {len(tables)}")
        print()
        unknown_columns: list[tuple[str, str]] = []
        for table in tables:
            # Identifier guard (Rajan C4 review condition 2026-06-15):
            # `table` comes from sqlite_master, but the repo's no-f-string-
            # SQL rule treats any interpolation as a code smell. Reject
            # anything that isn't a valid Python identifier — captures any
            # future weirdness without weakening the existing `nosec B608`
            # provenance comment below. SQLite identifiers are the same
            # ASCII shape as Python identifiers in this codebase.
            if not table.isidentifier():
                print(f"  ! WARNING: skipping non-identifier table name {table!r}")
                continue
            # bandit B608: `table` comes from sqlite_master (filter above)
            # and is guarded by `isidentifier()`. Never from user input.
            # SAFE_COLUMNS_BY_TABLE + CAPTURE_TABLES_NO_SAMPLES classify
            # what we encounter; the CI gate keeps them complete.
            cols = conn.execute(f"PRAGMA table_info({table})").fetchall()  # nosec B608
            col_names = [c[1] for c in cols]
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608
            print(f"[{table}]  rows: {count}")
            print(f"  schema: {', '.join(f'{c[1]} ({c[2]})' for c in cols)}")
            # Detect unclassified columns from the SCHEMA, not from row cells
            # — Rajan optional cosmetic 2026-06-15. The previous version
            # missed unclassified columns on empty tables; this version
            # catches them regardless of row count.
            if table not in CAPTURE_TABLES_NO_SAMPLES:
                table_policy = SAFE_COLUMNS_BY_TABLE.get(table, {})
                for col_name in col_names:
                    if col_name not in table_policy:
                        unknown_columns.append((table, col_name))
            if table in CAPTURE_TABLES_NO_SAMPLES:
                print("  samples: no samples (capture-table policy)")
                print()
                continue
            # Sample up to 5 rows.
            sample_rows = conn.execute(f"SELECT * FROM {table} LIMIT 5").fetchall()  # nosec B608
            if not sample_rows:
                print("  samples: (none)")
                print()
                continue
            for row in sample_rows:
                cells: list[str] = []
                for col_name, raw_value in zip(col_names, row, strict=False):
                    cells.append(f"{col_name}={redact_value_for_display(table, col_name, raw_value)}")
                print(f"  row: {', '.join(cells)}")
            print()
        if unknown_columns:
            print("  ! WARNING: unclassified columns rendered [REDACTED] by fail-closed default:")
            for table, col_name in sorted(set(unknown_columns)):
                print(f"    - {table}.{col_name}")
            print("  Run scripts/check_db_audit_classification.py for the schema gap.")
        return 0
    finally:
        conn.close()
