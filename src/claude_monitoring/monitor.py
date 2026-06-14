#!/usr/bin/env python3
# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""
ai_monitor.py — AI Runtime Agent: CrowdStrike-Style Full Visibility Monitor
=============================================================================
Three-layer monitoring of ALL AI agent activity on your machine:
  Layer 1: NETWORK  — JSONL transcript tailing + network connection tracking
  Layer 2: FILESYSTEM — watchdog (FSEvents) file activity monitoring
  Layer 3: PROCESS — psutil process lifecycle and resource tracking

All events flow into a SQLite store and are served via a web dashboard on port 9081.

USAGE:
  python3 ai_monitor.py --start              # Start monitoring + dashboard
  python3 ai_monitor.py --scan               # One-shot process scan
  python3 ai_monitor.py --install-agent      # Install as macOS LaunchAgent
  python3 ai_monitor.py --uninstall-agent    # Remove LaunchAgent

DEPENDENCIES:
  pip3 install watchdog psutil
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import psutil
except ImportError:
    psutil = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    Observer = None
    FileSystemEventHandler = object

from claude_monitoring.config import (
    get_bind_address,
    get_dashboard_port,
    get_db_path,
    get_mcp_known_servers,
    get_output_dir,
    is_mcp_alert_on_unknown,
)
from claude_monitoring.constants import (
    AGENT_TYPE_MAP,
    AI_HOSTS,
    ANTHROPIC_IP_PREFIXES,
    BROWSER_AI_PATTERNS,
    PLAN_LIMITS,
    SERVICE_CLASSIFICATION,
    SEVERITY_ORDER,
)
from claude_monitoring.db import get_thread_db, init_db
from claude_monitoring.utils import _is_known_example, is_ai_process, now_iso, scan_sensitive

# ─────────────────────────────────────────────────────────────
# SECTION 1: CONFIG & CONSTANTS
# ─────────────────────────────────────────────────────────────

# Module-level path aliases (for backward compat with tests that patch these)
DASHBOARD_PORT = get_dashboard_port()
CLAUDE_PROJECTS_DIR = Path.home() / ".claude" / "projects"
OPENCLAW_SESSIONS_DIR = Path.home() / ".openclaw" / "agents" / "main" / "sessions"
OUTPUT_DIR = get_output_dir()
DB_PATH = get_db_path()
SCRIPT_PATH = Path(__file__).resolve()

# In-memory live feed buffer
live_feed = deque(maxlen=500)
live_feed_lock = threading.Lock()
_live_feed_seen = set()  # dedup: last 1000 event hashes

# Track active session CWDs for file monitoring
active_session_cwds = set()
active_cwds_lock = threading.Lock()

# Plan/subscription detection (populated on startup)
plan_info = {"is_subscription": False, "plan_tier": ""}

# feat/daemon-discovery-scheduler — see `discovery_scheduler.py` for the
# loop body, the sweep, and the cadence constants. Re-exported below so
# tests + first-party consumers that monkeypatch `monitor.X` continue
# to resolve the same callable.

# Feature B: async scan progress state. Module-level singleton protected
# by a lock. Shape matches the plan:
#   running, started_at, finished_at, phase, per_source, totals
# The POST /api/supply-chain/scan handler spawns a daemon thread that
# calls vuln_scanner.run_full_scan(db, progress_cb=...). The callback
# updates this dict under the lock, and GET /api/supply-chain/scan-progress
# returns a snapshot for the dashboard to poll.
_scan_state_lock = threading.Lock()


def _new_scan_state() -> dict:
    return {
        "running": False,
        "started_at": None,
        "finished_at": None,
        "phase": None,
        "per_source": {
            "environment": {"status": "pending", "records": 0, "error": None},
            "pip-audit": {"status": "pending", "records": 0, "error": None},
            "osv": {"status": "pending", "records": 0, "error": None},
            "threatfox": {"status": "pending", "records": 0, "error": None},
            "urlhaus": {"status": "pending", "records": 0, "error": None},
            "registry": {"status": "pending", "records": 0, "error": None},
        },
        "totals": {"vulns_found": 0, "new_since_last_scan": 0, "packages_scanned": 0},
    }


_scan_state: dict = _new_scan_state()


# ─────────────────────────────────────────────────────────────
# SECTION 2: UTILITY FUNCTIONS (module-level state)
# ─────────────────────────────────────────────────────────────


_SUPPLY_CHAIN_PATTERNS = {
    "supply_chain_risk",
    "vulnerable_package",
    "typosquat",
    "remote_exec_unpinned",
    "malicious_package",
}


def _enrich_supply_chain_alert(db, session_id, data: dict) -> dict | None:
    """Feature C: build a {package, manager, advisory_id, advisory_url,
    investigation[]} dict for supply-chain alerts so the dashboard can
    render the investigation card.

    Returns None for non-supply-chain alerts (credentials, etc.) so the
    existing flat card layout stays in place for them.

    Cross-references:
      - ``agent_dependencies`` for the most recent install in the same
        session (so we know the package + manager + risk flags)
      - ``package_vulnerabilities`` for the first linked advisory
      - ``package_registry_cache`` for publish date / description /
        download signals
    """
    patterns = set(data.get("patterns") or [])
    if not patterns & _SUPPLY_CHAIN_PATTERNS:
        return None

    matched_value = (data.get("matched_value") or "").strip()
    context = (data.get("context") or "").strip()

    # Best-effort: find the most recent install in this session. If no
    # session_id, fall back to most recent global install (rare).
    dep_row = None
    try:
        if session_id:
            dep_row = db.execute(
                """SELECT package_name, package_manager, package_version,
                          risk_flags, risk_score, timestamp
                   FROM agent_dependencies
                   WHERE session_id = ?
                   ORDER BY id DESC LIMIT 1""",
                (session_id,),
            ).fetchone()
        if not dep_row and matched_value:
            # Try to match the alert's matched_value against a package name
            dep_row = db.execute(
                """SELECT package_name, package_manager, package_version,
                          risk_flags, risk_score, timestamp
                   FROM agent_dependencies
                   WHERE package_name LIKE ?
                   ORDER BY id DESC LIMIT 1""",
                (f"%{matched_value[:40]}%",),
            ).fetchone()
    except Exception:
        dep_row = None

    if not dep_row:
        return None

    pkg_name = dep_row["package_name"] if hasattr(dep_row, "keys") else dep_row[0]
    pkg_mgr = dep_row["package_manager"] if hasattr(dep_row, "keys") else dep_row[1]
    risk_flags_json = dep_row["risk_flags"] if hasattr(dep_row, "keys") else dep_row[3]

    try:
        risk_flags = json.loads(risk_flags_json or "{}")
    except Exception:
        risk_flags = {}

    # Find the first linked advisory (prefer OSV MAL- entries — those are
    # the loudest malicious-package signals)
    advisory_id = None
    advisory_url = None
    try:
        vuln_rows = db.execute(
            """SELECT vuln_id, source, severity FROM package_vulnerabilities
               WHERE package_name = ?
               ORDER BY
                 CASE WHEN vuln_id LIKE 'MAL-%' THEN 0 ELSE 1 END,
                 CASE severity
                   WHEN 'malicious' THEN 0
                   WHEN 'critical'  THEN 1
                   WHEN 'high'      THEN 2
                   WHEN 'medium'    THEN 3
                   ELSE 4 END,
                 id DESC""",
            (pkg_name,),
        ).fetchall()
    except Exception:
        vuln_rows = []

    for v in vuln_rows:
        vid = v["vuln_id"] if hasattr(v, "keys") else v[0]
        if vid:
            advisory_id = vid
            if vid.startswith(("MAL-", "GHSA-", "CVE-", "PYSEC-", "GO-")):
                advisory_url = f"https://osv.dev/vulnerability/{vid}"
            else:
                advisory_url = f"https://osv.dev/list?q={vid}"
            break

    if not advisory_url and pkg_name:
        if pkg_mgr == "pip":
            advisory_url = f"https://pypi.org/project/{pkg_name}/"
        elif pkg_mgr == "npm":
            advisory_url = f"https://www.npmjs.com/package/{pkg_name}"

    # Build the investigation checklist
    investigation: list[str] = []

    # 1. Malicious advisory signal
    if advisory_id and advisory_id.startswith("MAL-"):
        investigation.append("Package flagged as malicious (OSV MAL- prefix)")
    elif "malicious_package" in patterns:
        investigation.append("Flagged as malicious by pattern detector")

    # 2. Risk flags from the dependency row
    reasons = risk_flags.get("reasons") or []
    for reason in reasons:
        # Risk flags are already human-readable strings from supply_chain.py
        investigation.append(str(reason))

    # 3. Registry metadata signals (0 downloads, no description, scope mismatch)
    try:
        cache_row = db.execute(
            """SELECT metadata FROM package_registry_cache
               WHERE package_name = ? AND manager = ?""",
            (pkg_name, pkg_mgr),
        ).fetchone()
        if cache_row:
            meta_json = cache_row["metadata"] if hasattr(cache_row, "keys") else cache_row[0]
            try:
                meta = json.loads(meta_json or "{}")
            except Exception:
                meta = {}
            if not meta.get("has_description"):
                investigation.append("No description or summary")
            if not meta.get("has_repository"):
                investigation.append("No repository URL")
            if meta.get("has_install_scripts"):
                investigation.append("Has install scripts (postinstall / preinstall)")
    except Exception:
        pass

    # 4. Typosquat signal
    if "typosquat" in patterns:
        investigation.append("Name similar to a popular package (possible typosquat)")

    # 5. Pattern-based fallbacks
    if "remote_exec_unpinned" in patterns and not any("unpinned" in r.lower() for r in investigation):
        investigation.append("Unpinned remote code execution (npx / curl | sh)")

    # Dedup while preserving order
    seen = set()
    deduped = []
    for item in investigation:
        if item not in seen:
            seen.add(item)
            deduped.append(item)

    # Compute a display label for the installer
    installed_by = context or "unknown"
    if installed_by.startswith("tool:"):
        installed_by = installed_by[5:]

    return {
        "name": pkg_name,
        "manager": pkg_mgr,
        "advisory_id": advisory_id,
        "advisory_url": advisory_url,
        "installed_by": installed_by,
        "investigation": deduped,
    }


def push_live_event(event):
    """Push event to the in-memory live feed, with dedup."""
    ts = event.get("timestamp", "")
    sid = event.get("session_id", "")
    etype = event.get("event_type", "")
    summary = event.get("summary", "")[:80]
    # Only dedup events that have enough identity fields (real monitor events)
    if ts and etype:
        key = f"{ts}|{sid}|{etype}|{summary}"
        h = hashlib.sha256(key.encode()).hexdigest()[:12]
        with live_feed_lock:
            if h in _live_feed_seen:
                return
            _live_feed_seen.add(h)
            if len(_live_feed_seen) > 1000:
                _live_feed_seen.clear()
    with live_feed_lock:
        live_feed.append(event)


def compute_forecast(db):
    """Compute token burn rate and forecast from DB data."""
    forecast = {
        "daily_burn_rate": 0,
        "avg_7d_burn": 0,
        "daily_breakdown": [],
        "days_remaining": None,
        "monthly_limit": None,
        "monthly_used": 0,
        "burn_trend": "stable",
    }

    # Daily token usage for last 14 days
    rows = db.execute(
        """SELECT date(timestamp) as day,
                  SUM(json_extract(data_json, '$.input_tokens')) as input_t,
                  SUM(json_extract(data_json, '$.output_tokens')) as output_t
           FROM events
           WHERE event_type='token_usage'
             AND timestamp > datetime('now', '-14 days')
           GROUP BY day ORDER BY day"""
    ).fetchall()

    daily = []
    for r in rows:
        total = (r["input_t"] or 0) + (r["output_t"] or 0)
        daily.append(
            {
                "day": r["day"],
                "input_tokens": r["input_t"] or 0,
                "output_tokens": r["output_t"] or 0,
                "total_tokens": total,
            }
        )

    forecast["daily_breakdown"] = daily

    if not daily:
        return forecast

    # Calculate averages
    totals = [d["total_tokens"] for d in daily]
    last_7 = totals[-7:] if len(totals) >= 7 else totals
    last_3 = totals[-3:] if len(totals) >= 3 else totals

    forecast["avg_7d_burn"] = int(sum(last_7) / len(last_7)) if last_7 else 0
    forecast["daily_burn_rate"] = int(sum(last_3) / len(last_3)) if last_3 else 0

    # Trend: compare last 3 days avg to previous 4 days avg
    if len(totals) >= 7:
        recent_avg = sum(totals[-3:]) / 3
        earlier_avg = sum(totals[-7:-3]) / 4
        if earlier_avg > 0:
            ratio = recent_avg / earlier_avg
            if ratio > 1.3:
                forecast["burn_trend"] = "increasing"
            elif ratio < 0.7:
                forecast["burn_trend"] = "decreasing"

    # Subscription forecast
    if plan_info.get("is_subscription"):
        tier = (plan_info.get("plan_tier", "") or "").lower().replace(" ", "_")
        plan = None
        for key, data in PLAN_LIMITS.items():
            if key in tier:
                plan = data
                break
        if not plan:
            # Default to Pro limits
            plan = PLAN_LIMITS.get("pro", {"monthly_tokens": 45_000_000, "label": "Pro"})

        forecast["monthly_limit"] = plan["monthly_tokens"]
        forecast["plan_label"] = plan["label"]

        # Actual current-month token usage
        month_rows = db.execute(
            """SELECT COALESCE(SUM(json_extract(data_json, '$.input_tokens')), 0) +
                      COALESCE(SUM(json_extract(data_json, '$.output_tokens')), 0) as total
               FROM events WHERE event_type='token_usage'
                 AND timestamp >= date('now', 'start of month')"""
        ).fetchone()
        monthly_used = month_rows[0] if month_rows else 0
        forecast["monthly_used"] = monthly_used

        if forecast["daily_burn_rate"] > 0:
            remaining_tokens = plan["monthly_tokens"] - monthly_used
            if remaining_tokens <= 0:
                forecast["days_remaining"] = 0
            else:
                forecast["days_remaining"] = max(1, int(remaining_tokens / forecast["daily_burn_rate"]))

    return forecast


def detect_plan_info():
    """Detect Claude subscription plan from local config files."""
    global plan_info
    info = {"is_subscription": False, "plan_tier": ""}

    # Check stats-cache.json for modelUsage costUSD
    stats_path = Path.home() / ".claude" / "stats-cache.json"
    if stats_path.exists():
        try:
            with open(stats_path) as f:
                stats = json.load(f)
            model_usage = stats.get("modelUsage", {})
            if model_usage:
                all_zero = all(m.get("costUSD", 0) == 0 for m in model_usage.values())
                if all_zero:
                    info["is_subscription"] = True
        except Exception:
            pass

    # Check credentials for plan tier
    creds_path = Path.home() / ".claude" / ".credentials.json"
    if creds_path.exists():
        try:
            with open(creds_path) as f:
                creds = json.load(f)
            oauth = creds.get("claudeAiOauth", {})
            sub_type = oauth.get("subscriptionType", "")
            rate_tier = oauth.get("rateLimitTier", "")
            if sub_type:
                info["plan_tier"] = sub_type
                info["is_subscription"] = True
            if rate_tier:
                info["rate_tier"] = rate_tier
                if not info["plan_tier"]:
                    info["plan_tier"] = rate_tier
        except Exception:
            pass

    # Fallback: if no API key files found, assume subscription
    api_key_path = Path.home() / ".claude" / "api_key"
    if not api_key_path.exists() and not info.get("plan_tier"):
        # No API key file — likely subscription user
        info["is_subscription"] = True

    plan_info = info
    return info


# ─────────────────────────────────────────────────────────────
# SECTION 4: JSONL SESSION WATCHER (Layer 1a — Network/Content)
# ─────────────────────────────────────────────────────────────


class JSONLSessionWatcher:
    """Watches Claude JSONL transcript files for new data."""

    def __init__(self):
        self.file_positions = {}  # path -> last_read_offset
        self._file_lock = threading.Lock()  # Thread safety for file positions
        self._seen_uuids = set()  # Dedup: track seen record UUIDs
        self.db = get_thread_db()
        self._stop = threading.Event()
        self._pending_commits = 0
        self._load_file_positions()

    def stop(self):
        self._stop.set()

    def _load_file_positions(self):
        """Load persisted file positions from DB so restarts don't re-read files."""
        try:
            rows = self.db.execute("SELECT file_path, byte_offset FROM file_positions").fetchall()
            for row in rows:
                self.file_positions[row[0]] = row[1]
        except Exception:
            pass  # Table may not exist yet on first run

    def _save_file_position(self, path_str, offset):
        """Persist file position to DB."""
        try:
            self.db.execute(
                "INSERT INTO file_positions (file_path, byte_offset, last_read) VALUES (?, ?, datetime('now')) "
                "ON CONFLICT(file_path) DO UPDATE SET byte_offset=excluded.byte_offset, last_read=excluded.last_read",
                (path_str, offset),
            )
        except Exception:
            pass

    @staticmethod
    def _detect_agent_type(cwd, jsonl_path):
        """Detect agent type from cwd or jsonl_path patterns."""
        combined = (cwd or "") + "|" + str(jsonl_path or "")
        for pattern, agent_type in AGENT_TYPE_MAP.items():
            if pattern in combined:
                return agent_type
        return "unknown"

    def _ensure_session(self, session_id, jsonl_path, cwd=None, start_time=None):
        """Create or update session record."""
        try:
            agent_type = self._detect_agent_type(cwd, jsonl_path)
            # Pass None instead of empty string so COALESCE preserves existing values
            self.db.execute(
                """INSERT INTO sessions (session_id, start_time, cwd, jsonl_path, last_activity, agent_type)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE SET
                     last_activity=excluded.last_activity,
                     cwd=COALESCE(excluded.cwd, sessions.cwd),
                     jsonl_path=COALESCE(excluded.jsonl_path, sessions.jsonl_path),
                     agent_type=COALESCE(excluded.agent_type, sessions.agent_type)""",
                (session_id, start_time or now_iso(), cwd or None, str(jsonl_path), now_iso(), agent_type),
            )
            self.db.commit()
        except Exception:
            pass

    def _update_session_stats(self, session_id, model=None, input_tokens=0, output_tokens=0, is_turn=False):
        """Update session aggregate statistics."""
        try:
            parts = ["last_activity=?"]
            vals = [now_iso()]
            if model:
                parts.append("model=?")
                vals.append(model)
            if input_tokens:
                parts.append("total_input_tokens=total_input_tokens+?")
                vals.append(input_tokens)
            if output_tokens:
                parts.append("total_output_tokens=total_output_tokens+?")
                vals.append(output_tokens)
            if is_turn:
                parts.append("total_turns=total_turns+1")
            vals.append(session_id)
            self.db.execute(f"UPDATE sessions SET {', '.join(parts)} WHERE session_id=?", vals)  # nosec B608
            self.db.commit()
        except Exception:
            pass

    def _store_event(self, timestamp, session_id, event_type, source, data):
        """Store event in database and push to live feed, with dedup."""
        data_json = json.dumps(data, default=str)
        # Dedup hash: ensures identical events are never inserted twice
        dedup_key = f"{timestamp}|{session_id}|{event_type}|{data_json}"
        dedup_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]
        try:
            self.db.execute(
                "INSERT OR IGNORE INTO events (timestamp, session_id, event_type, source_layer, data_json, dedup_hash) VALUES (?,?,?,?,?,?)",
                (timestamp, session_id, event_type, source, data_json, dedup_hash),
            )
            self._pending_commits += 1
            # Batch commits for performance during backfill
            if self._pending_commits >= 50:
                self.db.commit()
                self._pending_commits = 0
        except Exception:
            pass

        feed_item = {
            "timestamp": timestamp,
            "session_id": session_id,
            "event_type": event_type,
            "source": source,
            "summary": self._make_summary(event_type, data),
        }
        push_live_event(feed_item)

    def _make_summary(self, event_type, data):
        """Create a short human-readable summary for the live feed."""
        if event_type == "user_prompt":
            text = data.get("text", "")
            return f'prompt: "{text[:80]}..."' if len(text) > 80 else f'prompt: "{text}"'
        elif event_type == "assistant_response":
            text = data.get("text", "")
            return f'response: "{text[:80]}..."' if len(text) > 80 else f'response: "{text}"'
        elif event_type == "thinking":
            return f"thinking ({data.get('length', 0)} chars)"
        elif event_type == "tool_use":
            name = data.get("name", "?")
            inp = data.get("input_preview", "")
            return f"{name}: {inp[:60]}"
        elif event_type == "tool_result":
            return f"result ({data.get('length', 0)} chars)"
        elif event_type == "token_usage":
            inp = data.get("input_tokens", 0)
            out = data.get("output_tokens", 0)
            return f"↑{inp}t ↓{out}t"
        elif event_type == "mcp_call":
            server = data.get("server", "?")
            method = data.get("method", "?")
            return f"MCP: {server}.{method}"
        elif event_type == "sensitive_data":
            sev = data.get("severity", "medium").upper()
            return f"ALERT [{sev}]: {', '.join(data.get('patterns', []))}"
        else:
            return event_type

    def process_jsonl_file(self, jsonl_path):
        """Read new lines from a JSONL file and process them."""
        path_str = str(jsonl_path)

        try:
            file_size = os.path.getsize(path_str)
        except OSError:
            return

        with self._file_lock:
            last_pos = self.file_positions.get(path_str, 0)
            if file_size <= last_pos:
                return

            try:
                with open(path_str, encoding="utf-8", errors="replace") as f:
                    f.seek(last_pos)
                    new_data = f.read()
                    new_pos = f.tell()
                    self.file_positions[path_str] = new_pos
                    self._save_file_position(path_str, new_pos)
            except OSError:
                return

        for line in new_data.strip().split("\n"):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._process_record(record, jsonl_path)

        # Flush any pending commits
        if self._pending_commits > 0:
            try:
                self.db.commit()
                self._pending_commits = 0
            except Exception:
                pass

    def _session_id_from_path(self, jsonl_path):
        """Extract session ID from JSONL filename (for OpenClaw files without sessionId)."""
        try:
            stem = Path(jsonl_path).stem
            # OpenClaw filenames are UUIDs: 50a4dd45-d84b-4d63-a613-b7937e30874f.jsonl
            if len(stem) == 36 and stem.count("-") == 4:
                return stem
        except Exception:
            pass
        return ""

    def _process_record(self, record, jsonl_path):
        """Process a single JSONL record."""
        try:
            # Dedup: skip records we've already processed
            rec_uuid = record.get("uuid", "")
            if rec_uuid:
                if rec_uuid in self._seen_uuids:
                    return
                self._seen_uuids.add(rec_uuid)

            rec_type = record.get("type", "")
            session_id = record.get("sessionId", "")
            timestamp = record.get("timestamp", now_iso())
            cwd = record.get("cwd", "")

            # OpenClaw: type:"session" records store session ID in "id" field;
            # type:"message" records also have "id" but it's a short *message* ID,
            # not the session ID. For non-session records, derive from filename.
            if not session_id:
                if rec_type == "session":
                    session_id = record.get("id", "")
                if not session_id:
                    session_id = self._session_id_from_path(jsonl_path)
            if not session_id:
                return

            # Handle OpenClaw type:"session" — initializes the session record
            if rec_type == "session":
                self._ensure_session(session_id, jsonl_path, cwd=cwd, start_time=timestamp)
                return

            # Handle OpenClaw type:"model_change" — sets the model on the session
            if rec_type == "model_change":
                model_id = record.get("modelId", "")
                if model_id:
                    self._update_session_stats(session_id, model=model_id)
                return

            self._ensure_session(session_id, jsonl_path, cwd=cwd, start_time=timestamp)

            # Track active CWDs for file monitoring
            if cwd:
                with active_cwds_lock:
                    active_session_cwds.add(cwd)

            # OpenClaw uses type:"message" with a role field instead of type:"user"/"assistant"
            if rec_type == "message":
                role = record.get("role", record.get("message", {}).get("role", ""))
                if role == "user":
                    record = self._normalize_openclaw_record(record, "user")
                    self._process_user_message(record, session_id, timestamp)
                elif role == "assistant":
                    record = self._normalize_openclaw_record(record, "assistant")
                    self._process_assistant_message(record, session_id, timestamp)
                elif role == "toolResult":
                    record = self._normalize_openclaw_tool_result(record, session_id)
                    self._process_user_message(record, session_id, timestamp)
                return

            if rec_type == "user":
                self._process_user_message(record, session_id, timestamp)
            elif rec_type == "assistant":
                self._process_assistant_message(record, session_id, timestamp)
            elif rec_type == "system":
                self._store_event(
                    timestamp, session_id, "system_event", "network", {"subtype": record.get("subtype", "")}
                )
            elif rec_type == "progress":
                self._process_progress(record, session_id, timestamp)
        except Exception:
            pass  # Never crash on a single malformed record

    @staticmethod
    def _normalize_openclaw_record(record, role):
        """Normalize OpenClaw JSONL fields to Claude Code format.

        Handles differences:
        - toolCall → tool_use in content blocks
        - toolResult → tool_result in content blocks
        - stopReason → stop_reason
        - usage.cacheRead → usage.cache_read_input_tokens
        - usage.cacheWrite → usage.cache_creation_input_tokens
        """
        message = record.get("message", {})

        # Normalize stop reason
        if "stopReason" in message and "stop_reason" not in message:
            message["stop_reason"] = message["stopReason"]

        # Normalize usage fields
        usage = message.get("usage", {})
        if usage:
            if "cacheRead" in usage and "cache_read_input_tokens" not in usage:
                usage["cache_read_input_tokens"] = usage["cacheRead"]
            if "cacheWrite" in usage and "cache_creation_input_tokens" not in usage:
                usage["cache_creation_input_tokens"] = usage["cacheWrite"]
            if "input" in usage and "input_tokens" not in usage:
                usage["input_tokens"] = usage["input"]
            if "output" in usage and "output_tokens" not in usage:
                usage["output_tokens"] = usage["output"]

        # Normalize content block types
        content = message.get("content", [])
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")
                if btype == "toolCall":
                    block["type"] = "tool_use"
                    # OpenClaw uses "arguments" where Claude Code uses "input"
                    if "arguments" in block and "input" not in block:
                        block["input"] = block["arguments"]
                elif btype == "toolResult":
                    block["type"] = "tool_result"
                    if "toolUseId" in block and "tool_use_id" not in block:
                        block["tool_use_id"] = block["toolUseId"]

        record["message"] = message
        return record

    @staticmethod
    def _normalize_openclaw_tool_result(record, session_id):
        """Normalize an OpenClaw toolResult record into a user message with tool_result content.

        OpenClaw format:
          {"type":"message","message":{"role":"toolResult","toolCallId":"toolu_01...","toolName":"search","content":"..."}}
        Claude Code format (what _process_user_message expects):
          {"message":{"content":[{"type":"tool_result","tool_use_id":"toolu_01...","content":"..."}]}}
        """
        msg = record.get("message", {})
        tool_result_block = {
            "type": "tool_result",
            "tool_use_id": msg.get("toolCallId", msg.get("tool_use_id", "")),
            "content": msg.get("content", ""),
            "is_error": msg.get("isError", False),
        }
        return {"message": {"content": [tool_result_block]}}

    @staticmethod
    def _extract_openclaw_user_text(text):
        """Strip OpenClaw metadata wrappers from user prompt text.

        OpenClaw wraps prompts with Conversation/Sender metadata blocks:
          Conversation info (untrusted metadata):
          ```json
          {"message_id": "4", "sender": "Aj K", ...}
          ```
          Sender (untrusted metadata):
          ```json
          {...}
          ```

          actual user message here

        Returns (cleaned_text, source_hint) where source_hint is e.g. "Telegram".
        """
        source_hint = ""
        if "untrusted metadata" not in text:
            return text, source_hint

        # Detect integration source from metadata
        if "sender_id" in text and "message_id" in text:
            source_hint = "Telegram"

        # The actual user text follows the last ``` + blank line
        # Split on the closing ``` markers and take the last segment
        parts = text.split("```")
        if len(parts) >= 5:  # At least 2 fenced blocks (open/close pairs) + trailing text
            user_text = parts[-1].strip()
            if user_text:
                return user_text, source_hint

        return text, source_hint

    @staticmethod
    def _detect_openclaw_channel(text):
        """Detect the OpenClaw messaging channel from user prompt metadata.

        Returns: "Telegram", "Discord", "Slack", or None.
        """
        if not text or "untrusted metadata" not in text:
            return None
        if "sender_id" in text and "message_id" in text:
            return "Telegram"
        if "discord" in text.lower():
            return "Discord"
        if "slack" in text.lower():
            return "Slack"
        return None

    # Patterns that should never be session titles
    _TITLE_SKIP_PREFIXES = (
        "Conversation info",
        "Sender (untrusted",
        "Sender (",
        "untrusted metadata",
        "Caveat:",
        "Caveat: The messages",
        "[Request interrupted",
        "Start with this:",
        "Then paste this",
        "Your task is to create a detailed summary",
        "de619ec2",
        '{ "label"',
    )

    @staticmethod
    def _clean_title(text):
        """Strip markdown, HTML tags, and metadata from title text."""
        t = re.sub(r"<[^>]+>", "", text)
        t = re.sub(r"```[\s\S]*?```", "", t)
        t = re.sub(r"```\w*", "", t)
        t = re.sub(r"^#+\s*", "", t, flags=re.MULTILINE)
        t = t.replace("**", "").replace("__", "")
        # Skip metadata/system prefixes — try to find real content
        for _prefix in JSONLSessionWatcher._TITLE_SKIP_PREFIXES:
            if t.strip().startswith(_prefix):
                parts = t.split("\n\n")
                for part in parts:
                    stripped = part.strip()
                    if stripped and not any(stripped.startswith(p) for p in JSONLSessionWatcher._TITLE_SKIP_PREFIXES):
                        t = stripped
                        break
                else:
                    return ""  # No real content found
                break
        t = re.sub(r"\s+", " ", t).strip()
        return t

    def _set_session_title(self, session_id, text):
        """Set session title from first user message if not already set."""
        try:
            row = self.db.execute(
                "SELECT title, total_turns, cwd FROM sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            if row and not row[0] and (row[1] or 0) <= 1:
                cwd = row[2] or ""
                is_openclaw = ".openclaw" in cwd

                if is_openclaw:
                    clean_text, source_hint = self._extract_openclaw_user_text(text)
                    clean_text = self._clean_title(clean_text)
                    if not clean_text or clean_text.startswith("Conversation info"):
                        clean_text = "OpenClaw session"
                    if source_hint:
                        title = f"OpenClaw · {source_hint}: {clean_text}"
                    else:
                        title = f"OpenClaw: {clean_text}"
                else:
                    title = self._clean_title(text)

                # Truncate at word boundary around 80 chars
                if len(title) > 80:
                    truncated = title[:80]
                    last_space = truncated.rfind(" ")
                    if last_space > 40:
                        truncated = truncated[:last_space]
                    title = truncated.rstrip() + "..."
                self.db.execute("UPDATE sessions SET title=? WHERE session_id=?", (title, session_id))
                self.db.commit()
        except Exception:
            pass

    def _process_user_message(self, record, session_id, timestamp):
        """Process a user message record."""
        message = record.get("message", {})
        content = message.get("content", "")

        if isinstance(content, str):
            # Simple text prompt
            self._store_event(timestamp, session_id, "user_prompt", "network", {"text": content, "role": "user"})
            self._check_sensitive(content, session_id, timestamp, "user_prompt")
            self._update_session_stats(session_id, is_turn=True)
            self._set_session_title(session_id, content)

        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")

                if btype == "text":
                    text = block.get("text", "")
                    self._store_event(timestamp, session_id, "user_prompt", "network", {"text": text, "role": "user"})
                    self._check_sensitive(text, session_id, timestamp, "user_prompt")
                    self._update_session_stats(session_id, is_turn=True)
                    self._set_session_title(session_id, text)

                elif btype == "tool_result":
                    tool_use_id = block.get("tool_use_id", "")
                    result_content = block.get("content", "")
                    if isinstance(result_content, list):
                        parts = []
                        for rc in result_content:
                            if isinstance(rc, dict) and rc.get("type") == "text":
                                parts.append(rc.get("text", ""))
                        result_content = "\n".join(parts)
                    result_str = str(result_content)
                    self._store_event(
                        timestamp,
                        session_id,
                        "tool_result",
                        "network",
                        {
                            "tool_use_id": tool_use_id,
                            "content": result_str[:5000],
                            "length": len(result_str),
                            "is_error": block.get("is_error", False),
                        },
                    )
                    self._check_sensitive(result_str, session_id, timestamp, "tool_result")

    def _process_assistant_message(self, record, session_id, timestamp):
        """Process an assistant message record."""
        message = record.get("message", {})
        content = message.get("content", [])
        model = message.get("model", "")
        usage = message.get("usage", {})
        stop_reason = message.get("stop_reason", "")

        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        cache_read = usage.get("cache_read_input_tokens", 0)
        cache_write = usage.get("cache_creation_input_tokens", 0)

        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type", "")

            if btype == "thinking":
                thinking_text = block.get("thinking", "")
                self._store_event(
                    timestamp,
                    session_id,
                    "thinking",
                    "network",
                    {
                        "text": thinking_text[:5000],
                        "length": len(thinking_text),
                    },
                )

            elif btype == "text":
                text = block.get("text", "")
                self._store_event(
                    timestamp,
                    session_id,
                    "assistant_response",
                    "network",
                    {
                        "text": text,
                        "model": model,
                        "stop_reason": stop_reason,
                    },
                )
                self._check_sensitive(text, session_id, timestamp, "assistant_response")

            elif btype == "tool_use":
                tool_name = block.get("name", "")
                tool_input = block.get("input", {})
                tool_id = block.get("id", "")

                # Build a preview of the input
                input_preview = ""
                if tool_name in ("Bash", "bash"):
                    input_preview = tool_input.get("command", "")[:200]
                elif tool_name in ("Read", "read_file"):
                    input_preview = tool_input.get("file_path", tool_input.get("path", ""))
                elif tool_name in ("Write", "write_file", "create_file"):
                    input_preview = tool_input.get("file_path", tool_input.get("path", ""))
                elif tool_name in ("Edit", "str_replace_editor"):
                    input_preview = tool_input.get("file_path", tool_input.get("path", ""))
                elif tool_name in ("Glob", "Grep"):
                    input_preview = tool_input.get("pattern", "")
                elif tool_name == "WebFetch":
                    input_preview = tool_input.get("url", "")
                elif tool_name == "WebSearch":
                    input_preview = tool_input.get("query", "")
                else:
                    input_preview = json.dumps(tool_input, default=str)[:200]

                self._store_event(
                    timestamp,
                    session_id,
                    "tool_use",
                    "network",
                    {
                        "name": tool_name,
                        "id": tool_id,
                        "input": tool_input,
                        "input_preview": input_preview,
                    },
                )
                self._check_sensitive(json.dumps(tool_input, default=str), session_id, timestamp, f"tool:{tool_name}")

                # Supply chain: detect package installs from Bash commands
                if tool_name in ("Bash", "bash") and input_preview:
                    self._check_supply_chain(input_preview, session_id, timestamp)

                # MCP server detection: tool names like mcp__<server>__<method>
                if tool_name.startswith("mcp__"):
                    parts = tool_name.split("__", 2)
                    mcp_server = parts[1] if len(parts) > 1 else "unknown"
                    mcp_method = parts[2] if len(parts) > 2 else "unknown"
                    self._store_event(
                        timestamp,
                        session_id,
                        "mcp_call",
                        "network",
                        {
                            "server": mcp_server,
                            "method": mcp_method,
                            "tool_name": tool_name,
                            "input_preview": input_preview,
                        },
                    )
                    # Alert on unknown MCP server
                    if is_mcp_alert_on_unknown():
                        known = set(get_mcp_known_servers())
                        if known and mcp_server not in known:
                            self._store_event(
                                timestamp,
                                session_id,
                                "sensitive_data",
                                "network",
                                {
                                    "patterns": [f"unknown_mcp_server:{mcp_server}"],
                                    "severity": "high",
                                    "categories": ["policy"],
                                    "context": f"Unknown MCP server '{mcp_server}' called method '{mcp_method}'",
                                    "snippet": tool_name,
                                },
                            )

        # Store token usage event
        if input_tokens or output_tokens:
            self._store_event(
                timestamp,
                session_id,
                "token_usage",
                "network",
                {
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cache_read_tokens": cache_read,
                    "cache_write_tokens": cache_write,
                    "stop_reason": stop_reason,
                },
            )
            self._update_session_stats(session_id, model=model, input_tokens=input_tokens, output_tokens=output_tokens)

        # OpenClaw API call extraction: records with provider/api fields contain
        # rich API metadata that we can insert into api_calls table (Option C from roadmap)
        provider = message.get("provider", "")
        api_type = message.get("api", "")
        response_id = message.get("responseId", "")
        if provider and api_type and (input_tokens or output_tokens):
            cost_data = message.get("cost", message.get("usage", {}).get("cost", {}))
            cost_total = cost_data.get("total", 0) if isinstance(cost_data, dict) else 0
            # Map provider to destination host
            host_map = {
                "anthropic": "api.anthropic.com",
                "openai": "api.openai.com",
                "google": "generativelanguage.googleapis.com",
            }
            svc_map = {"anthropic": "anthropic_api", "openai": "openai_api", "google": "gemini_api"}
            dest_host = host_map.get(provider, f"api.{provider}.com")
            dest_service = svc_map.get(provider, f"{provider}_api")
            try:
                self.db.execute(
                    """INSERT INTO api_calls (timestamp, session_id, destination_host, destination_service,
                       model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
                       estimated_cost_usd, stop_reason, request_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        timestamp,
                        session_id,
                        dest_host,
                        dest_service,
                        model,
                        input_tokens,
                        output_tokens,
                        cache_read,
                        cache_write,
                        cost_total,
                        stop_reason,
                        response_id,
                    ),
                )
                self.db.commit()
            except Exception:
                pass

    def _process_progress(self, record, session_id, timestamp):
        """Process a progress record."""
        data = record.get("data", {})
        dtype = data.get("type", "")
        if dtype == "bash_progress":
            output = data.get("output", "") or data.get("fullOutput", "")
            if output:
                self._store_event(
                    timestamp,
                    session_id,
                    "bash_progress",
                    "network",
                    {
                        "output": output[:2000],
                        "elapsed": data.get("elapsedTimeSeconds", 0),
                    },
                )

    def _check_supply_chain(self, command, session_id, timestamp):
        """Detect package installs in Bash commands and store in agent_dependencies."""
        try:
            from claude_monitoring.supply_chain import (
                KNOWN_TYPOSQUATS,
                parse_install_command,
                risk_level,
                store_dependency,
            )

            packages = parse_install_command(command)
            if not packages:
                return
            agent_type = None
            cwd = None
            try:
                row = self.db.execute(
                    "SELECT agent_type, cwd FROM sessions WHERE session_id=?", (session_id,)
                ).fetchone()
                if row:
                    agent_type = row[0]
                    cwd = row[1]
            except Exception:
                pass
            for pkg in packages:
                score = store_dependency(self.db, timestamp, session_id, agent_type, pkg, command, cwd)
                level = risk_level(score)
                # Critical alert for typosquats
                name_lower = pkg["name"].lower()
                if name_lower in KNOWN_TYPOSQUATS:
                    real_pkg = KNOWN_TYPOSQUATS[name_lower]
                    self._store_event(
                        timestamp,
                        session_id,
                        "sensitive_data",
                        "supply_chain",
                        {
                            "severity": "critical",
                            "patterns": ["typosquat"],
                            "categories": ["supply_chain"],
                            "context": "tool:Bash",
                            "snippet": f"Agent installed '{pkg['name']}' — known typosquat of '{real_pkg}'. Command: {command[:200]}",
                        },
                    )
                # High alert for high-risk packages
                elif level in ("high", "critical"):
                    self._store_event(
                        timestamp,
                        session_id,
                        "sensitive_data",
                        "supply_chain",
                        {
                            "severity": level,
                            "patterns": ["supply_chain_risk"],
                            "categories": ["supply_chain"],
                            "context": "tool:Bash",
                            "snippet": f"Agent installed '{pkg['name']}' (risk score: {score}). Command: {command[:200]}",
                        },
                    )
            self.db.commit()
        except Exception:
            pass

    # Alert dedup cache: (session_id, pattern, matched_prefix) -> event_id
    # P0-05: watchdog filesystem events dispatch to multiple handler
    # threads, and _check_sensitive mutates this dict (set, del, clear).
    # Without a lock two concurrent inserts can race the size check +
    # clear, and readers can see a half-populated dict. Shared class
    # lock keeps reads and writes atomic across all threads.
    _alert_dedup = {}
    _alert_dedup_lock = threading.Lock()

    @staticmethod
    def _calculate_confidence(context, pattern, matched_value, full_text):
        """Determine confidence level based on context and content."""
        if context == "user_prompt":
            return "high"
        if context == "tool_result":
            text_lower = (full_text or "").lower()
            if "/tests/" in full_text or "/test_" in full_text or "test_" in text_lower:
                return "low"
            if "EXAMPLE" in full_text or "example" in text_lower:
                return "low"
            return "high"
        if context == "assistant_response":
            return "low"  # assistants quote/discuss credentials, never introduce them
        if context and context.startswith("tool:"):
            text_lower = (full_text or "").lower()
            # Git commits about security = low
            if "git commit" in text_lower and any(
                w in text_lower for w in ("mask", "redact", "secret", "fix", "clean")
            ):
                return "low"
            # SQL/DB cleanup = low
            if any(w in text_lower for w in ("delete from", "sqlite3", "vacuum", "select count")):
                return "low"
            # Actual credential usage = high
            if any(w in text_lower for w in ("aws ", "curl -h", "export ", "ssh ", "docker login")):
                return "high"
            return "medium"
        return "medium"

    @staticmethod
    def _cap_severity_by_confidence(severity, confidence):
        """Cap severity based on confidence level."""
        if confidence == "low":
            return "low"
        if confidence == "medium" and severity in ("critical", "high"):
            return "medium"
        return severity

    def _check_sensitive(self, text, session_id, timestamp, context):
        """Scan text for sensitive patterns and store alerts with confidence."""
        if not text:
            return
        matches = scan_sensitive(text)
        if not matches:
            return
        matches = [m for m in matches if not _is_known_example(m["name"], text)]
        if not matches:
            return
        if "sender_id" in text or "message_id" in text:
            matches = [m for m in matches if m["name"] != "phone_number"]
        if not matches:
            return
        if any(kw in text for kw in ("input_tokens", "anthropic", "responseId", "cache_read")):
            matches = [m for m in matches if m["name"] != "credit_card"]
        if not matches:
            return

        # Capture the first match's value and context window
        first_match = matches[0]
        matched_value = first_match.get("matched_value", "")
        match_start = first_match.get("match_start", 0)
        ctx_start = max(0, match_start - 50)
        ctx_end = min(len(text), match_start + len(matched_value) + 50)
        match_context = text[ctx_start:ctx_end]

        # Confidence scoring
        pattern_names = [m["name"] for m in matches]
        confidence = self._calculate_confidence(context, pattern_names[0], matched_value, text)
        likely_fp = confidence == "low"

        # Severity: pattern severity capped by confidence
        raw_severity = min((m["severity"] for m in matches), key=lambda s: SEVERITY_ORDER.get(s, 99))
        severity = self._cap_severity_by_confidence(raw_severity, confidence)

        # Dedup: same pattern + matched value in same session
        dedup_key = (session_id, pattern_names[0], matched_value[:20] if matched_value else "")
        with self._alert_dedup_lock:
            existing_id = self._alert_dedup.get(dedup_key)
        if existing_id is not None:
            try:
                self.db.execute(
                    """UPDATE events SET data_json = json_set(data_json,
                        '$.repeat_count',
                        COALESCE(json_extract(data_json, '$.repeat_count'), 1) + 1)
                    WHERE id = ?""",
                    (existing_id,),
                )
                return
            except Exception:
                pass

        categories = list({m["category"] for m in matches})
        from claude_monitoring.security import hash_value, mask_value

        # Replace the raw credential everywhere it appears in the snippet so
        # surrounding context is preserved but the secret is redacted. We
        # also redact match_context the same way. The DB must NEVER contain
        # the raw value — an attacker who exfiltrates monitor.db gets no
        # usable secrets by design.
        masked_value = mask_value(matched_value)
        raw_snippet = text[:200] if text else ""
        safe_snippet = raw_snippet.replace(matched_value, masked_value) if matched_value else raw_snippet
        safe_match_context = match_context.replace(matched_value, masked_value) if matched_value else match_context

        event_data = {
            "patterns": pattern_names,
            "severity": severity,
            "categories": categories,
            "context": context,
            "snippet": safe_snippet,
            "matched_value": masked_value,
            "matched_hash": hash_value(matched_value),
            "match_context": safe_match_context,
            "confidence": confidence,
            "likely_false_positive": likely_fp,
        }
        self._store_event(timestamp, session_id, "sensitive_data", "network", event_data)

        # Track for dedup. The size-check-and-clear must run under the
        # same lock as the insert — without it, two threads inserting
        # near the 500-key cap could both see len < 500, both insert,
        # then both clear, losing each other's entry.
        try:
            row = self.db.execute("SELECT MAX(id) FROM events WHERE event_type='sensitive_data'").fetchone()
            if row and row[0]:
                with self._alert_dedup_lock:
                    self._alert_dedup[dedup_key] = row[0]
                    if len(self._alert_dedup) > 500:
                        self._alert_dedup.clear()
        except Exception:
            pass

    def _adjust_alert_severity(self, severity, context, text):
        """Downgrade alert severity based on context to reduce false positives.

        Rules:
        - tool_result with /tests/ or /test_ path: downgrade to low
        - tool_result with "EXAMPLE" near match: downgrade to low
        - assistant_response discussing/analyzing code: downgrade to medium
        - tool:Write with /tests/ path: downgrade to low
        """
        text_lower = text.lower() if text else ""

        if context == "tool_result":
            # Test file results
            if "/tests/" in text or "/test_" in text or "test_" in text_lower:
                return "low"
            # Example patterns in tool output
            if "EXAMPLE" in text or "example" in text_lower:
                return "low"

        elif context == "assistant_response":
            # Assistants quote/discuss credentials — never introduce new ones
            if severity in ("critical", "high"):
                return "medium"

        elif context and context.startswith("tool:"):
            # Tool writes to test files
            if "/tests/" in text or "/test_" in text:
                return "low"

        return severity


class JSONLFileHandler(FileSystemEventHandler):
    """Watchdog handler for JSONL file changes."""

    def __init__(self, watcher):
        super().__init__()
        self.watcher = watcher

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".jsonl"):
            self.watcher.process_jsonl_file(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".jsonl"):
            self.watcher.process_jsonl_file(event.src_path)


# ─────────────────────────────────────────────────────────────
# SECTION 5: PROCESS SCANNER (Layer 3)
# ─────────────────────────────────────────────────────────────


class ProcessScanner:
    """Scans for AI agent processes and tracks their lifecycle."""

    def __init__(self):
        self.known_pids = {}  # pid -> process info
        self.db = get_thread_db()
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def scan_once(self):
        """Perform a single scan of running processes."""
        if not psutil:
            return []

        found = []
        current_pids = set()

        try:
            for proc in psutil.process_iter(
                ["pid", "name", "cmdline", "cpu_percent", "memory_percent", "create_time", "status"]
            ):
                try:
                    info = proc.info
                    pid = info["pid"]
                    name = info.get("name") or ""
                    cmdline_str = " ".join(info.get("cmdline") or [])

                    # Get executable path for system service detection
                    try:
                        exe_path = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = ""

                    if not is_ai_process(name, cmdline_str, exe_path):
                        continue

                    current_pids.add(pid)
                    proc_data = {
                        "pid": pid,
                        "name": name,
                        "cmdline": cmdline_str[:500],
                        "cpu_percent": info.get("cpu_percent", 0) or 0,
                        "memory_percent": round(info.get("memory_percent", 0) or 0, 2),
                        "status": info.get("status", ""),
                        "create_time": datetime.fromtimestamp(info.get("create_time", 0), tz=timezone.utc).isoformat()
                        if info.get("create_time")
                        else "",
                    }
                    found.append(proc_data)

                    if pid not in self.known_pids:
                        # New process detected
                        self.known_pids[pid] = proc_data
                        try:
                            self.db.execute(
                                """INSERT INTO processes (pid, name, cmdline, start_time,
                                   cpu_percent, memory_percent, status)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (
                                    pid,
                                    proc_data["name"],
                                    proc_data["cmdline"],
                                    proc_data["create_time"],
                                    proc_data["cpu_percent"],
                                    proc_data["memory_percent"],
                                    "running",
                                ),
                            )
                            self.db.commit()
                        except Exception:
                            pass
                        push_live_event(
                            {
                                "timestamp": now_iso(),
                                "event_type": "process_start",
                                "source": "process",
                                "summary": f"NEW: {proc_data['name']} (PID {pid})",
                            }
                        )
                    else:
                        # Update existing process
                        self.known_pids[pid] = proc_data
                        try:
                            self.db.execute(
                                "UPDATE processes SET cpu_percent=?, memory_percent=? WHERE pid=? AND end_time IS NULL",
                                (proc_data["cpu_percent"], proc_data["memory_percent"], pid),
                            )
                            self.db.commit()
                        except Exception:
                            pass

                    # Bug 1: ensure a synthetic "desktop AI app" session exists
                    # in the sessions table so Session Explorer's Desktop Apps
                    # filter has something to show. The session is keyed by
                    # app name (not PID) so restarts don't create duplicates.
                    # Runs on every scan tick so last_activity stays fresh.
                    self._ensure_desktop_session(proc_data["name"], proc_data["cmdline"], pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception:
            pass

        # Detect terminated processes
        terminated = set(self.known_pids.keys()) - current_pids
        for pid in terminated:
            old = self.known_pids.pop(pid)
            try:
                self.db.execute(
                    "UPDATE processes SET end_time=?, status='terminated' WHERE pid=? AND end_time IS NULL",
                    (now_iso(), pid),
                )
                self.db.commit()
            except Exception:
                pass
            push_live_event(
                {
                    "timestamp": now_iso(),
                    "event_type": "process_stop",
                    "source": "process",
                    "summary": f"STOPPED: {old['name']} (PID {pid})",
                }
            )

        return found

    # Bug 1: desktop-app → session synthesis.
    # Desktop AI apps (ChatGPT.app, Claude Desktop, Cursor) don't have
    # JSONL files, so nothing creates a row in the sessions table for
    # them. We detect them here by process name and upsert a session
    # keyed by a stable "desktop_<agent>" id (NOT by PID, so restarts
    # don't create duplicates). The session's last_activity is bumped
    # on every process scan so it stays live in the dashboard.
    _DESKTOP_AI_APPS = (
        # (substring match, agent_type, display title)
        ("ChatGPT", "chatgpt_desktop", "ChatGPT Desktop App"),
        ("Claude Helper", "claude_desktop", "Claude Desktop App"),
        ("Claude Desktop", "claude_desktop", "Claude Desktop App"),
        ("Cursor Helper", "cursor_desktop", "Cursor"),
        ("Cursor", "cursor_desktop", "Cursor"),
    )

    def _ensure_desktop_session(self, process_name: str, cmdline: str, pid: int) -> None:
        """Upsert a synthetic session row for a detected desktop AI app.

        Matches are by process-name substring because the real process
        names vary (``ChatGPT``, ``ChatGPTHelper``, ``Claude Helper
        (Renderer)``, ``Cursor Helper (Plugin)``, etc). The first match
        wins. The session_id is ``desktop_<agent>`` — no PID suffix —
        so that restarts of the same app map to the same row and don't
        fragment the user's history.
        """
        name_lower = (process_name or "").lower()
        # Skip the app launcher itself ("Claude" alone matches too broadly;
        # prefer helper processes which are always present when the app is
        # actually running and doing work).
        for needle, agent_type, title in self._DESKTOP_AI_APPS:
            if needle.lower() not in name_lower:
                continue
            session_id = "desktop_" + agent_type
            now = now_iso()
            try:
                self.db.execute(
                    """INSERT INTO sessions
                       (session_id, agent_type, title, start_time, last_activity,
                        total_turns, total_input_tokens, total_output_tokens, model)
                       VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)
                       ON CONFLICT(session_id) DO UPDATE SET
                           last_activity = excluded.last_activity""",
                    (session_id, agent_type, title, now, now, agent_type),
                )
                self.db.commit()
            except Exception:
                pass
            return  # first match wins — don't double-count Claude Helper as both Claude and Cursor

    def run_loop(self):
        """Continuous scanning loop."""
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(2)


# ─────────────────────────────────────────────────────────────
# SECTION 6: NETWORK CONNECTION MONITOR (Layer 1b)
# ─────────────────────────────────────────────────────────────


class NetworkMonitor:
    """Monitors network connections from AI agent processes."""

    def __init__(self):
        self.db = get_thread_db()
        self._stop = threading.Event()
        self.seen_connections = set()  # (pid, remote_host, remote_port)
        self._dns_cache = {}  # ip -> hostname (cached reverse DNS)

    def stop(self):
        self._stop.set()

    def _reverse_dns(self, ip):
        """Reverse DNS lookup with caching. Returns hostname or original IP."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            import socket

            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except Exception:
            self._dns_cache[ip] = ip
            return ip

    def _resolve_service(self, host):
        """Map a hostname/IP to a known AI service, with reverse DNS fallback."""
        # First try direct match against host string
        for pattern, service in AI_HOSTS.items():
            if pattern in host:
                return service, host

        # Try SERVICE_CLASSIFICATION for friendly names
        for suffix, friendly in SERVICE_CLASSIFICATION.items():
            if host.endswith(suffix) or suffix[1:] in host:
                return friendly, host

        # If host looks like an IP, try known IP prefixes first
        if host and (host[0].isdigit() or ":" in host):
            if any(host.startswith(pfx) for pfx in ANTHROPIC_IP_PREFIXES):
                return "Anthropic API", host

            hostname = self._reverse_dns(host)
            if hostname != host:
                for pattern, service in AI_HOSTS.items():
                    if pattern in hostname:
                        return service, hostname
                for suffix, friendly in SERVICE_CLASSIFICATION.items():
                    if hostname.endswith(suffix) or suffix[1:] in hostname:
                        return friendly, hostname
                return None, hostname

        return None, host

    def scan_once(self):
        """Scan network connections of AI processes."""
        if not psutil:
            return []

        found = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    info = proc.info
                    name = info.get("name") or ""
                    cmdline_str = " ".join(info.get("cmdline") or [])
                    if not is_ai_process(name, cmdline_str):
                        continue

                    pid = info["pid"]
                    try:
                        conns = proc.net_connections(kind="inet")
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue

                    for conn in conns:
                        if conn.status != "ESTABLISHED" or not conn.raddr:
                            continue
                        remote_host = conn.raddr.ip
                        remote_port = conn.raddr.port

                        conn_key = (pid, remote_host, remote_port)
                        if conn_key in self.seen_connections:
                            continue
                        self.seen_connections.add(conn_key)

                        service, resolved_host = self._resolve_service(remote_host)
                        display_host = resolved_host if resolved_host != remote_host else remote_host
                        conn_data = {
                            "pid": pid,
                            "process_name": info.get("name", ""),
                            "remote_host": display_host,
                            "remote_ip": remote_host,
                            "remote_port": remote_port,
                            "status": conn.status,
                            "service": service or "unknown",
                        }
                        found.append(conn_data)

                        try:
                            self.db.execute(
                                """INSERT INTO connections
                                   (timestamp, pid, process_name, remote_host, remote_port, status, service)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (
                                    now_iso(),
                                    pid,
                                    conn_data["process_name"],
                                    display_host,
                                    remote_port,
                                    conn.status,
                                    conn_data["service"],
                                ),
                            )
                            self.db.commit()
                        except Exception:
                            pass

                        if service:
                            push_live_event(
                                {
                                    "timestamp": now_iso(),
                                    "event_type": "connection",
                                    "source": "network",
                                    "summary": f"{info.get('name', '?')} → {display_host}:{remote_port} ({service})",
                                }
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        # Clean stale connection keys periodically
        if len(self.seen_connections) > 10000:
            self.seen_connections.clear()

        return found

    def run_loop(self):
        """Continuous monitoring loop."""
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(5)


# ─────────────────────────────────────────────────────────────
# SECTION 7: FILE ACTIVITY MONITOR (Layer 2)
# ─────────────────────────────────────────────────────────────


class FileActivityHandler(FileSystemEventHandler):
    """Monitors file changes in AI agent working directories."""

    def __init__(self):
        super().__init__()
        self.db = get_thread_db()
        # Ignore patterns
        self._ignore = {".git", "__pycache__", "node_modules", ".DS_Store", ".pyc", ".pyo", ".swp", ".swo"}

    def _should_ignore(self, path):
        parts = Path(path).parts
        return any(ig in parts or path.endswith(ig) for ig in self._ignore)

    def _record(self, event, operation):
        if event.is_directory:
            return
        path = event.src_path
        if self._should_ignore(path):
            return

        timestamp = now_iso()
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            size = 0

        try:
            self.db.execute(
                "INSERT INTO file_events (timestamp, path, operation, size) VALUES (?, ?, ?, ?)",
                (timestamp, path, operation, size),
            )
            self.db.commit()
        except Exception:
            pass

        push_live_event(
            {
                "timestamp": timestamp,
                "event_type": f"file_{operation}",
                "source": "filesystem",
                "summary": f"{operation}: {Path(path).name} ({size} bytes)",
            }
        )

    def on_created(self, event):
        self._record(event, "created")

    def on_modified(self, event):
        self._record(event, "modified")

    def on_deleted(self, event):
        self._record(event, "deleted")


# ─────────────────────────────────────────────────────────────
# SECTION 7b: CHROME HISTORY WATCHER (Browser AI)
# ─────────────────────────────────────────────────────────────


class ChromeHistoryWatcher:
    """Watches Chrome browser history for AI service visits."""

    def __init__(self):
        self.db = get_thread_db()
        self._stop = threading.Event()
        self.last_check_times = {}  # profile_path -> last chrome timestamp
        self.chrome_dir = Path.home() / "Library" / "Application Support" / "Google" / "Chrome"

    def stop(self):
        self._stop.set()

    def _chrome_ts_to_iso(self, chrome_ts):
        """Convert Chrome timestamp (microseconds since 1601-01-01) to ISO string."""
        if not chrome_ts:
            return None
        try:
            unix_ts = chrome_ts / 1_000_000 - 11644473600
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except Exception:
            return None

    def _extract_conversation_id(self, url, service):
        """Extract conversation ID from AI service URLs."""
        try:
            parsed = urlparse(url)
            path = parsed.path
            if service == "ChatGPT" and "/c/" in path:
                return path.split("/c/")[-1].split("/")[0].split("?")[0]
            elif service == "Gemini" and "/app/" in path:
                return path.split("/app/")[-1].split("/")[0].split("?")[0]
            elif service == "Claude Web" and "/chat/" in path:
                return path.split("/chat/")[-1].split("/")[0].split("?")[0]
        except Exception:
            pass
        return None

    def _find_history_files(self):
        """Find all Chrome History files across all profiles."""
        if not self.chrome_dir.exists():
            return []
        paths = []
        for entry in self.chrome_dir.iterdir():
            if entry.is_dir() and (entry.name == "Default" or entry.name.startswith("Profile")):
                hist = entry / "History"
                if hist.exists():
                    paths.append(hist)
        return paths

    def scan_once(self):
        """Copy Chrome history DBs and query for new AI visits across all profiles."""
        history_files = self._find_history_files()
        if not history_files:
            return []

        all_found = []
        # Parameterized LIKE conditions for browser AI pattern matching
        url_placeholders = " OR ".join("urls.url LIKE ?" for _ in BROWSER_AI_PATTERNS)
        url_params = [f"%{domain}%" for domain in BROWSER_AI_PATTERNS]

        for hist_path in history_files:
            profile_key = str(hist_path)
            tmp_path = None
            try:
                tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
                os.close(tmp_fd)
                shutil.copy2(str(hist_path), tmp_path)

                conn = sqlite3.connect(tmp_path)
                conn.row_factory = sqlite3.Row

                last_check = self.last_check_times.get(profile_key, 0)
                if last_check == 0:
                    # First run: look back 7 days
                    cutoff = int((time.time() + 11644473600) * 1_000_000) - (7 * 24 * 3600 * 1_000_000)
                else:
                    cutoff = last_check

                query = f"""SELECT urls.url, urls.title, visits.visit_time, visits.visit_duration
                    FROM visits JOIN urls ON visits.url = urls.id
                    WHERE ({url_placeholders}) AND visits.visit_time > ?
                    ORDER BY visits.visit_time ASC"""  # nosec B608

                rows = conn.execute(query, url_params + [cutoff]).fetchall()

                for row in rows:
                    url = row["url"]
                    title = row["title"] or ""
                    visit_time = row["visit_time"]
                    duration = (row["visit_duration"] or 0) / 1_000_000

                    service = None
                    for domain, svc in BROWSER_AI_PATTERNS.items():
                        if domain in url:
                            service = svc
                            break
                    if not service:
                        continue

                    visit_iso = self._chrome_ts_to_iso(visit_time)
                    conv_id = self._extract_conversation_id(url, service)

                    try:
                        # Dedup: skip if same URL visited within 60 seconds
                        existing = self.db.execute(
                            """SELECT id FROM browser_sessions
                               WHERE url = ? AND ABS(strftime('%s', visit_time) - strftime('%s', ?)) < 60
                               LIMIT 1""",
                            (url, visit_iso),
                        ).fetchone()
                        if not existing:
                            self.db.execute(
                                """INSERT INTO browser_sessions
                                   (service, url, title, conversation_id, visit_time, duration_seconds)
                                   VALUES (?, ?, ?, ?, ?, ?)""",
                                (service, url, title, conv_id, visit_iso, duration),
                            )
                    except Exception:
                        pass

                    all_found.append(
                        {
                            "service": service,
                            "title": title,
                            "url": url,
                            "visit_time": visit_iso,
                            "duration": duration,
                            "conversation_id": conv_id,
                        }
                    )

                    if visit_time > self.last_check_times.get(profile_key, 0):
                        self.last_check_times[profile_key] = visit_time

                    push_live_event(
                        {
                            "timestamp": visit_iso,
                            "event_type": "browser_ai",
                            "source": "browser",
                            "summary": (
                                f"BROWSER: {service} — {title[:60]}" + (f" ({int(duration)}s)" if duration else "")
                            ),
                        }
                    )

                conn.close()

            except Exception:
                pass
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

        if all_found:
            try:
                self.db.commit()
            except Exception:
                pass

        return all_found

    def run_loop(self):
        """Poll Chrome history every 60 seconds."""
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(60)


# ─────────────────────────────────────────────────────────────
# SECTION 8: WEB DASHBOARD SERVER
# ─────────────────────────────────────────────────────────────

# `ReusableHTTPServer` (the threaded dashboard server) and the dual-stack
# loopback wrapper both live in `dashboard_server.py` — see issue #98
# (3rd gap) for the threading fix and the 2026-06-09 dual-stack hotfix
# for the v4+v6 loopback bind. Re-exported here for back-compat with
# consumers that import these names from `monitor`.
# `DashboardHandler` + `DASHBOARD_HTML` extracted to
# `dashboard_handler.py` (pure-move PR 2026-06-12, Rajan-ratified Path 1).
# Re-export so existing callers continue to import these names from
# `monitor`.
from claude_monitoring.dashboard_handler import (  # noqa: E402, F401
    DASHBOARD_HTML,
    DashboardHandler,
    _format_uptime,
)
from claude_monitoring.dashboard_server import (  # noqa: E402, F401
    LoopbackDualStackServer,
    ReusableHTTPServer,
    start_dashboard_server,
)

# ─────────────────────────────────────────────────────────────
# SECTION 10: INITIAL JSONL BACKFILL
# ─────────────────────────────────────────────────────────────


def backfill_existing_sessions(watcher):
    """Scan existing JSONL files and backfill the database."""
    count = 0
    for sessions_dir in (CLAUDE_PROJECTS_DIR, OPENCLAW_SESSIONS_DIR):
        if not sessions_dir.exists():
            continue
        for jsonl_file in sessions_dir.rglob("*.jsonl"):
            try:
                watcher.process_jsonl_file(str(jsonl_file))
                count += 1
            except Exception:
                continue
    return count


# ─────────────────────────────────────────────────────────────
# SECTION 10b: DISCOVERY SCHEDULER (re-export)
# ─────────────────────────────────────────────────────────────
# Live code in discovery_scheduler.py. Re-exported here so callers
# (tests, start_monitoring(), first-party consumers that monkeypatch
# monitor.X) keep working without source changes.
from claude_monitoring.cve_poll_scheduler import (  # noqa: E402
    cve_poll_loop as _cve_poll_loop,
)
from claude_monitoring.discovery_scheduler import (  # noqa: E402, F401
    DISCOVERY_CADENCE as _DISCOVERY_CADENCE,
)
from claude_monitoring.discovery_scheduler import (  # noqa: E402
    discovery_scheduler_loop as _discovery_scheduler_loop,
)
from claude_monitoring.discovery_scheduler import (  # noqa: E402
    finalize_crashed_runs_at_startup as _finalize_crashed_runs_at_startup,
)
from claude_monitoring.discovery_scheduler import (  # noqa: E402
    run_discover,
)

# ─────────────────────────────────────────────────────────────
# SECTION 11: MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────


def start_monitoring():
    """Start all monitoring layers and the web dashboard."""
    print("=" * 62)
    print("  AI Runtime Monitor — CrowdStrike-Style Full Visibility")
    print("=" * 62)

    # Phase 1: write monitor.pid + register atexit cleanup FIRST.
    # atexit is best-effort (won't run on SIGKILL/OOM) but still catches
    # Ctrl+C and normal exits. The real defense against crash-leaked
    # state is detect_stale_state() on the next --start.
    import atexit

    from claude_monitoring.lifecycle import (
        bind_with_retry,
        cleanup_for_shutdown,
        get_monitor_pid_file,
        write_heartbeat,
        write_pid_file,
    )

    write_pid_file(get_monitor_pid_file(), os.getpid())

    def _atexit_cleanup():
        # PID + system proxy off first, then the slower pm.stop(). The
        # signal handler unregisters this hook before its own cleanup
        # runs to avoid a double pm.stop() on a recycled PID.
        cleanup_for_shutdown(get_monitor_pid_file())
        pm = globals().get("_PROXY_MANAGER")
        if pm is not None:
            try:
                pm.stop(disable_proxy=False)  # proxy already off above
            except Exception:
                pass

    atexit.register(_atexit_cleanup)

    # Check dependencies
    missing = []
    if not psutil:
        missing.append("psutil")
    if Observer is None:
        missing.append("watchdog")
    if missing:
        print(f"\n  WARNING: Missing optional dependencies: {', '.join(missing)}")
        print(f"  Install with: pip3 install {' '.join(missing)}")
        if Observer is None:
            print("  watchdog is REQUIRED for JSONL monitoring. Exiting.")
            sys.exit(1)

    # Init database
    db_conn = init_db()
    db_conn.close()
    print(f"\n  Database: {DB_PATH}")

    # Security hardening (Sections 2/4): enforce permissions, ensure dashboard
    # token, purge old sensitive-data plaintext. Never fatal — the monitor
    # must still start even if one check fails.
    try:
        from claude_monitoring.security import (
            enforce_permissions,
            ensure_dashboard_token,
            purge_old_sensitive_data,
        )

        fixed = enforce_permissions()
        if fixed:
            print(f"  Permissions tightened: {', '.join(fixed)}")
        dashboard_token = ensure_dashboard_token()
        purge_conn = get_thread_db()
        try:
            scrubbed = purge_old_sensitive_data(purge_conn)
            if scrubbed:
                print(f"  Purged plaintext from {scrubbed} old sensitive alerts")
        finally:
            purge_conn.close()
    except Exception as exc:
        print(f"  WARNING: security hardening incomplete: {exc}")
        dashboard_token = None

    # Verify dedup integrity on startup
    check_db = get_thread_db()
    try:
        count = check_db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        distinct = check_db.execute(
            "SELECT COUNT(DISTINCT dedup_hash) FROM events WHERE dedup_hash IS NOT NULL"
        ).fetchone()[0]
        if count > 0 and distinct > 0 and count != distinct:
            dupes = count - distinct
            print(f"  Dedup check: found {dupes} duplicate events, cleaning up...")
            check_db.execute("""DELETE FROM events WHERE dedup_hash IS NOT NULL AND id NOT IN
                (SELECT MIN(id) FROM events GROUP BY dedup_hash)""")
            check_db.commit()
            print(f"  Cleaned {dupes} duplicates")
    except Exception:
        pass
    finally:
        check_db.close()

    # CodeQL py/clear-text-logging flag: tier is OAuth subscriptionType enum, not the token. Pattern B dismissal.
    info = detect_plan_info()
    if info["is_subscription"]:
        tier = info.get("plan_tier", "")
        print(f"  Plan: {tier}" if tier else "  Plan: Subscription")
    else:
        print("  Billing: API")

    # Layer 1a: JSONL Session Watcher
    jsonl_watcher = JSONLSessionWatcher()
    jsonl_handler = JSONLFileHandler(jsonl_watcher)
    jsonl_observer = Observer()

    if CLAUDE_PROJECTS_DIR.exists():
        jsonl_observer.schedule(jsonl_handler, str(CLAUDE_PROJECTS_DIR), recursive=True)
        print(f"  Watching JSONL: {CLAUDE_PROJECTS_DIR}")
    else:
        print(f"  WARNING: {CLAUDE_PROJECTS_DIR} not found — will retry on first activity")

    if OPENCLAW_SESSIONS_DIR.exists():
        jsonl_observer.schedule(jsonl_handler, str(OPENCLAW_SESSIONS_DIR), recursive=True)
        print(f"  Watching JSONL: {OPENCLAW_SESSIONS_DIR}")
    else:
        print("  OpenClaw sessions dir not found — will watch if created")

    # Backfill existing sessions in background
    def _backfill():
        n = backfill_existing_sessions(jsonl_watcher)
        print(f"  Backfill complete: {n} files processed")

    backfill_thread = threading.Thread(target=_backfill, daemon=True, name="Backfill")
    backfill_thread.start()
    print("  Backfilling existing sessions in background...")

    # Layer 2: File Activity Monitor
    file_handler = FileActivityHandler()
    file_observer = Observer()
    # We'll watch the current working directory as a start
    # Additional CWDs from active sessions will be added dynamically
    cwd = os.getcwd()
    file_observer.schedule(file_handler, cwd, recursive=True)
    print(f"  Watching files: {cwd}")

    # Layer 3: Process Scanner
    proc_scanner = ProcessScanner()
    proc_thread = threading.Thread(target=proc_scanner.run_loop, daemon=True, name="ProcessScanner")

    # Layer 1b: Network Monitor
    net_monitor = NetworkMonitor()
    net_thread = threading.Thread(target=net_monitor.run_loop, daemon=True, name="NetworkMonitor")

    # Layer 4: Chrome Browser History Watcher
    chrome_watcher = ChromeHistoryWatcher()
    chrome_thread = threading.Thread(target=chrome_watcher.run_loop, daemon=True, name="ChromeWatcher")

    # Start all observers and threads
    jsonl_observer.start()
    file_observer.start()
    proc_thread.start()
    net_thread.start()
    chrome_thread.start()
    print("  Process scanner: active (every 2s)")
    print("  Network monitor: active (every 5s)")
    chrome_profiles = chrome_watcher._find_history_files()
    if chrome_profiles:
        print(f"  Chrome AI watcher: active (every 60s, {len(chrome_profiles)} profile(s))")
    else:
        print("  Chrome AI watcher: Chrome history not found")

    # Web Dashboard — lifecycle wiring (single-server vs dual-stack-loopback)
    # lives in `dashboard_server.start_dashboard_server` so the file-size
    # ratchet on monitor.py stays under ceiling. See dashboard_server.py.
    server = start_dashboard_server(get_bind_address(), DASHBOARD_PORT, DashboardHandler, bind_with_retry)
    if dashboard_token:
        print(f"\n  Dashboard: http://localhost:{DASHBOARD_PORT}?token={dashboard_token}")
        print("  (Bookmark this URL — the token is remembered by the browser.)")
    else:
        print(f"\n  Dashboard: http://localhost:{DASHBOARD_PORT}")
    print("\n  Press Ctrl+C to stop")
    print("=" * 62)

    # Initial process scan
    procs = proc_scanner.scan_once()
    if procs:
        print(f"\n  Found {len(procs)} AI process(es) running:")
        for p in procs:
            print(f"    PID {p['pid']}: {p['name']} ({p['cpu_percent']}% CPU, {p['memory_percent']}% MEM)")
    print()

    # Keep main thread alive
    stop_event = threading.Event()

    # Phase 1: Watchdog thread. Polls ProxyManager every 30s. If mitmdump
    # died, disables system proxy and attempts restart (exponential backoff,
    # max 3 attempts). Writes heartbeat file every tick so external observers
    # (--status, other processes) can tell whether we're healthy or hung.
    #
    # Bug fix: the restart counter only resets after HEALTHY_TICKS_BEFORE_RESET
    # consecutive healthy polls (not on every successful restart). Otherwise
    # a flapping mitmdump restarts forever without the backoff ever kicking in,
    # leading to the 30-second flap loop we hit this week.
    HEALTHY_TICKS_BEFORE_RESET = 3

    def _watchdog_loop():
        healthy_streak = 0
        while not stop_event.is_set():
            write_heartbeat()
            pm = globals().get("_PROXY_MANAGER")
            # Issue #98 (4th gap): if the user invoked `--stop`, ProxyManager.stop()
            # set ``_stopped = True`` and SIGTERM'd mitmdump. WITHOUT this guard
            # the watchdog sees mitmdump's pid gone, can't distinguish "user
            # asked for shutdown" from "mitmdump crashed," and respawns it as
            # an orphan that outlives the monitor process. With the guard,
            # explicit shutdown is honored and the watchdog stays out of it.
            if pm is not None and not pm.is_alive() and not pm.was_explicitly_stopped():  # pragma: no cover
                # Closure inside start_monitoring; coverage applied via the
                # underlying lifecycle.handle_mitmdump_death_and_restart helper
                # (5 dedicated tests in tests/test_lifecycle.py).
                healthy_streak = 0
                from claude_monitoring.lifecycle import handle_mitmdump_death_and_restart

                result = handle_mitmdump_death_and_restart(pm)
                exit_suffix = f" ({result['exit_summary']})" if result["exit_summary"] else ""
                print(f"\n  ⚠ Watchdog: mitmdump died{exit_suffix} — disabling system proxy")
                if result["restarted"]:
                    print("  ✅ Watchdog: mitmdump restarted")
                    if result["proxy_restored"]:
                        print("  ✅ Watchdog: system proxy restored")
                else:
                    print("  ❌ Watchdog: max restart attempts reached — giving up")
            elif pm is not None and not pm.was_explicitly_stopped():
                healthy_streak += 1
                if healthy_streak >= HEALTHY_TICKS_BEFORE_RESET:
                    pm.reset_restart_count()
            stop_event.wait(30)

    watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True, name="Watchdog")
    watchdog_thread.start()

    # feat/daemon-discovery-scheduler: finalize crashed discovery_runs
    # before the scheduler launches, so the /api/assets envelope starts
    # clean regardless of whether the scheduler ever fires. The wrapper
    # handles conn open/close + fail-open + the operator-visible print;
    # extracted into discovery_scheduler so the wiring is unit-testable.
    _finalize_crashed_runs_at_startup()

    discovery_scheduler_thread = threading.Thread(
        target=_discovery_scheduler_loop, daemon=True, name="DiscoveryScheduler"
    )
    discovery_scheduler_thread.start()

    # P4.5: separate CVE-poll thread per spec §8.3 ("Separate from asset
    # discovery. Runs daily."). Reads the same schedule.toml (under
    # [cve_poll]) so operators have one config surface.
    cve_poll_thread = threading.Thread(target=_cve_poll_loop, daemon=True, name="CvePollScheduler")
    cve_poll_thread.start()

    def signal_handler(sig, frame):
        print("\n\n  Shutting down...")
        # PID file + system proxy off FIRST so if launchd KillTimeout
        # interrupts pm.stop() below, the next --start still sees clean
        # state. See docs/design/lifecycle-reliability.md.
        cleanup_for_shutdown(get_monitor_pid_file())
        atexit.unregister(_atexit_cleanup)  # avoid double pm.stop on exit
        pm = globals().get("_PROXY_MANAGER")
        if pm is not None:
            try:
                pm.stop(disable_proxy=False)  # proxy already off above
            except Exception:
                pass
        jsonl_watcher.stop()
        proc_scanner.stop()
        net_monitor.stop()
        chrome_watcher.stop()
        jsonl_observer.stop()
        file_observer.stop()
        server.shutdown()
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while not stop_event.is_set():
            stop_event.wait(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

    jsonl_observer.join(timeout=2)
    file_observer.join(timeout=2)
    print("  Stopped.\n")


def one_shot_scan():
    """Perform a one-time process and network scan."""
    print("\nAI Agent Process Scan")
    print("=" * 50)

    if not psutil:
        print("ERROR: psutil not installed. Run: pip3 install psutil")
        sys.exit(1)

    scanner = ProcessScanner()
    procs = scanner.scan_once()

    if not procs:
        print("  No AI agent processes found.")
    else:
        print(f"  Found {len(procs)} AI process(es):\n")
        for p in procs:
            print(
                f"  PID {p['pid']:>6}  {p['name']:<20} "
                f"CPU:{p['cpu_percent']:>5.1f}%  MEM:{p['memory_percent']:>5.1f}%  "
                f"Status:{p['status']}"
            )
            if p.get("cmdline"):
                print(f"           cmd: {p['cmdline'][:80]}")
    print()


def install_launch_agent():
    """Install as a macOS LaunchAgent for auto-start on login."""
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / "com.ai-monitor.agent.plist"

    python_path = sys.executable
    script_path = str(SCRIPT_PATH)
    log_path = str(OUTPUT_DIR / "ai_monitor.log")

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ai-monitor.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>{script_path}</string>
        <string>--start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{log_path}</string>
    <key>WorkingDirectory</key>
    <string>{str(Path.home())}</string>
</dict>
</plist>"""

    plist_path.write_text(plist_content)
    print(f"  Wrote: {plist_path}")

    result = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True, timeout=10)
    if result.returncode == 0:
        print("  LaunchAgent loaded successfully!")
        print(f"  Log: {log_path}")
        print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    else:
        print(f"  launchctl load failed: {result.stderr}")
        print(f"  Try manually: launchctl load {plist_path}")


def uninstall_launch_agent():
    """Remove the macOS LaunchAgent."""
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.ai-monitor.agent.plist"
    if not plist_path.exists():
        print("  LaunchAgent not found. Nothing to uninstall.")
        return

    subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True, timeout=10)
    plist_path.unlink()
    print("  LaunchAgent unloaded and removed.")


# ─────────────────────────────────────────────────────────────
# SECTION 12: CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────


def _update_port(port):
    global DASHBOARD_PORT
    DASHBOARD_PORT = port


def _resolve_version() -> str:
    """Return installed package version. Order: importlib.metadata, setuptools_scm, static fallback.
    Never raises — `--version` must print something rather than crash."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("ai-runtime-monitor")
    except (PackageNotFoundError, Exception):
        pass
    try:
        from setuptools_scm import get_version

        return get_version(root="../..", relative_to=__file__)
    except Exception:
        pass
    return "0.0.0+unknown"


def _preflight_proxy_start():
    """Pre-flight checks before spawning mitmdump. Returns ``(exit_code, stderr_message)``.
    Exit codes: 0 proceed, 2 mitmproxy missing, 3 CA not trusted; allow_hosts regression returns (0, warning)."""
    import importlib.util as _ilu

    if _ilu.find_spec("mitmproxy") is None:
        return 2, (
            "❌ Proxy mode requires mitmproxy, which is not installed in this environment.\n"
            "   Fix: pip install ai-runtime-monitor  (or, in this venv, pip install mitmproxy)\n"
            "   Then re-run: ai-monitor --start"
        )
    try:
        from claude_monitoring.security import get_ca_cert_path, verify_ca_trusted

        ok, code = verify_ca_trusted(get_ca_cert_path())
    except Exception:
        ok, code = False, "verification_error"
    if not ok:
        from claude_monitoring.security import trust_reason_message

        return 3, (
            "❌ Proxy mode requires the CA to be trusted in System.keychain admin trust settings.\n"
            f"   Current state: {trust_reason_message(code)}\n"
            "   Fix: ai-monitor --setup  (re-runs the wizard and verifies trust)\n"
            "   Refusing to enable the system proxy without trust — it would route\n"
            "   AI traffic through an untrusted CA and produce cert errors with\n"
            "   zero useful capture."
        )
    from claude_monitoring.constants import AI_BROWSER_DOMAINS, AI_PROXY_DOMAINS

    leaked = sorted(set(AI_PROXY_DOMAINS) & set(AI_BROWSER_DOMAINS))
    if leaked:
        return 0, (
            f"⚠ AI_PROXY_DOMAINS contains browser UI sites: {leaked}\n"
            "  These should be captured by the Chrome extension, not the proxy.\n"
            "  See claude_monitoring.constants comment for rationale.\n"
            "  Proceeding anyway, but this is a regression from PR #51."
        )
    return 0, None


def main():
    parser = argparse.ArgumentParser(description="AI Runtime Monitor — Full visibility into AI agent activity")
    parser.add_argument("--version", action="version", version=f"ai-monitor {_resolve_version()}")
    parser.add_argument("--start", action="store_true", help="Start monitoring and dashboard")
    parser.add_argument("--scan", action="store_true", help="One-shot process scan")
    parser.add_argument(
        "--install-agent", action="store_true", help="Install as macOS LaunchAgent (auto-start on login)"
    )
    parser.add_argument("--uninstall-agent", action="store_true", help="Remove macOS LaunchAgent")
    parser.add_argument("--port", type=int, default=DASHBOARD_PORT, help=f"Dashboard port (default: {DASHBOARD_PORT})")
    parser.add_argument("--init-config", action="store_true", help="Generate default config.toml")
    # Proxy on by default since PR #52; --with-proxy kept as no-op for backwards-compat.
    parser.add_argument(
        "--with-proxy",
        action="store_true",
        help="(default; flag retained for backwards-compat) Start HTTPS proxy for deep API capture",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Start the daemon without the HTTPS proxy (JSONL + extension capture only)",
    )
    parser.add_argument("--enable-system-proxy", action="store_true", help="Enable macOS system proxy")
    parser.add_argument("--disable-system-proxy", action="store_true", help="Disable macOS system proxy")
    parser.add_argument("--status", action="store_true", help="Show runtime status (monitor, proxy, cert, security)")
    parser.add_argument("--status-json", action="store_true", help="Show runtime status as JSON (for scripts)")
    parser.add_argument("--setup", action="store_true", help="Run the setup wizard. Idempotent (reuses valid CA).")
    parser.add_argument("--regenerate-ca", action="store_true", help="Modifier for --setup: force CA regeneration.")
    parser.add_argument("--cleanup", action="store_true", help="Remove duplicate captures, empty sessions, etc.")
    parser.add_argument("--dry-run", action="store_true", help="Modifier for --cleanup: preview without changes")
    parser.add_argument("--purge", action="store_true", help="Permanently uninstall and delete all monitoring data")
    parser.add_argument("--stop", action="store_true", help="Stop a running monitor + proxy cleanly (uses PID file)")
    parser.add_argument("--logs", action="store_true", help="Tail the monitor log file (Ctrl+C to exit)")
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode (no prompts, stdout→log)")
    parser.add_argument("--install-service", action="store_true", help="Install as a macOS LaunchAgent (runs at login)")
    parser.add_argument("--uninstall-service", action="store_true", help="Uninstall the LaunchAgent")
    parser.add_argument(
        "--with-system-proxy",
        action="store_true",
        help="Modifier for --install-service: auto-enable system proxy on start",
    )
    parser.add_argument("--restart", action="store_true", help="Stop + start the monitor (clean restart)")
    # P4.6: on-demand discovery scan per spec §8.1 ("CLI command: `vigil --discover`").
    # Runs once and exits; does NOT start the daemon. Writes a discovery_runs
    # row with trigger="on_demand" and emits a JSON summary on stdout.
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Run a one-shot on-demand discovery scan and exit (spec §8.1).",
    )

    args = parser.parse_args()

    # P4.6 dispatch — handle before the rest so we never start the daemon
    # accidentally on a `--discover` invocation.
    if args.discover:
        sys.exit(run_discover())

    if args.port != DASHBOARD_PORT:
        # Update the module-level port if overridden
        _update_port(args.port)

    if args.init_config:
        from claude_monitoring.config import generate_default_config

        path = generate_default_config()
        print(f"Config file generated at: {path}")
        print("Edit this file to customize ports, paths, and proxy settings.")
        sys.exit(0)
    elif args.install_agent:
        install_launch_agent()
    elif args.uninstall_agent:
        uninstall_launch_agent()
    elif args.enable_system_proxy:
        from claude_monitoring.config import get_proxy_port

        port = get_proxy_port()
        print(f"Enabling macOS system proxy → 127.0.0.1:{port}")
        print("Only AI API domains are inspected. All other traffic passes through untouched.")
        subprocess.run(
            ["networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", str(port)],
            check=False,
            timeout=10,
        )
        print("✅ System proxy enabled.")
        print("Run 'ai-monitor --disable-system-proxy' to disable.")
        sys.exit(0)
    elif args.disable_system_proxy:
        print("Disabling macOS system proxy...")
        subprocess.run(
            ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"],
            check=False,
            timeout=10,
        )
        print("✅ System proxy disabled.")
        sys.exit(0)
    elif args.status:
        from claude_monitoring.status import show_status

        sys.exit(show_status())
    elif args.status_json:
        from claude_monitoring.status import show_status_json

        sys.exit(show_status_json())
    elif args.setup:
        from claude_monitoring.wizard import run_setup_wizard

        sys.exit(0 if run_setup_wizard(force=args.regenerate_ca) else 1)
    elif args.cleanup:
        from claude_monitoring.cleanup import print_cleanup_summary, run_cleanup

        summary = run_cleanup(dry_run=args.dry_run)
        print_cleanup_summary(summary)
        sys.exit(0 if summary.get("ok") else 1)
    elif args.purge:
        from claude_monitoring.wizard import run_purge

        sys.exit(0 if run_purge() else 1)
    elif args.stop:
        # Phase 1: clean shutdown via PID file.
        from claude_monitoring.lifecycle import (
            ProxyManager,
            get_monitor_pid_file,
            is_pid_alive,
            read_pid_file,
        )

        monitor_pid = read_pid_file(get_monitor_pid_file())
        if monitor_pid and is_pid_alive(monitor_pid):
            print(f"Stopping monitor (PID {monitor_pid})...")
            try:
                os.kill(monitor_pid, signal.SIGTERM)
                print("✅ Monitor stop signal sent")
            except OSError as exc:
                print(f"⚠ Could not signal monitor: {exc}")
        else:
            print("Monitor is not running (no live PID file)")
        # Belt-and-suspenders: also kill any orphan mitmdump + disable proxy
        ProxyManager().stop(disable_proxy=True)
        print("✅ Proxy stopped and system proxy disabled")
        sys.exit(0)
    elif args.install_service:
        from claude_monitoring.lifecycle import install_service

        ok, msg = install_service(with_system_proxy=args.with_system_proxy)
        print(("✅ " if ok else "❌ ") + msg)
        if ok:
            print("The monitor will start on every login.")
            print("View logs:    ai-monitor --logs")
            print("Check status: ai-monitor --status")
            print("Uninstall:    ai-monitor --uninstall-service")
        sys.exit(0 if ok else 1)
    elif args.uninstall_service:
        from claude_monitoring.lifecycle import uninstall_service

        ok, msg = uninstall_service()
        print(("✅ " if ok else "❌ ") + msg)
        sys.exit(0 if ok else 1)
    elif args.restart:
        # Phase 3: restart via launchctl kickstart -k when the service is
        # installed. Falls back to a terminal-mode restart (old behavior)
        # when there's no LaunchAgent, so dev workflows still work.
        from claude_monitoring.lifecycle import (
            ProxyManager,
            get_monitor_pid_file,
            is_pid_alive,
            is_service_installed,
            read_pid_file,
            restart_service,
        )

        if is_service_installed():
            print("Restarting LaunchAgent service...")
            ok, msg = restart_service()
            print(("✅ " if ok else "❌ ") + msg)
            if ok:
                token_path = Path.home() / "claude_watch_output" / ".dashboard_token"
                if token_path.exists():
                    try:
                        token = token_path.read_text().strip()
                        print(f"  Dashboard: http://localhost:9081?token={token}")
                    except Exception:
                        pass
            sys.exit(0 if ok else 1)

        # No service installed — terminal-mode restart (dev workflow)
        mpid = read_pid_file(get_monitor_pid_file())
        if mpid and is_pid_alive(mpid):
            print(f"Stopping monitor (PID {mpid})...")
            try:
                os.kill(mpid, signal.SIGTERM)
            except OSError:
                pass
        ProxyManager().stop(disable_proxy=True)
        for _ in range(30):
            if not (mpid and is_pid_alive(mpid)):
                break
            time.sleep(0.2)
        print("Restarting monitor...")
        os.execvp(
            sys.executable,
            [sys.executable, "-m", "claude_monitoring.monitor", "--start", "--with-proxy"],
        )
    elif args.scan:
        one_shot_scan()
    elif args.logs:
        # Phase 2: tail the rotating log file so operators can see what
        # a daemon-mode monitor is doing without hunting through the FS.
        from claude_monitoring.lifecycle import get_log_path

        log_path = get_log_path()
        if not log_path.exists():
            print(f"No log file yet at {log_path}")
            print("Start the monitor with: ai-monitor --start")
            sys.exit(0)
        print(f"Tailing {log_path} (Ctrl+C to exit)\n")
        try:
            subprocess.run(["tail", "-f", str(log_path)])
        except KeyboardInterrupt:
            pass
        sys.exit(0)
    elif args.start:
        # Task #181 leg 3: refuse early if a healthy daemon is already
        # running (BEFORE detect_stale_state — which would SIGTERM the
        # running daemon's mitmdump as an "orphan"). 2026-06-10 regression.
        from claude_monitoring.lifecycle import refuse_if_already_running as _refuse

        _refuse()

        # Phase 2: in --daemon mode, redirect stdout/stderr to the log
        # file BEFORE anything else so every print() below lands in the
        # log rather than a detached TTY.
        if args.daemon:
            from claude_monitoring.lifecycle import redirect_stdio_to_log

            redirect_stdio_to_log()

        # Phase 1: stale state detection runs BEFORE anything else.
        # Load-bearing defense against orphaned mitmdump + stuck system
        # proxy from a previous crashed run. See lifecycle.detect_stale_state.
        from claude_monitoring.lifecycle import detect_stale_state

        stale_fixes = detect_stale_state()
        if stale_fixes:
            print("\n  ⚠ Cleaning up stale state from previous run:")
            for fix in stale_fixes:
                print(f"    • {fix}")
            print()

        # Phase 3: service mode honors the user's auto_enable_system_proxy pref.
        # This is how the user opts into "system proxy on every boot" — set
        # via `ai-monitor --install-service --with-system-proxy`.
        if args.daemon:
            from claude_monitoring.lifecycle import read_preferences

            prefs = read_preferences()
            if prefs.get("auto_enable_system_proxy"):
                from claude_monitoring.config import get_proxy_port

                subprocess.run(
                    [
                        "networksetup",
                        "-setsecurewebproxy",
                        "Wi-Fi",
                        "127.0.0.1",
                        str(get_proxy_port()),
                    ],
                    capture_output=True,
                    timeout=10,
                )

        # Section 8: first-run wizard. Skipped if .setup_complete already
        # exists. Users can re-run anytime via `ai-monitor --setup`.
        try:
            from claude_monitoring.wizard import is_first_run, run_setup_wizard

            if is_first_run():
                if args.daemon:
                    from claude_monitoring.lifecycle import get_logger

                    get_logger().error("daemon mode cannot run the interactive wizard — run ai-monitor --setup first")
                    sys.exit(2)
                if not run_setup_wizard():
                    sys.exit(1)
        except Exception as exc:
            print(f"  WARNING: setup wizard failed: {exc}")

        # PR #52: HTTPS proxy is on by default. --no-proxy is the opt-
        # out; --with-proxy is preserved as a no-op so existing scripts,
        # LaunchAgent plists, and docs keep working without a flag-not-
        # found error. The condition reads as 'start the proxy unless
        # the user explicitly disabled it'.
        proxy_enabled = not args.no_proxy
        if proxy_enabled:
            from claude_monitoring.config import get_proxy_port
            from claude_monitoring.lifecycle import ProxyManager

            _preflight_code, _preflight_msg = _preflight_proxy_start()
            if _preflight_msg:
                print(_preflight_msg, file=sys.stderr)
            if _preflight_code != 0:
                sys.exit(_preflight_code)

            # Phase 1: ProxyManager owns the mitmdump subprocess lifecycle.
            # It tracks the PID, gets health-checked by the watchdog, and
            # gets cleanly stopped on shutdown (disables system proxy too).
            _pm = ProxyManager()
            _pm.start()
            globals()["_PROXY_MANAGER"] = _pm
            print(f"Proxy started on port {get_proxy_port()} (AI domains only — selective SSL inspection)")
            print(f"To enable: export HTTPS_PROXY=http://127.0.0.1:{get_proxy_port()}")
            print("For desktop apps: ai-monitor --enable-system-proxy")
        start_monitoring()
    else:
        parser.print_help()
        print("\n  Quick start: python3 ai_monitor.py --start")


if __name__ == "__main__":
    main()
