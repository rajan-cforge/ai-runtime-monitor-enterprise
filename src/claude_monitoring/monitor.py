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
import csv
import hashlib
import io
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
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
    BROWSER_SERVICE_AGENT_MAP,
    PLAN_LIMITS,
    SERVICE_CLASSIFICATION,
    SEVERITY_ORDER,
    TOOL_RISK_MAP,
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


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _check_auth(self, path: str, params: dict) -> bool:
        """Return True when the request is authorized.

        Unauthenticated paths: the dashboard HTML itself (so users can bookmark
        localhost:9081 and paste their token), favicon, and CORS preflight.
        Everything under /api/ requires a valid token — either via
        ``?token=...`` query param or ``Authorization: Bearer ...`` header.
        """
        # HTML/static routes are open so the page can load and prompt for a token.
        if path == "/" or path.endswith(".html") or path == "/favicon.ico":
            return True
        # Loopback-only: DISABLE_DASHBOARD_AUTH=1 lets tests opt out.
        if os.environ.get("DISABLE_DASHBOARD_AUTH") == "1":
            return True
        presented = ""
        if params.get("token"):
            presented = params.get("token", [""])[0]
        if not presented:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                presented = auth_header[7:]
        if not presented:
            return False
        try:
            from claude_monitoring.security import verify_token

            return verify_token(presented)
        except Exception:
            return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        routes = {
            "/": self._serve_dashboard,
            "/api/sessions": self._api_sessions,
            "/api/session": self._api_session_detail,
            "/api/feed": self._api_feed,
            "/api/stats": self._api_stats,
            "/api/processes": self._api_processes,
            "/api/files": self._api_files,
            "/api/connections": self._api_connections,
            "/api/browser": self._api_browser,
            "/api/alerts": self._api_alerts,
            "/api/session_turns": self._api_session_turns,
            "/api/browser/sessions": self._api_browser_sessions,
            "/api/browser/session_detail": self._api_browser_session_detail,
            "/api/activity/timeline": self._api_activity_timeline,
            "/api/process_detail": self._api_process_detail,
            "/api/export": self._api_export,
            "/api/traffic": self._api_traffic,
            "/api/traffic/stats": self._api_traffic_stats,
            "/api/session_traffic": self._api_session_traffic,
            "/api/mcp/stats": self._api_mcp_stats,
            "/api/mcp/servers": self._api_mcp_servers,
            "/api/insights": self._api_insights,
            "/api/insights/projects": self._api_insights_projects,
            "/api/insights/efficiency": self._api_insights_efficiency,
            "/api/report": self._api_report,
            "/api/supply-chain": self._api_supply_chain,
            "/api/supply-chain/detail": self._api_supply_chain_detail,
            "/api/supply-chain/scan-status": self._api_supply_chain_scan_status,
            "/api/supply-chain/scan-progress": self._api_supply_chain_scan_progress,
            "/api/supply-chain/environment": self._api_supply_chain_environment,
            "/api/supply-chain/intel-status": self._api_supply_chain_intel_status,
            "/api/supply-chain/registry": self._api_supply_chain_registry,
            "/api/supply-chain/sbom": self._api_supply_chain_sbom,
            "/api/supply-chain/watchlist": self._api_supply_chain_watchlist,
            "/api/browser/extension-health": self._api_browser_extension_health,
        }

        # Match path prefixes for dynamic routes
        if path.startswith("/api/browser/session/"):
            params["conversation_id"] = [path.split("/api/browser/session/")[1]]
            path = "/api/browser/session_detail"
        elif path.startswith("/api/process/"):
            params["pid"] = [path.split("/api/process/")[1]]
            path = "/api/process_detail"
        elif path.startswith("/api/session/"):
            remainder = path.split("/api/session/")[1]
            if remainder.endswith("/turns"):
                params["id"] = [remainder[: -len("/turns")]]
                path = "/api/session_turns"
            elif remainder.endswith("/traffic"):
                params["id"] = [remainder[: -len("/traffic")]]
                path = "/api/session_traffic"
            else:
                params["id"] = [remainder]
                path = "/api/session"

        if not self._check_auth(path, params):
            self._send_json(
                {"error": "unauthorized", "hint": "include ?token=... from ~/claude_watch_output/.dashboard_token"}, 401
            )
            return

        handler = routes.get(path)
        if handler:
            try:
                handler(params)
            except BrokenPipeError:
                pass  # Client disconnected, nothing to do
            except Exception as e:
                try:
                    self._send_json({"error": str(e)}, 500)
                except BrokenPipeError:
                    pass
        else:
            self._send_json({"error": "not found", "path": path}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # /api/browser/ingest comes from the Chrome extension which cannot
        # easily attach a token — the extension runs in a separate origin and
        # loopback-only makes this an acceptable trade-off. Same for the
        # heartbeat endpoint added in Section 6.
        if path not in ("/api/browser/ingest", "/api/browser/heartbeat") and not self._check_auth(path, params):
            self._send_json({"error": "unauthorized"}, 401)
            return

        post_routes = {
            "/api/alerts/dismiss": self._api_alerts_dismiss,
            "/api/browser/ingest": self._api_browser_ingest,
            "/api/browser/heartbeat": self._api_browser_heartbeat,
            "/api/supply-chain/scan": self._api_supply_chain_scan_post,
            "/api/supply-chain/intel-refresh": self._api_supply_chain_intel_refresh,
        }

        handler = post_routes.get(path)
        if handler:
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length > 1_000_000:
                    self._send_json({"error": "payload too large"}, 413)
                    return
                body = self.rfile.read(length) if length else b""
                try:
                    payload = json.loads(body) if body else {}
                except (json.JSONDecodeError, ValueError):
                    self._send_json({"error": "invalid JSON"}, 400)
                    return
                handler(payload)
            except BrokenPipeError:
                pass
            except Exception as e:
                try:
                    self._send_json({"error": str(e)}, 500)
                except BrokenPipeError:
                    pass
        else:
            self._send_json({"error": "not found", "path": path}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _api_alerts_dismiss(self, payload):
        event_id = payload.get("event_id")
        reason = payload.get("reason", "")
        if event_id is None:
            self._send_json({"error": "event_id is required"}, 400)
            return
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            self._send_json({"error": "event_id must be an integer"}, 400)
            return
        db = get_thread_db()
        row = db.execute(
            "SELECT id FROM events WHERE id=? AND event_type='sensitive_data'",
            (event_id,),
        ).fetchone()
        if not row:
            self._send_json({"error": "event not found"}, 404)
            return
        now = datetime.now(timezone.utc).isoformat()
        try:
            db.execute(
                "INSERT INTO alert_dismissals (event_id, dismissed_at, reason) VALUES (?, ?, ?)",
                (event_id, now, reason),
            )
            db.commit()
        except sqlite3.IntegrityError:
            self._send_json({"error": "alert already dismissed"}, 409)
            return
        self._send_json({"ok": True, "event_id": event_id, "dismissed_at": now})

    def _api_browser_heartbeat(self, payload):
        """Section 6: receive 60s heartbeats from extension content scripts.

        Body: { hostname, user_matches, assistant_matches, captures_sent,
                selector_failure }

        We UPSERT one row per hostname so the table stays small. The
        /api/browser/extension-health endpoint reads the latest row and
        decides if a warning should be shown in the dashboard.
        """
        if not isinstance(payload, dict):
            self._send_json({"error": "expected JSON object"}, 400)
            return
        hostname = str(payload.get("hostname", ""))[:64]
        if not hostname:
            self._send_json({"error": "hostname required"}, 400)
            return
        user_m = int(payload.get("user_matches", 0) or 0)
        asst_m = int(payload.get("assistant_matches", 0) or 0)
        captures = int(payload.get("captures_sent", 0) or 0)
        failure = 1 if payload.get("selector_failure") else 0
        now = datetime.now(timezone.utc).isoformat()
        db = get_thread_db()
        try:
            db.execute(
                """INSERT INTO extension_heartbeats
                       (hostname, last_seen, user_matches, assistant_matches,
                        captures_sent, selector_failure)
                       VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(hostname) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       user_matches=excluded.user_matches,
                       assistant_matches=excluded.assistant_matches,
                       captures_sent=excluded.captures_sent,
                       selector_failure=excluded.selector_failure""",
                (hostname, now, user_m, asst_m, captures, failure),
            )
            db.commit()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
            return
        self._send_json({"ok": True, "hostname": hostname, "last_seen": now})

    def _api_browser_extension_health(self, params):
        """Return per-host heartbeat status with stale/failure flags.

        Used by the dashboard to render a yellow warning banner when an
        extension on claude.ai or chatgpt.com hasn't reported in for 5+
        minutes or is reporting zero selector matches.
        """
        db = get_thread_db()
        try:
            rows = db.execute(
                "SELECT hostname, last_seen, user_matches, assistant_matches, "
                "captures_sent, selector_failure FROM extension_heartbeats"
            ).fetchall()
        except Exception:
            self._send_json({"hosts": [], "warnings": []})
            return
        now = datetime.now(timezone.utc)
        hosts = []
        warnings = []
        for r in rows:
            try:
                last_seen = datetime.fromisoformat(r["last_seen"])
            except Exception:
                continue
            stale_seconds = (now - last_seen).total_seconds()
            user_m = r["user_matches"] or 0
            asst_m = r["assistant_matches"] or 0
            failure = bool(r["selector_failure"])
            entry = {
                "hostname": r["hostname"],
                "last_seen": r["last_seen"],
                "stale_seconds": int(stale_seconds),
                "user_matches": user_m,
                "assistant_matches": asst_m,
                "captures_sent": r["captures_sent"] or 0,
                "selector_failure": failure,
                "is_stale": stale_seconds > 300,
                "is_zero_matches": (user_m + asst_m) == 0,
            }
            hosts.append(entry)
            if entry["is_stale"]:
                warnings.append(
                    f"Extension on {r['hostname']} has not reported for "
                    f"{int(stale_seconds // 60)} minutes — content capture may be stale."
                )
            elif entry["is_zero_matches"] or failure:
                warnings.append(
                    f"Extension on {r['hostname']} reports zero selector matches — "
                    "the AI provider may have changed their DOM. Content capture is failing."
                )
        self._send_json({"hosts": hosts, "warnings": warnings})

    def _api_browser_ingest(self, payload):
        """Receive browser capture events from the Chrome extension."""
        events = payload.get("events", [])
        if not isinstance(events, list) or len(events) > 100:
            self._send_json({"error": "events must be a list of max 100 items"}, 400)
            return

        db = get_thread_db()
        stored = 0
        alerts = 0

        for ev in events:
            if not isinstance(ev, dict):
                continue
            service = ev.get("service", "")
            url = ev.get("url", "")
            text = ev.get("text", "")
            ev_type = ev.get("type", "")
            timestamp = ev.get("timestamp", now_iso())
            conv_id = ev.get("conversation_id")
            title = ev.get("title", "")

            if not service or not ev_type:
                continue

            # P1-02: sanitize raw text before storage. Extension payloads
            # can contain user prompts with plaintext credentials (API
            # keys pasted into a chat box, AWS keys in tool outputs
            # rendered inside claude.ai). The DB must never persist the
            # raw secret — anyone with read access to monitor.db would
            # get usable credentials. Run scan_sensitive first; for
            # every match, inline-replace the matched bytes with
            # mask_value() so conversation context survives but the
            # credential itself is redacted.
            sanitized_text = text
            early_matches = []
            if text:
                early_matches = scan_sensitive(text[:5000])
                if early_matches:
                    from claude_monitoring.security import mask_value

                    sanitized_text = text[:5000]
                    for m in early_matches:
                        raw = m.get("matched_value") or ""
                        if raw and raw in sanitized_text:
                            sanitized_text = sanitized_text.replace(raw, mask_value(raw))

            # Content-based dedup: hash first 200 chars of the SANITIZED
            # text. Dedup on sanitized content avoids the edge case where
            # the same credential appears twice with different surrounding
            # context — the masked form collapses both into one row.
            content_hash = None
            if sanitized_text:
                content_hash = hashlib.sha256(sanitized_text[:200].encode()).hexdigest()[:16]
                recent = db.execute(
                    """SELECT id FROM browser_sessions
                       WHERE conversation_id = ? AND event_type = ?
                       AND (content_hash = ? OR substr(content_text, 1, 200) = ?)
                       AND visit_time > datetime(?, '-7 days')
                       LIMIT 1""",
                    (conv_id, ev_type, content_hash, sanitized_text[:200], timestamp),
                ).fetchone()
                if recent:
                    continue

            try:
                db.execute(
                    """INSERT INTO browser_sessions
                       (service, url, title, conversation_id,
                        visit_time, duration_seconds, source, event_type, content_text, content_hash)
                       VALUES (?, ?, ?, ?, ?, 0, 'extension', ?, ?, ?)""",
                    (
                        service,
                        url,
                        title,
                        conv_id,
                        timestamp,
                        ev_type,
                        sanitized_text[:5000] if sanitized_text else None,
                        content_hash,
                    ),
                )
                stored += 1
                # Push to live feed.
                # Normalize event_type so the Live Feed label is derived from the
                # canonical type (user_prompt / assistant_response) rather than
                # lumping everything under "browser_ai" — that caused the Live Feed
                # to show identical labels for prompts and responses captured via
                # the browser extension.
                if ev_type in ("user_prompt", "user", "prompt"):
                    feed_event_type = "user_prompt"
                elif ev_type in ("assistant_response", "assistant", "response"):
                    feed_event_type = "assistant_response"
                else:
                    feed_event_type = "browser_ai"
                push_live_event(
                    {
                        "timestamp": timestamp,
                        "session_id": "browser_" + (conv_id or ""),
                        "event_type": feed_event_type,
                        "source": "browser",
                        "service": service,
                        "summary": f"{service}: {(sanitized_text or '')[:80]}",
                    }
                )
            except Exception:
                continue

            # P1-02: reuse the matches found during the sanitization pass
            # above. Storing the alert event with raw matched_value/snippet
            # would defeat the purpose of the sanitization — mask them
            # here the same way _check_sensitive does on the JSONL path.
            if early_matches:
                from claude_monitoring.security import hash_value, mask_value

                alerts += len(early_matches)
                session_id = "browser_" + (conv_id or "unknown")
                matched_value = early_matches[0].get("matched_value", "") or ""
                masked_value = mask_value(matched_value)
                severity = min(
                    (m.get("severity", "medium") for m in early_matches),
                    key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 99),
                )
                confidence = "high" if ev_type == "user_prompt" else "medium"
                # Snippet comes from the already-sanitized text so no raw
                # credentials land in the events row either.
                safe_snippet = (sanitized_text or "")[:200]
                data_json = json.dumps(
                    {
                        "patterns": [m["name"] for m in early_matches],
                        "severity": severity,
                        "categories": list({m.get("category", "credential") for m in early_matches}),
                        "context": f"browser_{ev_type}",
                        "snippet": safe_snippet,
                        "matched_value": masked_value,
                        "matched_hash": hash_value(matched_value),
                        "confidence": confidence,
                        "likely_false_positive": False,
                    }
                )
                dedup_key = f"{session_id}|{timestamp}|{[m['name'] for m in early_matches]}"
                dedup_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]
                try:
                    db.execute(
                        """INSERT OR IGNORE INTO events
                           (timestamp, session_id, event_type, source_layer, data_json, dedup_hash)
                           VALUES (?, ?, 'sensitive_data', 'browser', ?, ?)""",
                        (timestamp, session_id, data_json, dedup_hash),
                    )
                except Exception:
                    pass

        if stored > 0:
            try:
                db.commit()
            except Exception:
                pass

        self._send_json({"stored": stored, "alerts": alerts})

    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _serve_dashboard(self, params):
        self._send_html(DASHBOARD_HTML)

    def _api_sessions(self, params):
        db = get_thread_db()
        q = params.get("q", [""])[0].strip()
        sort = params.get("sort", ["recent"])[0]
        limit = int(params.get("limit", ["200"])[0])

        sort_map = {
            "recent": "last_activity DESC",
            "newest": "start_time DESC",
            "turns": "total_turns DESC",
            "tokens": "total_input_tokens DESC",
        }
        order = sort_map.get(sort, "last_activity DESC")

        if q:
            sql = f"""SELECT session_id, start_time, cwd, model,
                          total_input_tokens, total_output_tokens, total_turns,
                          jsonl_path, last_activity, title, agent_type
                   FROM sessions
                   WHERE title LIKE ? OR session_id LIKE ? OR cwd LIKE ? OR model LIKE ?
                   ORDER BY {order} LIMIT ?"""  # nosec B608
            rows = db.execute(sql, (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%", limit)).fetchall()
        else:
            sql = f"""SELECT session_id, start_time, cwd, model,
                          total_input_tokens, total_output_tokens, total_turns,
                          jsonl_path, last_activity, title, agent_type
                   FROM sessions ORDER BY {order} LIMIT ?"""  # nosec B608
            rows = db.execute(sql, (limit,)).fetchall()
        sessions = [dict(r) for r in rows]

        # Add source field to CLI sessions
        for s in sessions:
            s["source"] = "cli"

        # Batch-fetch alert counts + severity breakdown per session for risk scoring
        session_ids = [s["session_id"] for s in sessions]
        if session_ids:
            placeholders = ",".join("?" * len(session_ids))
            alert_sql = f"""SELECT session_id, COUNT(*) as cnt FROM events
                    WHERE event_type='sensitive_data' AND session_id IN ({placeholders})
                    GROUP BY session_id"""  # nosec B608
            alert_rows = db.execute(alert_sql, session_ids).fetchall()
            alert_map = {r["session_id"]: r["cnt"] for r in alert_rows}

            # Severity breakdown for risk scoring
            sev_sql = f"""SELECT session_id,
                        json_extract(data_json, '$.severity') as sev, COUNT(*) as cnt
                    FROM events
                    WHERE event_type='sensitive_data' AND session_id IN ({placeholders})
                    GROUP BY session_id, sev"""  # nosec B608
            sev_rows = db.execute(sev_sql, session_ids).fetchall()
            sev_map = {}  # session_id -> {critical: N, high: N, ...}
            for r in sev_rows:
                sid = r["session_id"]
                if sid not in sev_map:
                    sev_map[sid] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                sev_map[sid][r["sev"] or "medium"] = r["cnt"]

            risk_weights = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}
            for s in sessions:
                s["alert_count"] = alert_map.get(s["session_id"], 0)
                sevs = sev_map.get(s["session_id"], {"critical": 0, "high": 0, "medium": 0, "low": 0})
                s["alert_counts"] = sevs
                score = sum(sevs.get(k, 0) * v for k, v in risk_weights.items())
                s["risk_score"] = round(score, 1)
                s["risk_level"] = (
                    "critical" if score >= 20 else "high" if score >= 10 else "medium" if score >= 3 else "low"
                )

        # Optionally include browser sessions
        include_browser = params.get("include_browser", ["false"])[0].lower() == "true"
        source_filter = params.get("source", [""])[0].lower()

        if include_browser or source_filter in ("all", "browser"):
            browser_rows = db.execute(
                """SELECT conversation_id, service,
                          MIN(visit_time) as start_time,
                          MAX(visit_time) as last_activity,
                          COUNT(*) as total_turns,
                          COALESCE((strftime('%s', MAX(visit_time)) - strftime('%s', MIN(visit_time))), 0) as total_duration,
                          (SELECT b2.title FROM browser_sessions b2
                           WHERE b2.conversation_id = browser_sessions.conversation_id
                             AND b2.title IS NOT NULL AND b2.title != ''
                             AND b2.title != b2.service
                           ORDER BY b2.visit_time DESC LIMIT 1) as title
                   FROM browser_sessions
                   WHERE conversation_id IS NOT NULL AND conversation_id != ''
                   GROUP BY conversation_id
                   ORDER BY last_activity DESC
                   LIMIT 50"""
            ).fetchall()

            for r in browser_rows:
                rd = dict(r)
                sessions.append(
                    {
                        "session_id": "browser_" + (rd["conversation_id"] or ""),
                        "conversation_id": rd["conversation_id"],
                        "source": "browser",
                        "start_time": rd["start_time"],
                        "last_activity": rd["last_activity"],
                        "title": rd["title"] or rd["service"],
                        "model": rd["service"],
                        "service": rd["service"],
                        "cwd": "",
                        "total_input_tokens": 0,
                        "total_output_tokens": 0,
                        "total_turns": rd["total_turns"],
                        "total_duration": rd["total_duration"],
                        "alert_count": 0,
                        "agent_type": BROWSER_SERVICE_AGENT_MAP.get(rd["service"], "unknown"),
                    }
                )

        # Bug 1: Desktop AI apps (ChatGPT.app, Claude Desktop, Cursor) are
        # written to the sessions table by ProcessScanner._ensure_desktop_session
        # with agent_type in ('chatgpt_desktop','claude_desktop','cursor_desktop').
        # We tag those sessions with source='desktop' and enrich them with
        # live api_call stats so the detail panel can show real traffic.
        DESKTOP_AGENT_TYPES = {"chatgpt_desktop", "claude_desktop", "cursor_desktop"}
        AGENT_TO_SERVICES = {
            "chatgpt_desktop": ("chatgpt_web", "openai_api"),
            "claude_desktop": ("claude_web", "anthropic_api"),
            "cursor_desktop": ("cursor_api",),
        }
        for s in sessions:
            if s.get("agent_type") in DESKTOP_AGENT_TYPES:
                s["source"] = "desktop"
                # Enrich with api_calls aggregates for the relevant services
                services = AGENT_TO_SERVICES.get(s["agent_type"], ())
                if services:
                    try:
                        placeholders = ",".join(["?"] * len(services))
                        row = db.execute(
                            f"""SELECT COUNT(*) as n,
                                       COALESCE(SUM(input_tokens),0) as in_tok,
                                       COALESCE(SUM(output_tokens),0) as out_tok,
                                       MIN(timestamp) as first_ts,
                                       MAX(timestamp) as last_ts
                                FROM api_calls
                                WHERE destination_service IN ({placeholders})""",  # nosec B608
                            list(services),
                        ).fetchone()
                        if row and row["n"]:
                            s["total_turns"] = row["n"]
                            s["total_input_tokens"] = row["in_tok"] or 0
                            s["total_output_tokens"] = row["out_tok"] or 0
                            # Only update activity if we have newer data
                            if row["last_ts"] and (not s.get("last_activity") or row["last_ts"] > s["last_activity"]):
                                s["last_activity"] = row["last_ts"]
                            if row["first_ts"] and (not s.get("start_time") or row["first_ts"] < s["start_time"]):
                                s["start_time"] = row["first_ts"]
                    except Exception:
                        pass

        # Filter by source if requested
        if source_filter and source_filter not in ("all", ""):
            sessions = [s for s in sessions if s.get("source") == source_filter]

        # Re-sort mixed list
        if include_browser or source_filter in ("all", "desktop"):
            sort_key = {"recent": "last_activity", "newest": "start_time"}.get(sort, "last_activity")
            sessions.sort(key=lambda s: s.get(sort_key, "") or "", reverse=True)

        self._send_json({"sessions": sessions})

    def _api_session_detail(self, params):
        session_id = params.get("id", [""])[0]
        if not session_id:
            self._send_json({"error": "missing session id"}, 400)
            return

        db = get_thread_db()

        # Get session info
        session = db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if not session:
            self._send_json({"error": "session not found"}, 404)
            return

        # Get all events for this session, ordered by timestamp
        events = db.execute(
            """SELECT id, timestamp, event_type, source_layer, data_json
               FROM events WHERE session_id=? ORDER BY id ASC""",
            (session_id,),
        ).fetchall()

        event_list = []
        for e in events:
            try:
                data = json.loads(e["data_json"])
            except (json.JSONDecodeError, TypeError):
                data = {}
            event_list.append(
                {
                    "id": e["id"],
                    "timestamp": e["timestamp"],
                    "event_type": e["event_type"],
                    "source": e["source_layer"],
                    "data": data,
                }
            )

        # Enrich with tool risk annotations
        for ev in event_list:
            if ev["event_type"] == "tool_use":
                tool_name = ev["data"].get("name", "")
                risk_info = TOOL_RISK_MAP.get(tool_name)
                if risk_info:
                    ev["data"]["risk_level"] = risk_info[0]
                    ev["data"]["risk_description"] = risk_info[1]

        # Enrichments for OpenClaw sessions
        session_dict = dict(session)
        enrichments = {}
        if session_dict.get("agent_type") == "openclaw":
            # Detect channel from first user_prompt event
            for ev in event_list:
                if ev["event_type"] == "user_prompt":
                    text = ev["data"].get("text", "")
                    channel = self._watcher_detect_channel(text)
                    if channel:
                        enrichments["channel"] = channel
                        break

            # Aggregate cost from api_calls
            cost_row = db.execute(
                "SELECT SUM(estimated_cost_usd) as total_cost, COUNT(*) as api_call_count "
                "FROM api_calls WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if cost_row:
                enrichments["total_cost"] = cost_row["total_cost"] or 0
                enrichments["api_call_count"] = cost_row["api_call_count"] or 0

        # Desktop synthetic sessions (chatgpt_desktop, claude_desktop,
        # cursor_desktop) are Electron wrappers that route traffic through
        # the system proxy. Their conversation bodies are SSE / protobuf
        # that we cannot parse, so we surface network activity instead:
        # totals, daily breakdown, peak hour, top hosts — the kind of
        # information a SOC analyst actually wants to correlate with
        # other events.
        DESKTOP_AGENT_TYPES = {"chatgpt_desktop", "claude_desktop", "cursor_desktop"}
        if session_dict.get("agent_type") in DESKTOP_AGENT_TYPES:
            agent_type = session_dict["agent_type"]
            # Match api_calls rows by service AND by host substring —
            # host-matching catches any call that wasn't recognized by
            # detect_service but still came from our target app's
            # upstream endpoints.
            agent_match = {
                "chatgpt_desktop": {
                    "services": ("chatgpt_web", "openai_api"),
                    "host_patterns": ("chatgpt.com", "api.openai.com"),
                    "display_name": "ChatGPT Desktop",
                },
                "claude_desktop": {
                    "services": ("claude_web", "anthropic_api"),
                    "host_patterns": ("claude.ai", "api.anthropic.com"),
                    "display_name": "Claude Desktop",
                },
                "cursor_desktop": {
                    "services": ("cursor_api",),
                    "host_patterns": ("cursor.sh", "cursor.com"),
                    "display_name": "Cursor",
                },
            }
            matcher = agent_match.get(agent_type, {})
            services = matcher.get("services", ())
            host_patterns = matcher.get("host_patterns", ())

            if services or host_patterns:
                try:
                    svc_placeholders = ",".join(["?"] * max(len(services), 1))
                    host_clauses = " OR ".join(["destination_host LIKE ?"] * len(host_patterns))
                    where_parts = []
                    params: list[object] = []
                    if services:
                        where_parts.append(f"destination_service IN ({svc_placeholders})")
                        params.extend(services)
                    if host_clauses:
                        where_parts.append(f"({host_clauses})")
                        params.extend(f"%{p}%" for p in host_patterns)
                    where_sql = " OR ".join(where_parts) if where_parts else "1=0"

                    # Totals + first/last timestamps in one pass
                    agg = db.execute(
                        f"""SELECT
                              COUNT(*) as call_count,
                              COALESCE(SUM(input_tokens), 0) as in_tok,
                              COALESCE(SUM(output_tokens), 0) as out_tok,
                              COALESCE(SUM(request_size_bytes), 0) as req_bytes,
                              COALESCE(SUM(response_size_bytes), 0) as resp_bytes,
                              COALESCE(SUM(estimated_cost_usd), 0) as total_cost,
                              COALESCE(AVG(latency_ms), 0) as avg_latency,
                              MIN(timestamp) as first_ts,
                              MAX(timestamp) as last_ts
                           FROM api_calls
                           WHERE {where_sql}""",  # nosec B608
                        params,
                    ).fetchone()

                    call_count = (agg and agg["call_count"]) or 0
                    if call_count:
                        session_dict["total_turns"] = call_count
                        session_dict["total_input_tokens"] = agg["in_tok"] or 0
                        session_dict["total_output_tokens"] = agg["out_tok"] or 0
                        if agg["first_ts"]:
                            session_dict["start_time"] = agg["first_ts"]
                        if agg["last_ts"]:
                            session_dict["last_activity"] = agg["last_ts"]
                        enrichments["bytes_in"] = agg["req_bytes"] or 0
                        enrichments["bytes_out"] = agg["resp_bytes"] or 0
                        enrichments["total_cost"] = agg["total_cost"] or 0
                        enrichments["api_call_count"] = call_count

                        # Daily activity for the last 14 days
                        daily = db.execute(
                            f"""SELECT
                                  substr(timestamp, 1, 10) as day,
                                  COUNT(*) as calls,
                                  COALESCE(SUM(response_size_bytes), 0) as bytes_down
                               FROM api_calls
                               WHERE {where_sql}
                               GROUP BY day
                               ORDER BY day DESC
                               LIMIT 14""",  # nosec B608
                            params,
                        ).fetchall()

                        # Peak hour — the single hour with the most calls
                        peak = db.execute(
                            f"""SELECT
                                  substr(timestamp, 1, 13) as hour,
                                  COUNT(*) as calls
                               FROM api_calls
                               WHERE {where_sql}
                               GROUP BY hour
                               ORDER BY calls DESC
                               LIMIT 1""",  # nosec B608
                            params,
                        ).fetchone()

                        # Top hosts — most-hit destinations
                        top_hosts = db.execute(
                            f"""SELECT
                                  destination_host as host,
                                  COUNT(*) as calls,
                                  COALESCE(SUM(request_size_bytes + response_size_bytes), 0) as bytes_total
                               FROM api_calls
                               WHERE {where_sql}
                               GROUP BY destination_host
                               ORDER BY calls DESC
                               LIMIT 5""",  # nosec B608
                            params,
                        ).fetchall()

                        enrichments["activity_summary"] = {
                            "total_calls": call_count,
                            "bytes_up": agg["req_bytes"] or 0,
                            "bytes_down": agg["resp_bytes"] or 0,
                            "avg_latency_ms": int(agg["avg_latency"] or 0),
                            "active_since": agg["first_ts"],
                            "last_activity": agg["last_ts"],
                            "daily": [
                                {
                                    "date": d["day"],
                                    "calls": d["calls"],
                                    "bytes": d["bytes_down"] or 0,
                                }
                                for d in daily
                            ],
                            "peak_hour": (
                                {"hour": peak["hour"], "calls": peak["calls"]} if peak and peak["hour"] else None
                            ),
                            "top_hosts": [
                                {"host": h["host"], "calls": h["calls"], "bytes": h["bytes_total"] or 0}
                                for h in top_hosts
                            ],
                        }
                        enrichments["traffic_captured"] = True
                    else:
                        # Zero rows — Cursor typically lands here because its
                        # Electron stack bypasses the system proxy. Signal to
                        # the frontend so it can show a configuration hint
                        # instead of an empty summary.
                        enrichments["traffic_captured"] = False
                        enrichments["activity_summary"] = {
                            "total_calls": 0,
                            "bytes_up": 0,
                            "bytes_down": 0,
                            "avg_latency_ms": 0,
                            "active_since": None,
                            "last_activity": None,
                            "daily": [],
                            "peak_hour": None,
                            "top_hosts": [],
                        }
                except Exception:
                    pass
                enrichments["is_desktop_session"] = True
                enrichments["desktop_agent_type"] = agent_type

        self._send_json(
            {
                "session": session_dict,
                "events": event_list,
                **enrichments,
            }
        )

    @staticmethod
    def _watcher_detect_channel(text):
        """Detect OpenClaw channel from user prompt text."""
        if not text or "untrusted metadata" not in text:
            return None
        if "sender_id" in text and "message_id" in text:
            return "Telegram"
        if "discord" in text.lower():
            return "Discord"
        if "slack" in text.lower():
            return "Slack"
        return None

    def _api_session_turns(self, params):
        session_id = params.get("id", [""])[0]
        if not session_id:
            self._send_json({"error": "missing session id"}, 400)
            return

        db = get_thread_db()
        session = db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if not session:
            self._send_json({"error": "not found"}, 404)
            return

        events = db.execute(
            """SELECT id, timestamp, event_type, source_layer, data_json
               FROM events WHERE session_id=? ORDER BY id ASC""",
            (session_id,),
        ).fetchall()

        turns = []
        current_turn = None
        turn_num = 0
        cumulative_input = 0
        cumulative_output = 0

        for e in events:
            try:
                data = json.loads(e["data_json"]) if e["data_json"] else {}
            except (json.JSONDecodeError, TypeError):
                data = {}
            evt = {"id": e["id"], "timestamp": e["timestamp"], "event_type": e["event_type"], "data": data}

            if e["event_type"] == "user_prompt":
                if current_turn:
                    turns.append(current_turn)
                turn_num += 1
                current_turn = {
                    "turn_number": turn_num,
                    "timestamp": e["timestamp"],
                    "prompt_preview": JSONLSessionWatcher._clean_title(data.get("text", "") or "")[:80],
                    "events": [evt],
                    "tools_used": [],
                    "has_alert": False,
                    "token_delta": {"input": 0, "output": 0},
                    "cumulative_tokens": {"input": cumulative_input, "output": cumulative_output},
                }
            elif current_turn:
                current_turn["events"].append(evt)
                if e["event_type"] == "tool_use":
                    current_turn["tools_used"].append(data.get("name", ""))
                elif e["event_type"] == "token_usage":
                    inp = data.get("input_tokens", 0) or 0
                    out = data.get("output_tokens", 0) or 0
                    current_turn["token_delta"] = {"input": inp, "output": out}
                    cumulative_input += inp
                    cumulative_output += out
                    current_turn["cumulative_tokens"] = {"input": cumulative_input, "output": cumulative_output}
                elif e["event_type"] == "sensitive_data":
                    current_turn["has_alert"] = True

        if current_turn:
            turns.append(current_turn)

        self._send_json(
            {
                "session": dict(session),
                "turns": turns,
                "total_turns": turn_num,
                "total_input": cumulative_input,
                "total_output": cumulative_output,
            }
        )

    def _api_feed(self, params):
        since = params.get("since", [""])[0]
        limit = int(params.get("limit", ["50"])[0])

        with live_feed_lock:
            items = list(live_feed)

        if since:
            items = [i for i in items if i.get("timestamp", "") > since]

        items = items[-limit:]
        self._send_json({"events": items})

    def _api_stats(self, params):
        db = get_thread_db()

        total_sessions = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_input = db.execute("SELECT COALESCE(SUM(total_input_tokens), 0) FROM sessions").fetchone()[0]
        total_output = db.execute("SELECT COALESCE(SUM(total_output_tokens), 0) FROM sessions").fetchone()[0]
        total_alerts = db.execute("SELECT COUNT(*) FROM events WHERE event_type='sensitive_data'").fetchone()[0]

        # Active processes count
        active_procs = 0
        if psutil:
            try:
                for proc in psutil.process_iter(["name", "cmdline"]):
                    try:
                        name = proc.info.get("name") or ""
                        cmdline_str = " ".join(proc.info.get("cmdline") or [])
                        if is_ai_process(name, cmdline_str):
                            active_procs += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass

        # Token usage over time (last 24h, grouped by hour)
        token_timeline = db.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
                      SUM(json_extract(data_json, '$.input_tokens')) as input_t,
                      SUM(json_extract(data_json, '$.output_tokens')) as output_t
               FROM events
               WHERE event_type='token_usage'
                 AND timestamp > datetime('now', '-24 hours')
               GROUP BY hour ORDER BY hour"""
        ).fetchall()

        # Tool usage breakdown
        tool_counts = db.execute(
            """SELECT json_extract(data_json, '$.name') as tool, COUNT(*) as cnt
               FROM events WHERE event_type='tool_use'
               GROUP BY tool ORDER BY cnt DESC LIMIT 20"""
        ).fetchall()

        # Model usage
        model_usage = db.execute(
            """SELECT model, COUNT(*) as sessions
               FROM sessions WHERE model IS NOT NULL AND model != ''
               GROUP BY model ORDER BY sessions DESC"""
        ).fetchall()

        # Browser AI stats
        browser_today = 0
        browser_total_duration = 0
        try:
            row = db.execute(
                """SELECT COUNT(*) as cnt, COALESCE(SUM(duration_seconds), 0) as dur
                   FROM browser_sessions
                   WHERE date(visit_time) = date('now')"""
            ).fetchone()
            browser_today = row[0] if row else 0
            browser_total_duration = row[1] if row else 0
        except Exception:
            pass

        # Browser AI daily breakdown for chart
        browser_daily = []
        try:
            rows = db.execute(
                """SELECT service, date(visit_time) as day, COUNT(*) as visits,
                          COALESCE(SUM(duration_seconds), 0) as dur
                   FROM browser_sessions
                   WHERE visit_time > datetime('now', '-7 days')
                   GROUP BY service, day ORDER BY day"""
            ).fetchall()
            browser_daily = [dict(r) for r in rows]
        except Exception:
            pass

        # Token forecast
        forecast = compute_forecast(db)

        self._send_json(
            {
                "total_sessions": total_sessions,
                "total_events": total_events,
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "total_alerts": total_alerts,
                "active_processes": active_procs,
                "token_timeline": [dict(r) for r in token_timeline],
                "tool_counts": [dict(r) for r in tool_counts],
                "model_usage": [dict(r) for r in model_usage],
                "plan_info": plan_info,
                "browser_today": browser_today,
                "browser_total_duration": round(browser_total_duration, 0),
                "browser_daily": browser_daily,
                "forecast": forecast,
            }
        )

    def _api_processes(self, params):
        if not psutil:
            self._send_json({"processes": [], "error": "psutil not installed"})
            return

        found = []
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "cmdline", "cpu_percent", "memory_percent", "create_time", "status"]
            ):
                try:
                    info = proc.info
                    name = info.get("name") or ""
                    cmdline_str = " ".join(info.get("cmdline") or [])
                    try:
                        exe_path = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = ""
                    if is_ai_process(name, cmdline_str, exe_path):
                        # Classify source type
                        source_type = "CLI"
                        name_lower = name.lower()
                        if any(n in name_lower for n in ("cursor", "windsurf", "chatgpt")):
                            source_type = "Desktop App"
                        found.append(
                            {
                                "pid": info["pid"],
                                "name": name,
                                "cmdline": cmdline_str[:300],
                                "source_type": source_type,
                                "cpu_percent": info.get("cpu_percent", 0) or 0,
                                "memory_percent": round(info.get("memory_percent", 0) or 0, 2),
                                "status": info.get("status", ""),
                                "uptime": _format_uptime(info.get("create_time", 0)),
                            }
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        self._send_json({"processes": found})

    def _api_files(self, params):
        db = get_thread_db()
        limit = int(params.get("limit", ["100"])[0])
        rows = db.execute(
            """SELECT timestamp, path, operation, session_id, size
               FROM file_events ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        self._send_json({"files": [dict(r) for r in rows]})

    def _api_connections(self, params):
        db = get_thread_db()
        rows = db.execute(
            """SELECT timestamp, pid, process_name, remote_host, remote_port, status, service
               FROM connections ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        self._send_json({"connections": [dict(r) for r in rows]})

    def _api_alerts(self, params):
        db = get_thread_db()
        limit = int(params.get("limit", ["50"])[0])
        offset = int(params.get("offset", ["0"])[0])
        severity_filter = params.get("severity", [""])[0]
        category_filter = params.get("category", [""])[0]
        confidence_filter = params.get("confidence", ["medium+"])[0]
        include_dismissed = params.get("include_dismissed", ["false"])[0].lower() == "true"
        rows = db.execute(
            """SELECT e.id, e.timestamp, e.session_id, e.data_json,
                      s.title, s.cwd,
                      d.id AS dismissal_id
               FROM events e
               LEFT JOIN sessions s ON e.session_id = s.session_id
               LEFT JOIN alert_dismissals d ON e.id = d.event_id
               WHERE e.event_type='sensitive_data'
               ORDER BY e.id DESC LIMIT 1000"""
        ).fetchall()
        # First pass: apply all filters, count everything
        filtered_rows = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts = {}
        for r in rows:
            try:
                data = json.loads(r["data_json"])
            except (json.JSONDecodeError, TypeError):
                data = {}
            sev = data.get("severity", "medium")
            cats = data.get("categories", ["credential"])
            dismissed = r["dismissal_id"] is not None
            conf = data.get("confidence", "medium")

            if dismissed and not include_dismissed:
                continue
            if severity_filter and sev != severity_filter:
                continue
            if category_filter and category_filter not in cats:
                continue
            if confidence_filter == "high" and conf != "high":
                continue
            if confidence_filter == "medium+" and conf == "low":
                continue

            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            for cat in cats:
                category_counts[cat] = category_counts.get(cat, 0) + 1
            filtered_rows.append((r, data, sev, cats, dismissed, conf))

        # Second pass: paginate
        alerts = []
        for idx, (r, data, sev, cats, dismissed, _conf) in enumerate(filtered_rows):
            if idx < offset:
                continue
            if len(alerts) >= limit:
                continue

            # Compute turn number for this alert
            turn_count = 0
            if r["session_id"]:
                tc_row = db.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE session_id=? AND event_type='user_prompt' AND id <= ?""",
                    (r["session_id"], r["id"]),
                ).fetchone()
                turn_count = tc_row[0] if tc_row else 0

            # Feature C: enrich supply-chain alerts with package metadata
            # so the dashboard can render the investigation card with
            # advisory links, deep-jump buttons, and Copy Report.
            package_info = _enrich_supply_chain_alert(db, r["session_id"], data)

            alert_row = {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "session_id": r["session_id"],
                "session_title": JSONLSessionWatcher._clean_title(r["title"])
                if r["title"]
                else (r["session_id"] or "")[:8],
                "cwd": r["cwd"],
                "patterns": data.get("patterns", []),
                "severity": sev,
                "categories": cats,
                "context": data.get("context", ""),
                "snippet": data.get("snippet", ""),
                "matched_value": data.get("matched_value", ""),
                "confidence": data.get("confidence", "medium"),
                "likely_false_positive": data.get("likely_false_positive", False),
                "repeat_count": data.get("repeat_count", 1),
                "turn_number": turn_count,
                "dismissed": dismissed,
            }
            if package_info is not None:
                alert_row["package"] = package_info
            alerts.append(alert_row)
        self._send_json(
            {
                "alerts": alerts,
                "severity_counts": severity_counts,
                "category_counts": category_counts,
                "total": sum(severity_counts.values()),
                "has_more": len(alerts) >= limit,
            }
        )

    def _api_browser(self, params):
        db = get_thread_db()
        limit = int(params.get("limit", ["100"])[0])
        rows = db.execute(
            """SELECT id, service, url, title, conversation_id, visit_time,
                      duration_seconds, foreground_seconds
               FROM browser_sessions ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        self._send_json({"browser_sessions": [dict(r) for r in rows]})

    def _api_browser_sessions(self, params):
        """Browser visits grouped by conversation_id as logical sessions."""
        db = get_thread_db()
        limit = int(params.get("limit", ["100"])[0])
        service_filter = params.get("service", [""])[0]
        q = params.get("q", [""])[0].strip()

        conditions = ["conversation_id IS NOT NULL AND conversation_id != ''"]
        bind_vals = []
        if service_filter:
            conditions.append("service = ?")
            bind_vals.append(service_filter)
        if q:
            conditions.append("(title LIKE ? OR url LIKE ? OR conversation_id LIKE ?)")
            bind_vals.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

        where = " AND ".join(conditions)
        bind_vals.append(limit)

        browser_sql = f"""SELECT conversation_id, service,
                       MIN(visit_time) as first_visit,
                       MAX(visit_time) as last_visit,
                       COUNT(*) as visit_count,
                       COALESCE(SUM(duration_seconds), 0) as total_duration,
                       (SELECT b2.title FROM browser_sessions b2
                        WHERE b2.conversation_id = browser_sessions.conversation_id
                          AND b2.title IS NOT NULL AND b2.title != ''
                          AND b2.title != b2.service
                        ORDER BY b2.visit_time DESC LIMIT 1) as title
                FROM browser_sessions
                WHERE {where}
                GROUP BY conversation_id
                ORDER BY last_visit DESC
                LIMIT ?"""  # nosec B608
        rows = db.execute(browser_sql, bind_vals).fetchall()

        sessions = [dict(r) for r in rows]

        orphan_rows = db.execute(
            """SELECT id, service, url, title, visit_time, duration_seconds
               FROM browser_sessions
               WHERE conversation_id IS NULL OR conversation_id = ''
               ORDER BY visit_time DESC LIMIT 50"""
        ).fetchall()

        self._send_json(
            {
                "browser_sessions": sessions,
                "orphan_visits": [dict(r) for r in orphan_rows],
            }
        )

    def _api_browser_session_detail(self, params):
        """All visits for a specific browser conversation with correlated connections."""
        conv_id = params.get("conversation_id", [""])[0]
        if not conv_id:
            self._send_json({"error": "missing conversation_id"}, 400)
            return

        db = get_thread_db()
        rows = db.execute(
            """SELECT id, service, url, title, conversation_id, visit_time,
                      duration_seconds, foreground_seconds, source, event_type, content_text
               FROM browser_sessions
               WHERE conversation_id = ?
               ORDER BY visit_time ASC""",
            (conv_id,),
        ).fetchall()

        if not rows:
            self._send_json({"error": "conversation not found"}, 404)
            return

        visits = [dict(r) for r in rows]
        service = visits[0]["service"]
        first_visit = visits[0]["visit_time"]
        last_visit = visits[-1]["visit_time"]
        total_duration = sum(v.get("duration_seconds", 0) or 0 for v in visits)

        # Temporally correlated network connections
        service_hosts = {
            "ChatGPT": ["chatgpt.com", "openai.com"],
            "Gemini": ["googleapis.com", "google.com"],
            "Claude Web": ["anthropic.com", "claude.ai"],
            "Perplexity": ["perplexity.ai"],
            "Copilot": ["microsoft.com", "github.com"],
            "AI Studio": ["googleapis.com", "google.com"],
            "DeepSeek": ["deepseek.com"],
        }

        correlated_connections = []
        hosts = service_hosts.get(service, [])
        if hosts and first_visit and last_visit:
            host_conditions = " OR ".join(["remote_host LIKE ?"] * len(hosts))
            host_binds = [f"%{h}%" for h in hosts]
            conn_sql = f"""SELECT timestamp, pid, process_name, remote_host, remote_port, service
                    FROM connections
                    WHERE ({host_conditions})
                      AND timestamp >= datetime(?, '-5 minutes')
                      AND timestamp <= datetime(?, '+5 minutes')
                    ORDER BY timestamp ASC LIMIT 100"""  # nosec B608
            conn_rows = db.execute(conn_sql, host_binds + [first_visit, last_visit]).fetchall()
            correlated_connections = [dict(r) for r in conn_rows]

        # Bug 2: reverse the visits list so the dashboard renders newest
        # messages at the top, matching Claude Code session deep dives.
        # first_visit / last_visit are computed from the chronological
        # sort order before the reverse.
        visits_newest_first = list(reversed(visits))

        self._send_json(
            {
                "conversation_id": conv_id,
                "service": service,
                "title": next(
                    (v["title"] for v in reversed(visits) if v.get("title") and v["title"] != service), service
                ),
                "first_visit": first_visit,
                "last_visit": last_visit,
                "visit_count": len(visits),
                "total_duration": total_duration,
                "visits": visits_newest_first,
                "correlated_connections": correlated_connections,
            }
        )

    def _api_process_detail(self, params):
        """Process lifecycle and connection history for a specific PID."""
        pid = int(params.get("pid", ["0"])[0])
        if not pid:
            self._send_json({"error": "missing pid"}, 400)
            return

        db = get_thread_db()
        proc_rows = db.execute(
            """SELECT MAX(id) as id, pid, name, cmdline,
                      MIN(start_time) as start_time,
                      MAX(end_time) as end_time,
                      cpu_percent, memory_percent, status
               FROM processes WHERE pid = ?
               GROUP BY pid, name, start_time
               ORDER BY start_time DESC""",
            (pid,),
        ).fetchall()

        conn_rows = db.execute(
            """SELECT timestamp, remote_host, remote_port, status, service
               FROM connections WHERE pid = ?
               ORDER BY timestamp DESC LIMIT 200""",
            (pid,),
        ).fetchall()
        connections = [dict(r) for r in conn_rows]

        service_counts = {}
        for c in connections:
            svc = c.get("service", "unknown")
            service_counts[svc] = service_counts.get(svc, 0) + 1

        self._send_json(
            {
                "pid": pid,
                "processes": [dict(r) for r in proc_rows],
                "connections": connections,
                "service_breakdown": service_counts,
            }
        )

    def _api_activity_timeline(self, params):
        """Unified timeline of all AI activity across sources."""
        db = get_thread_db()
        limit = int(params.get("limit", ["100"])[0])
        since = params.get("since", [""])[0]
        source_filter = params.get("source", [""])[0]

        timeline = []

        # CLI session events
        if not source_filter or source_filter == "cli":
            cli_conds = ["event_type IN ('user_prompt', 'assistant_response', 'sensitive_data')"]
            cli_binds = []
            if since:
                cli_conds.append("e.timestamp > ?")
                cli_binds.append(since)
            cli_binds.append(limit)
            cli_sql = f"""SELECT e.timestamp, e.event_type, e.session_id, e.data_json,
                           s.title, s.model
                    FROM events e
                    LEFT JOIN sessions s ON e.session_id = s.session_id
                    WHERE {" AND ".join(cli_conds)}
                    ORDER BY e.timestamp DESC LIMIT ?"""  # nosec B608
            cli_rows = db.execute(cli_sql, cli_binds).fetchall()
            for r in cli_rows:
                try:
                    data = json.loads(r["data_json"]) if r["data_json"] else {}
                except (json.JSONDecodeError, TypeError):
                    data = {}
                timeline.append(
                    {
                        "timestamp": r["timestamp"],
                        "source": "cli",
                        "event_type": r["event_type"],
                        "session_id": r["session_id"],
                        "title": r["title"] or (r["session_id"] or "")[:8],
                        "model": r["model"] or "",
                        "summary": (data.get("text", "") or "")[:120],
                    }
                )

        # Browser visits
        if not source_filter or source_filter == "browser":
            browser_conds = ["1=1"]
            browser_binds = []
            if since:
                browser_conds.append("visit_time > ?")
                browser_binds.append(since)
            browser_binds.append(limit)
            b_sql = f"""SELECT visit_time, service, title, url, conversation_id, duration_seconds
                    FROM browser_sessions
                    WHERE {" AND ".join(browser_conds)}
                    ORDER BY visit_time DESC LIMIT ?"""  # nosec B608
            browser_rows = db.execute(b_sql, browser_binds).fetchall()
            for r in browser_rows:
                rd = dict(r)
                dur = int(rd.get("duration_seconds") or 0)
                timeline.append(
                    {
                        "timestamp": rd["visit_time"],
                        "source": "browser",
                        "event_type": "browser_visit",
                        "session_id": "browser_" + (rd["conversation_id"] or ""),
                        "title": rd["title"] or rd["service"],
                        "model": rd["service"],
                        "summary": f"{rd['service']}: {(rd['title'] or '')[:80]}" + (f" ({dur}s)" if dur else ""),
                    }
                )

        # Network connections
        if not source_filter or source_filter == "network":
            net_conds = ["1=1"]
            net_binds = []
            if since:
                net_conds.append("timestamp > ?")
                net_binds.append(since)
            net_binds.append(limit)
            n_sql = f"""SELECT timestamp, pid, process_name, remote_host, remote_port, service
                    FROM connections
                    WHERE {" AND ".join(net_conds)}
                    ORDER BY timestamp DESC LIMIT ?"""  # nosec B608
            net_rows = db.execute(n_sql, net_binds).fetchall()
            for r in net_rows:
                rd = dict(r)
                timeline.append(
                    {
                        "timestamp": rd["timestamp"],
                        "source": "network",
                        "event_type": "connection",
                        "session_id": None,
                        "title": rd["process_name"],
                        "model": "",
                        "summary": f"{rd['process_name']} \u2192 {rd['remote_host']}:{rd['remote_port']} ({rd['service']})",
                    }
                )

        timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        timeline = timeline[:limit]

        self._send_json({"timeline": timeline, "count": len(timeline)})

    def _send_ndjson(self, rows, filename):
        """Send rows as NDJSON (newline-delimited JSON) with download headers."""
        lines = []
        for row in rows:
            lines.append(json.dumps(row, default=str))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_json_download(self, data, filename):
        """Send JSON data with download headers."""
        body = json.dumps(data, default=str, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_csv(self, rows, filename):
        """Send rows as CSV with download headers."""
        if not rows:
            body = b""
        else:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            for row in rows:
                writer.writerow({k: str(v) if v is not None else "" for k, v in row.items()})
            body = output.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _api_export(self, params):
        """Export data for SIEM integration."""
        export_type = params.get("type", ["sessions"])[0]
        fmt = params.get("format", ["json"])[0]
        since = params.get("since", [""])[0]
        until = params.get("until", [""])[0]
        session_id = params.get("session_id", [""])[0]
        event_types = params.get("event_type", [""])[0]
        limit = int(params.get("limit", ["10000"])[0])

        db = get_thread_db()

        if export_type == "sessions":
            rows = db.execute(
                """SELECT session_id, start_time, cwd, model,
                          total_input_tokens, total_output_tokens, total_turns,
                          last_activity, title
                   FROM sessions ORDER BY last_activity DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            data = [dict(r) for r in rows]
            fname = f"ai_monitor_sessions_{now_iso()[:10]}"

        elif export_type == "events":
            conditions = ["1=1"]
            bind_vals = []
            if since:
                conditions.append("timestamp >= ?")
                bind_vals.append(since)
            if until:
                conditions.append("timestamp <= ?")
                bind_vals.append(until)
            if session_id:
                conditions.append("session_id = ?")
                bind_vals.append(session_id)
            if event_types:
                types = event_types.split(",")
                placeholders = ",".join("?" * len(types))
                conditions.append(f"event_type IN ({placeholders})")
                bind_vals.extend(types)
            bind_vals.append(limit)

            evt_sql = f"""SELECT id, timestamp, session_id, event_type, source_layer, data_json
                   FROM events
                   WHERE {" AND ".join(conditions)}
                   ORDER BY id DESC LIMIT ?"""  # nosec B608
            rows = db.execute(evt_sql, bind_vals).fetchall()
            data = []
            for r in rows:
                row = dict(r)
                try:
                    row["data"] = json.loads(row.pop("data_json", "{}"))
                except (json.JSONDecodeError, TypeError):
                    row["data"] = {}
                data.append(row)
            fname = f"ai_monitor_events_{now_iso()[:10]}"

        elif export_type == "alerts":
            rows = db.execute(
                """SELECT e.id, e.timestamp, e.session_id, e.data_json,
                          s.title, s.cwd, s.model
                   FROM events e
                   LEFT JOIN sessions s ON e.session_id = s.session_id
                   WHERE e.event_type='sensitive_data'
                   ORDER BY e.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            data = []
            for r in rows:
                row = dict(r)
                try:
                    d = json.loads(row.pop("data_json", "{}"))
                    row.update(d)
                except (json.JSONDecodeError, TypeError):
                    pass
                data.append(row)
            fname = f"ai_monitor_alerts_{now_iso()[:10]}"

        elif export_type == "connections":
            rows = db.execute(
                """SELECT timestamp, pid, process_name, remote_host,
                          remote_port, status, service
                   FROM connections ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            data = [dict(r) for r in rows]
            fname = f"ai_monitor_connections_{now_iso()[:10]}"

        elif export_type == "traffic":
            rows = db.execute(
                """SELECT * FROM api_calls ORDER BY timestamp DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            data = [dict(r) for r in rows]
            fname = f"ai_monitor_traffic_{now_iso()[:10]}"

        else:
            self._send_json({"error": f"Unknown export type: {export_type}"}, 400)
            return

        if fmt == "csv":
            self._send_csv(data, fname + ".csv")
        elif fmt == "ndjson":
            self._send_ndjson(data, fname + ".ndjson")
        else:
            self._send_json_download(
                {"export_type": export_type, "count": len(data), "exported_at": now_iso(), "data": data},
                fname + ".json",
            )

    # ── API Traffic endpoints (claude-watch integration) ──────────────

    def _api_traffic(self, params):
        """Paginated list of API calls from claude-watch dual-write."""
        db = get_thread_db()
        limit = int(params.get("limit", ["50"])[0])
        offset = int(params.get("offset", ["0"])[0])
        service = params.get("service", [""])[0]
        model = params.get("model", [""])[0]

        conditions = ["1=1"]
        bind_vals = []
        if service:
            conditions.append("destination_service = ?")
            bind_vals.append(service)
        if model:
            conditions.append("model LIKE ?")
            bind_vals.append(f"%{model}%")

        where = " AND ".join(conditions)

        sort_col = params.get("sort", ["timestamp"])[0]
        sort_dir = params.get("dir", ["desc"])[0].upper()
        allowed_sorts = {
            "timestamp",
            "model",
            "input_tokens",
            "output_tokens",
            "latency_ms",
            "http_status",
            "destination_service",
        }
        if sort_col not in allowed_sorts:
            sort_col = "timestamp"
        if sort_dir not in ("ASC", "DESC"):
            sort_dir = "DESC"
        query_sql = f"""SELECT * FROM api_calls WHERE {where}
            ORDER BY {sort_col} {sort_dir} LIMIT ? OFFSET ?"""  # nosec B608
        rows = db.execute(query_sql, bind_vals + [limit, offset]).fetchall()

        # Dedup by request_id — keep row with non-null latency preferred
        seen_rids = {}
        unique_calls = []
        for r in rows:
            rd = dict(r)
            rid = rd.get("request_id", "")
            if rid and rid in seen_rids:
                existing = seen_rids[rid]
                if rd.get("latency_ms") and not existing.get("latency_ms"):
                    idx = unique_calls.index(existing)
                    unique_calls[idx] = rd
                    seen_rids[rid] = rd
                continue
            if rid:
                seen_rids[rid] = rd
            unique_calls.append(rd)

        self._send_json(
            {
                "calls": unique_calls,
                "total": len(unique_calls),
                "limit": limit,
                "offset": offset,
            }
        )

    def _api_traffic_stats(self, params):
        """Aggregated traffic statistics."""
        db = get_thread_db()
        row = db.execute(
            """SELECT COUNT(DISTINCT COALESCE(request_id, id)) as total_calls,
                      COALESCE(SUM(input_tokens), 0) as total_input_tokens,
                      COALESCE(SUM(output_tokens), 0) as total_output_tokens,
                      COALESCE(AVG(CASE WHEN latency_ms > 0 THEN latency_ms END), 0) as avg_latency,
                      COALESCE(SUM(sensitive_pattern_count), 0) as total_sensitive,
                      COALESCE(SUM(estimated_cost_usd), 0) as total_cost
               FROM api_calls"""
        ).fetchone()

        by_service = db.execute(
            """SELECT destination_service, COUNT(*) as count
               FROM api_calls GROUP BY destination_service
               ORDER BY count DESC"""
        ).fetchall()

        by_model = db.execute(
            """SELECT model, COUNT(*) as count
               FROM api_calls WHERE model != '' GROUP BY model
               ORDER BY count DESC"""
        ).fetchall()

        self._send_json(
            {
                "total_calls": row["total_calls"],
                "total_input_tokens": row["total_input_tokens"],
                "total_output_tokens": row["total_output_tokens"],
                "avg_latency": round(row["avg_latency"], 1),
                "total_sensitive": row["total_sensitive"],
                "total_cost": round(float(row["total_cost"] or 0), 2),
                "by_service": [dict(r) for r in by_service],
                "by_model": [dict(r) for r in by_model],
            }
        )

    def _api_session_traffic(self, params):
        """All API calls for a specific session."""
        session_id = params.get("id", [""])[0]
        if not session_id:
            self._send_json({"error": "session id required"}, 400)
            return

        db = get_thread_db()
        rows = db.execute(
            """SELECT * FROM api_calls WHERE session_id = ?
               ORDER BY turn_number ASC""",
            (session_id,),
        ).fetchall()

        calls = [dict(r) for r in rows]

        self._send_json(
            {
                "session_id": session_id,
                "calls": calls,
                "total_calls": len(calls),
            }
        )

    # ── MCP endpoints ────────────────────────────────────────────

    def _api_mcp_stats(self, params):
        """MCP server activity statistics from tool_use events."""
        db = get_thread_db()
        limit = int(params.get("limit", ["50"])[0])

        # Query tool_use events with mcp__ prefix
        rows = db.execute(
            """SELECT e.id, e.timestamp, e.session_id, e.data_json
               FROM events e
               WHERE e.event_type = 'mcp_call'
               ORDER BY e.id DESC LIMIT ?""",
            (limit * 10,),
        ).fetchall()

        servers = {}
        recent_calls = []
        session_ids = set()

        for r in rows:
            try:
                data = json.loads(r["data_json"]) if r["data_json"] else {}
            except (json.JSONDecodeError, TypeError):
                continue

            server = data.get("server", "unknown")
            method = data.get("method", "unknown")
            session_ids.add(r["session_id"])

            if server not in servers:
                servers[server] = {"server": server, "call_count": 0, "methods": set(), "sessions": set()}
            servers[server]["call_count"] += 1
            servers[server]["methods"].add(method)
            servers[server]["sessions"].add(r["session_id"])

            if len(recent_calls) < limit:
                recent_calls.append(
                    {
                        "timestamp": r["timestamp"],
                        "session_id": r["session_id"],
                        "server": server,
                        "method": method,
                        "input_preview": data.get("input_preview", ""),
                    }
                )

        # Also scan tool_use events for mcp__ prefix (for data captured before mcp_call was added)
        fallback_rows = db.execute(
            """SELECT e.id, e.timestamp, e.session_id, e.data_json
               FROM events e
               WHERE e.event_type = 'tool_use'
                 AND json_extract(e.data_json, '$.name') LIKE 'mcp__%'
               ORDER BY e.id DESC LIMIT ?""",
            (limit * 10,),
        ).fetchall()

        for r in fallback_rows:
            try:
                data = json.loads(r["data_json"]) if r["data_json"] else {}
            except (json.JSONDecodeError, TypeError):
                continue

            tool_name = data.get("name", "")
            parts = tool_name.split("__", 2)
            if len(parts) < 2:
                continue
            server = parts[1]
            method = parts[2] if len(parts) > 2 else "unknown"
            session_ids.add(r["session_id"])

            if server not in servers:
                servers[server] = {"server": server, "call_count": 0, "methods": set(), "sessions": set()}
            servers[server]["call_count"] += 1
            servers[server]["methods"].add(method)
            servers[server]["sessions"].add(r["session_id"])

        # Convert sets to lists for JSON
        server_list = []
        for s in sorted(servers.values(), key=lambda x: -x["call_count"]):
            server_list.append(
                {
                    "server": s["server"],
                    "call_count": s["call_count"],
                    "methods": sorted(s["methods"]),
                    "session_count": len(s["sessions"]),
                }
            )

        self._send_json(
            {
                "servers": server_list,
                "total_calls": sum(s["call_count"] for s in server_list),
                "total_servers": len(server_list),
                "total_sessions": len(session_ids),
                "recent_calls": recent_calls,
            }
        )

    def _api_mcp_servers(self, params):
        """List distinct MCP servers and their discovered methods."""
        db = get_thread_db()

        # From mcp_call events
        rows = db.execute("""SELECT data_json FROM events WHERE event_type = 'mcp_call'""").fetchall()

        # Also from tool_use events with mcp__ prefix
        fallback_rows = db.execute(
            """SELECT data_json FROM events
               WHERE event_type = 'tool_use'
                 AND json_extract(data_json, '$.name') LIKE 'mcp__%'"""
        ).fetchall()

        servers = {}
        for r in rows:
            try:
                data = json.loads(r["data_json"]) if r["data_json"] else {}
            except (json.JSONDecodeError, TypeError):
                continue
            server = data.get("server", "unknown")
            method = data.get("method", "unknown")
            if server not in servers:
                servers[server] = {"server": server, "methods": set(), "call_count": 0}
            servers[server]["methods"].add(method)
            servers[server]["call_count"] += 1

        for r in fallback_rows:
            try:
                data = json.loads(r["data_json"]) if r["data_json"] else {}
            except (json.JSONDecodeError, TypeError):
                continue
            tool_name = data.get("name", "")
            parts = tool_name.split("__", 2)
            if len(parts) < 2:
                continue
            server = parts[1]
            method = parts[2] if len(parts) > 2 else "unknown"
            if server not in servers:
                servers[server] = {"server": server, "methods": set(), "call_count": 0}
            servers[server]["methods"].add(method)
            servers[server]["call_count"] += 1

        result = []
        for s in sorted(servers.values(), key=lambda x: -x["call_count"]):
            result.append(
                {
                    "server": s["server"],
                    "methods": sorted(s["methods"]),
                    "call_count": s["call_count"],
                }
            )

        self._send_json({"servers": result, "total": len(result)})

    # ── Insights endpoints ─────────────────────────────────────

    def _api_insights(self, params):
        """Cross-session analytics with project grouping and efficiency metrics."""
        db = get_thread_db()
        period = params.get("period", ["30d"])[0]
        period_map = {"7d": 7, "30d": 30, "90d": 90, "all": 9999}
        days = period_map.get(period, 30)

        since_clause = "AND timestamp >= datetime('now', ?)" if days < 9999 else ""
        session_since = "AND last_activity >= datetime('now', ?)" if days < 9999 else ""
        bind = [f"-{days} days"] if days < 9999 else []

        # Top 10 tools across all sessions
        top_tools = db.execute(
            f"""SELECT json_extract(data_json, '$.name') as tool, COUNT(*) as cnt
               FROM events
               WHERE event_type = 'tool_use' {since_clause}
               GROUP BY tool ORDER BY cnt DESC LIMIT 10""",  # nosec B608
            bind,
        ).fetchall()

        # Top 15 most-read files
        top_files = db.execute(
            f"""SELECT json_extract(data_json, '$.input_preview') as file_path, COUNT(*) as cnt
               FROM events
               WHERE event_type = 'tool_use'
                 AND json_extract(data_json, '$.name') IN ('Read', 'read_file')
                 {since_clause}
               GROUP BY file_path ORDER BY cnt DESC LIMIT 15""",  # nosec B608
            bind,
        ).fetchall()

        # Sessions grouped by project (cwd)
        projects = db.execute(
            f"""SELECT cwd, COUNT(*) as sessions,
                      COALESCE(SUM(total_input_tokens), 0) as input_tokens,
                      COALESCE(SUM(total_output_tokens), 0) as output_tokens,
                      COALESCE(SUM(total_turns), 0) as turns
               FROM sessions
               WHERE cwd IS NOT NULL AND cwd != '' {session_since}
               GROUP BY cwd ORDER BY sessions DESC""",  # nosec B608
            bind,
        ).fetchall()

        # Daily token trend
        daily_trend = db.execute(
            f"""SELECT date(timestamp) as day,
                      COALESCE(SUM(json_extract(data_json, '$.input_tokens')), 0) as input_tokens,
                      COALESCE(SUM(json_extract(data_json, '$.output_tokens')), 0) as output_tokens
               FROM events
               WHERE event_type = 'token_usage' {since_clause}
               GROUP BY day ORDER BY day""",  # nosec B608
            bind,
        ).fetchall()

        # Efficiency metrics
        sessions_data = db.execute(
            f"""SELECT session_id, total_turns, total_input_tokens, total_output_tokens
               FROM sessions
               WHERE total_turns > 0 {session_since}""",  # nosec B608
            bind,
        ).fetchall()

        total_sessions = len(sessions_data)
        avg_turns = sum(s["total_turns"] for s in sessions_data) / max(total_sessions, 1)
        total_tokens = sum((s["total_input_tokens"] or 0) + (s["total_output_tokens"] or 0) for s in sessions_data)
        total_turns_all = sum(s["total_turns"] for s in sessions_data)
        avg_tokens_per_turn = total_tokens / max(total_turns_all, 1)

        # Model distribution
        models = db.execute(
            f"""SELECT model, COUNT(*) as sessions
               FROM sessions
               WHERE model IS NOT NULL AND model != '' {session_since}
               GROUP BY model ORDER BY sessions DESC""",  # nosec B608
            bind,
        ).fetchall()

        self._send_json(
            {
                "period": period,
                "days": days,
                "total_sessions": total_sessions,
                "efficiency": {
                    "avg_turns_per_session": round(avg_turns, 1),
                    "avg_tokens_per_turn": round(avg_tokens_per_turn, 0),
                },
                "top_tools": [{"tool": t["tool"], "count": t["cnt"]} for t in top_tools],
                "top_files": [{"file": f["file_path"], "count": f["cnt"]} for f in top_files],
                "projects": [dict(p) for p in projects],
                "daily_trend": [dict(d) for d in daily_trend],
                "models": [dict(m) for m in models],
                "total_projects": len(projects),
            }
        )

    def _api_insights_projects(self, params):
        """Per-project drill-down with sessions list and daily breakdown."""
        db = get_thread_db()
        cwd = params.get("cwd", [""])[0]
        if not cwd:
            self._send_json({"error": "cwd parameter required"}, 400)
            return

        sessions = db.execute(
            """SELECT session_id, start_time, model, total_input_tokens,
                      total_output_tokens, total_turns, last_activity, title
               FROM sessions WHERE cwd = ? ORDER BY last_activity DESC""",
            (cwd,),
        ).fetchall()

        # Daily breakdown for this project
        session_ids = [s["session_id"] for s in sessions]
        daily = []
        if session_ids:
            placeholders = ",".join("?" * len(session_ids))
            daily = db.execute(
                f"""SELECT date(timestamp) as day,
                          COALESCE(SUM(json_extract(data_json, '$.input_tokens')), 0) as input_tokens,
                          COALESCE(SUM(json_extract(data_json, '$.output_tokens')), 0) as output_tokens
                   FROM events
                   WHERE event_type = 'token_usage' AND session_id IN ({placeholders})
                   GROUP BY day ORDER BY day""",  # nosec B608
                session_ids,
            ).fetchall()

        self._send_json(
            {
                "cwd": cwd,
                "sessions": [dict(s) for s in sessions],
                "total_sessions": len(sessions),
                "daily": [dict(d) for d in daily],
            }
        )

    def _api_insights_efficiency(self, params):
        """Session comparison table with computed efficiency columns."""
        db = get_thread_db()
        period = params.get("period", ["30d"])[0]
        period_map = {"7d": 7, "30d": 30, "90d": 90, "all": 9999}
        days = period_map.get(period, 30)

        session_since = "AND last_activity >= datetime('now', ?)" if days < 9999 else ""
        bind = [f"-{days} days"] if days < 9999 else []

        sessions = db.execute(
            f"""SELECT session_id, start_time, cwd, model, total_input_tokens,
                      total_output_tokens, total_turns, last_activity, title
               FROM sessions
               WHERE total_turns > 0 {session_since}
               ORDER BY last_activity DESC""",  # nosec B608
            bind,
        ).fetchall()

        result = []
        for s in sessions:
            turns = s["total_turns"] or 1
            total_tokens = (s["total_input_tokens"] or 0) + (s["total_output_tokens"] or 0)
            result.append(
                {
                    **dict(s),
                    "tokens_per_turn": round(total_tokens / turns, 0),
                }
            )

        self._send_json({"sessions": result, "total": len(result), "period": period})

    # ── Report endpoint ────────────────────────────────────────

    def _api_supply_chain(self, params):
        """Supply chain dependency data with category filter and grouped view."""
        db = get_thread_db()
        manager = params.get("manager", [""])[0]
        category = params.get("category", ["package"])[0]
        search = params.get("search", [""])[0]
        view = params.get("view", ["grouped"])[0]
        limit = int(params.get("limit", ["200"])[0])

        # Base filter
        conditions = ["1=1"]
        bind = []
        if category and category != "all":
            conditions.append("d.category = ?")
            bind.append(category)
        if manager:
            conditions.append("d.package_manager = ?")
            bind.append(manager)
        if search:
            conditions.append("d.package_name LIKE ?")
            bind.append(f"%{search}%")
        min_risk = params.get("min_risk", [""])[0]
        if min_risk:
            conditions.append("d.risk_score >= ?")
            bind.append(int(min_risk))
        unpinned = params.get("unpinned", [""])[0]
        if unpinned == "1":
            conditions.append("d.pinned = 0")

        where = " AND ".join(conditions)

        # Stats for current filter
        stats_sql = f"""SELECT COUNT(*) as total,
                    COUNT(DISTINCT package_name) as uniq,
                    SUM(CASE WHEN pinned=0 THEN 1 ELSE 0 END) as unpinned,
                    SUM(CASE WHEN risk_score >= 4 THEN 1 ELSE 0 END) as risk_flagged
                FROM agent_dependencies d WHERE {where}"""  # nosec B608
        st = db.execute(stats_sql, bind).fetchone()
        by_manager = {
            r[0]: r[1]
            for r in db.execute(
                f"SELECT package_manager, COUNT(*) FROM agent_dependencies d WHERE {where} GROUP BY package_manager",  # nosec B608
                bind,
            ).fetchall()
        }

        if view == "grouped":
            sql = f"""SELECT package_name, package_manager, category, registry_url,
                          COUNT(*) as install_count,
                          MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                          MAX(risk_score) as risk_score, MAX(risk_flags) as risk_flags,
                          GROUP_CONCAT(DISTINCT agent_type) as agents,
                          GROUP_CONCAT(DISTINCT project) as projects,
                          MAX(pinned) as pinned,
                          (SELECT package_version FROM agent_dependencies
                           WHERE package_name=d.package_name AND package_manager=d.package_manager
                           ORDER BY id DESC LIMIT 1) as latest_version
                      FROM agent_dependencies d WHERE {where}
                      GROUP BY package_name, package_manager
                      ORDER BY MAX(risk_score) DESC, COUNT(*) DESC LIMIT ?"""  # nosec B608
            rows = db.execute(sql, bind + [limit]).fetchall()
            installs = []
            for r in rows:
                rd = dict(r)
                try:
                    rd["risk_flags"] = json.loads(rd.get("risk_flags") or "{}")
                except (json.JSONDecodeError, TypeError):
                    rd["risk_flags"] = {}
                # Enrich with vulnerability data
                vuln_rows = db.execute(
                    """SELECT vuln_id, severity, cvss_score, fix_version, description, package_name
                       FROM package_vulnerabilities WHERE package_name=? LIMIT 10""",
                    (rd["package_name"],),
                ).fetchall()
                if vuln_rows:
                    vulns = [dict(v) for v in vuln_rows]
                    max_cvss = max((v["cvss_score"] or 0) for v in vulns)
                    rd["vulnerabilities"] = {
                        "count": len(vulns),
                        "scanned": True,
                        "max_severity": max((v["severity"] or "unknown") for v in vulns),
                        "max_cvss": max_cvss,
                        "vulns": vulns,
                    }
                else:
                    has_scan = db.execute("SELECT 1 FROM scan_history LIMIT 1").fetchone()
                    rd["vulnerabilities"] = {
                        "count": 0,
                        "scanned": has_scan is not None,
                        "max_severity": None,
                        "max_cvss": None,
                        "vulns": [],
                    }
                installs.append(rd)
        else:
            sql = f"""SELECT d.*, s.title as session_title
                      FROM agent_dependencies d
                      LEFT JOIN sessions s ON d.session_id = s.session_id
                      WHERE {where} ORDER BY d.id DESC LIMIT ?"""  # nosec B608
            rows = db.execute(sql, bind + [limit]).fetchall()
            installs = [dict(r) for r in rows]

        self._send_json(
            {
                "stats": {
                    "total_installs": st[0] or 0,
                    "unique_packages": st[1] or 0,
                    "unpinned_count": st[2] or 0,
                    "risk_flagged_count": st[3] or 0,
                    "by_manager": by_manager,
                },
                "installs": installs,
                "view": view,
            }
        )

    def _api_supply_chain_environment(self, params):
        """Full environment package inventory with vuln + agent cross-reference."""
        db = get_thread_db()
        search = params.get("search", [""])[0]
        conditions = ["1=1"]
        bind = []
        if search:
            conditions.append("ep.package_name LIKE ?")
            bind.append(f"%{search}%")
        where = " AND ".join(conditions)

        sql = f"""SELECT ep.package_name, ep.package_version, ep.manager,
                     (SELECT COUNT(*) FROM package_vulnerabilities pv
                      WHERE pv.package_name = ep.package_name) as vuln_count,
                     (SELECT MAX(pv.cvss_score) FROM package_vulnerabilities pv
                      WHERE pv.package_name = ep.package_name) as max_cvss,
                     (SELECT COUNT(*) FROM agent_dependencies ad
                      WHERE ad.package_name = ep.package_name AND ad.category='package') as agent_installs
                  FROM environment_packages ep WHERE {where}
                  ORDER BY vuln_count DESC, agent_installs DESC, ep.package_name
                  LIMIT 500"""  # nosec B608
        rows = db.execute(sql, bind).fetchall()

        total = db.execute(f"SELECT COUNT(*) FROM environment_packages ep WHERE {where}", bind).fetchone()[0]  # nosec B608
        vuln_count = db.execute(
            "SELECT COUNT(DISTINCT package_name) FROM environment_packages ep WHERE package_name IN (SELECT package_name FROM package_vulnerabilities)"
        ).fetchone()[0]
        agent_count = db.execute(
            "SELECT COUNT(DISTINCT package_name) FROM environment_packages WHERE package_name IN (SELECT package_name FROM agent_dependencies WHERE category='package')"
        ).fetchone()[0]

        self._send_json(
            {
                "stats": {
                    "total": total,
                    "vulnerable": vuln_count,
                    "agent_installed": agent_count,
                    "clean": total - vuln_count,
                },
                "packages": [dict(r) for r in rows],
            }
        )

    def _api_supply_chain_registry(self, params):
        """Fetch or return cached registry metadata for a package."""
        pkg = params.get("package", [""])[0]
        mgr = params.get("manager", [""])[0]
        if not pkg:
            self._send_json({"error": "missing package"}, 400)
            return
        db = get_thread_db()
        # Check cache
        cached = db.execute(
            "SELECT metadata FROM package_registry_cache WHERE package_name=? AND manager=?",
            (pkg, mgr),
        ).fetchone()
        if cached:
            try:
                self._send_json({"metadata": json.loads(cached[0])})
                return
            except Exception:
                pass
        # Fetch live
        try:
            from claude_monitoring.threat_intel import fetch_registry_metadata

            meta = fetch_registry_metadata(pkg, mgr)
            if meta:
                db.execute(
                    """INSERT OR REPLACE INTO package_registry_cache
                       (package_name, manager, fetch_timestamp, metadata)
                       VALUES (?, ?, datetime('now'), ?)""",
                    (pkg, mgr, json.dumps(meta)),
                )
                db.commit()
                self._send_json({"metadata": meta})
                return
        except Exception:
            pass
        self._send_json({"metadata": None})

    def _api_supply_chain_sbom(self, params):
        """Export SBOM in CycloneDX JSON format."""
        from claude_monitoring.supply_chain import generate_sbom

        db = get_thread_db()
        sbom = generate_sbom(db)
        body = json.dumps(sbom, indent=2, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", "attachment; filename=ai-runtime-sbom.json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _api_supply_chain_watchlist(self, params):
        """Package watchlist with monitoring priorities."""
        from claude_monitoring.supply_chain import populate_watchlist

        db = get_thread_db()
        counts = populate_watchlist(db)
        rows = db.execute(
            "SELECT * FROM package_watchlist ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, package_name LIMIT 100"
        ).fetchall()
        self._send_json(
            {
                "counts": counts,
                "watchlist": [dict(r) for r in rows],
            }
        )

    def _api_supply_chain_intel_status(self, params):
        """Threat intelligence source status (Feature A).

        Returns per-source state derived from the ``intel_source_status``
        table. State is one of ``green``/``yellow``/``red``/``gray``:

          green  — last fetch succeeded within 24h
          yellow — last fetch succeeded but > 24h ago
          red    — last fetch attempted and failed
          gray   — never fetched / disabled

        Sources reported: osv, pip-audit, threatfox, urlhaus, registry.
        pip-audit and OSV are recorded by vuln_scanner on each scan.
        threatfox and urlhaus are recorded by threat_intel fetchers.
        registry is live-counted from package_registry_cache.
        """
        from datetime import datetime, timezone

        db = get_thread_db()
        ioc_count = db.execute("SELECT COUNT(*) FROM threat_iocs").fetchone()[0]
        registry_cached = db.execute("SELECT COUNT(*) FROM package_registry_cache").fetchone()[0]
        last_scan_row = db.execute("SELECT timestamp FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
        last_scan_ts = last_scan_row[0] if last_scan_row else None

        # Load per-source state rows, indexed by canonical short name
        status_rows: dict = {}
        try:
            for row in db.execute(
                "SELECT name, last_attempt, last_success, last_error, record_count FROM intel_source_status"
            ).fetchall():
                status_rows[row[0] if not hasattr(row, "keys") else row["name"]] = {
                    "last_attempt": row[1] if not hasattr(row, "keys") else row["last_attempt"],
                    "last_success": row[2] if not hasattr(row, "keys") else row["last_success"],
                    "last_error": row[3] if not hasattr(row, "keys") else row["last_error"],
                    "record_count": row[4] if not hasattr(row, "keys") else row["record_count"],
                }
        except Exception:
            pass

        now_utc = datetime.now(timezone.utc)

        def _compute_state(last_attempt, last_success, last_error):
            if last_error:
                return ("red", None)
            if not last_attempt and not last_success:
                return ("gray", None)
            if not last_success:
                return ("red", None)
            try:
                ts = datetime.fromisoformat(last_success.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                age_hours = (now_utc - ts).total_seconds() / 3600
            except Exception:
                return ("red", None)
            if age_hours <= 24:
                return ("green", age_hours)
            return ("yellow", age_hours)

        def _source(short_name: str, display: str, description: str, default_records: int = 0):
            s = status_rows.get(short_name, {})
            state, age = _compute_state(s.get("last_attempt"), s.get("last_success"), s.get("last_error"))
            records = s.get("record_count") if s.get("record_count") is not None else default_records
            return {
                "name": display,
                "short_name": short_name,
                "state": state,
                "description": description,
                "records": records,
                "iocs": records,  # legacy alias
                "cached": records,  # legacy alias
                "last_attempt": s.get("last_attempt"),
                "last_success": s.get("last_success"),
                "last_error": s.get("last_error"),
                "age_hours": round(age, 1) if age is not None else None,
                # legacy: treat green/yellow as "active" so older UI still works
                "active": state in ("green", "yellow"),
            }

        # Registry source isn't in intel_source_status yet (cache is live-counted),
        # so synthesize a state from package_registry_cache.fetch_timestamp MAX.
        registry_state = {"last_attempt": None, "last_success": None, "last_error": None}
        try:
            row = db.execute("SELECT MAX(fetch_timestamp) FROM package_registry_cache").fetchone()
            if row and row[0]:
                registry_state["last_success"] = row[0]
                registry_state["last_attempt"] = row[0]
        except Exception:
            pass
        if "registry" not in status_rows:
            status_rows["registry"] = {
                **registry_state,
                "record_count": registry_cached,
            }

        sources = [
            _source("osv", "OSV.dev", "15K+ malicious packages"),
            _source("pip-audit", "pip-audit", "Local Python vuln scan"),
            _source("threatfox", "ThreatFox", "abuse.ch IP/domain IOCs"),
            _source("urlhaus", "URLhaus", "Active malware URLs"),
            _source("registry", "Registry metadata", "PyPI/npm package info"),
        ]

        self._send_json(
            {
                "sources": sources,
                "total_iocs": ioc_count,
                "last_scan": last_scan_ts,
            }
        )

    def _api_supply_chain_scan(self, params):
        """GET: return scan status (alias for scan-status)."""
        self._api_supply_chain_scan_status(params)

    def _api_supply_chain_scan_post(self, payload):
        """POST: trigger a vulnerability scan (Feature B: async).

        Returns immediately with ``{"started": true}``. The scan runs in
        a daemon thread; the client polls ``/api/supply-chain/scan-progress``
        to follow phase-by-phase progress. Rejects concurrent scans with
        409 Conflict.
        """
        with _scan_state_lock:
            if _scan_state["running"]:
                self._send_json(
                    {
                        "error": "scan already in progress",
                        "started_at": _scan_state["started_at"],
                    },
                    409,
                )
                return
            # P0-04: reset state by MUTATING the existing dict in place
            # (clear + update), not by rebinding `_scan_state = ...`.
            # Rebinding the module-level variable inside the lock leaves
            # any other thread that holds a reference to the old dict
            # reading stale state — the lock only protects the binding
            # operation itself, not the dict identity. Mutating in place
            # keeps the single shared reference authoritative.
            fresh = _new_scan_state()
            _scan_state.clear()
            _scan_state.update(fresh)
            _scan_state["running"] = True
            _scan_state["started_at"] = datetime.now(timezone.utc).isoformat()

        def _progress_cb(phase: str, status: str, records: int = 0, error: str | None = None):
            """Called by vuln_scanner on each phase transition."""
            with _scan_state_lock:
                _scan_state["phase"] = phase
                if phase in _scan_state["per_source"]:
                    _scan_state["per_source"][phase] = {
                        "status": status,
                        "records": int(records or 0),
                        "error": error,
                    }

        def _runner():
            try:
                from claude_monitoring.vuln_scanner import run_full_scan

                db = get_thread_db()
                try:
                    results = run_full_scan(db, progress_cb=_progress_cb)
                finally:
                    db.close()
                with _scan_state_lock:
                    _scan_state["totals"] = {
                        "vulns_found": int(results.get("vulns_found", 0)),
                        "packages_scanned": int(results.get("scanned", 0)),
                        "new_since_last_scan": int(results.get("new_since_last_scan", 0)),
                    }
                    _scan_state["phase"] = "done"
                    _scan_state["running"] = False
                    _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            except Exception as exc:
                with _scan_state_lock:
                    _scan_state["running"] = False
                    _scan_state["phase"] = "error"
                    _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                    _scan_state["error"] = str(exc)[:300]

        threading.Thread(target=_runner, daemon=True, name="SupplyChainScan").start()
        self._send_json({"started": True, "started_at": _scan_state["started_at"]})

    def _api_supply_chain_scan_progress(self, params):
        """GET current scan state snapshot (Feature B)."""
        with _scan_state_lock:
            snapshot = json.loads(json.dumps(_scan_state))  # deep copy
        self._send_json(snapshot)

    def _api_supply_chain_intel_refresh(self, payload):
        """POST: refresh threat intel feeds (ThreatFox + URLhaus) only.

        Runs in a daemon thread so the HTTP request returns immediately.
        This is distinct from ``/api/supply-chain/scan`` — it only hits
        the intel feeds, not pip-audit or OSV. Good for a user who wants
        fresh IOCs without waiting 90s for a full package scan.

        Rejects if a full scan is already in progress (avoids thrashing
        the same DB connection + double-writing intel_source_status rows).
        """
        with _scan_state_lock:
            if _scan_state["running"]:
                self._send_json(
                    {
                        "error": "scan already in progress",
                        "started_at": _scan_state["started_at"],
                    },
                    409,
                )
                return

        def _refresher():
            try:
                from claude_monitoring.threat_intel import (
                    fetch_threatfox_iocs,
                    fetch_urlhaus_iocs,
                    store_iocs,
                )

                db = get_thread_db()
                try:
                    iocs = fetch_threatfox_iocs(db=db)
                    if iocs and (iocs.get("ips") or iocs.get("domains")):
                        store_iocs(db, iocs)
                    fetch_urlhaus_iocs(db)
                finally:
                    db.close()
            except Exception:
                pass  # errors are recorded via record_intel_status in the fetchers

        threading.Thread(target=_refresher, daemon=True, name="IntelRefresh").start()
        self._send_json({"started": True})

    def _api_supply_chain_scan_status(self, params):
        """Get last scan info."""
        db = get_thread_db()
        row = db.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
        vuln_count = db.execute("SELECT COUNT(DISTINCT vuln_id) FROM package_vulnerabilities").fetchone()[0]
        pkg_count = db.execute("SELECT COUNT(DISTINCT package_name) FROM package_vulnerabilities").fetchone()[0]
        self._send_json(
            {
                "last_scan": dict(row) if row else None,
                "total_vulns": vuln_count,
                "packages_with_vulns": pkg_count,
            }
        )

    def _api_supply_chain_detail(self, params):
        """Individual install events for a specific package (click-to-expand)."""
        db = get_thread_db()
        pkg = params.get("package", [""])[0]
        mgr = params.get("manager", [""])[0]
        if not pkg:
            self._send_json({"error": "missing package"}, 400)
            return
        conditions = ["d.package_name = ?"]
        bind = [pkg]
        if mgr:
            conditions.append("d.package_manager = ?")
            bind.append(mgr)
        where = " AND ".join(conditions)
        sql = f"""SELECT d.*, s.title as session_title
                  FROM agent_dependencies d
                  LEFT JOIN sessions s ON d.session_id = s.session_id
                  WHERE {where} ORDER BY d.timestamp DESC LIMIT 50"""  # nosec B608
        rows = db.execute(sql, bind).fetchall()
        self._send_json({"installs": [dict(r) for r in rows]})

    def _api_report(self, params):
        """Generate a summary report in various formats."""
        from claude_monitoring.report import generate_summary_report

        days = int(params.get("days", ["7"])[0])
        fmt = params.get("format", ["html"])[0]

        content = generate_summary_report(DB_PATH, days, fmt)

        if fmt == "html":
            self._send_html(content)
        elif fmt == "csv":
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename=report_{days}d.csv")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            # markdown
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename=report_{days}d.md")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)


def _format_uptime(create_time):
    """Format process uptime from create_time."""
    if not create_time:
        return "unknown"
    try:
        elapsed = time.time() - create_time
        if elapsed < 60:
            return f"{int(elapsed)}s"
        elif elapsed < 3600:
            return f"{int(elapsed / 60)}m"
        else:
            return f"{int(elapsed / 3600)}h {int((elapsed % 3600) / 60)}m"
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────────
# SECTION 9: DASHBOARD HTML/JS/CSS
# ─────────────────────────────────────────────────────────────


def _load_dashboard_html():
    """Load dashboard HTML from package data."""
    try:
        import importlib.resources

        return importlib.resources.files("claude_monitoring").joinpath("dashboard.html").read_text()
    except Exception:
        return "<html><body><h1>Dashboard HTML not found</h1></body></html>"


DASHBOARD_HTML = _load_dashboard_html()


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
# SECTION 11: MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────


def start_monitoring(cp_url=None, cp_api_key=None):
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
        get_monitor_pid_file,
        remove_pid_file,
        write_heartbeat,
        write_pid_file,
    )

    write_pid_file(get_monitor_pid_file(), os.getpid())

    def _atexit_cleanup():
        remove_pid_file(get_monitor_pid_file())
        pm = globals().get("_PROXY_MANAGER")
        if pm is not None:
            try:
                pm.stop(disable_proxy=True)
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

    # Web Dashboard
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address = True

        def handle_error(self, request, client_address):
            """Suppress BrokenPipeError tracebacks from disconnected clients."""
            import sys

            exc_type = sys.exc_info()[0]
            if exc_type is BrokenPipeError:
                return
            super().handle_error(request, client_address)

    server = ReusableHTTPServer((get_bind_address(), DASHBOARD_PORT), DashboardHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="Dashboard")
    server_thread.start()
    if dashboard_token:
        print(f"\n  Dashboard: http://localhost:{DASHBOARD_PORT}?token={dashboard_token}")
        print("  (Bookmark this URL — the token is remembered by the browser.)")
    else:
        print(f"\n  Dashboard: http://localhost:{DASHBOARD_PORT}")
    print("\n  Press Ctrl+C to stop")
    print("=" * 62)

    # Control plane sync agent (optional)
    sync_agent = None
    if cp_url and cp_api_key:
        try:
            from claude_monitoring.sync import SyncAgent

            sync_agent = SyncAgent(cp_url, cp_api_key)
            sync_agent.start()
            print(f"  Control Plane sync: {cp_url} (every 30s)")
        except ImportError:
            print("  WARNING: requests library needed for control plane sync (pip install requests)")

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
            if pm is not None and not pm.is_alive():
                healthy_streak = 0
                print("\n  ⚠ Watchdog: mitmdump died — disabling system proxy")
                try:
                    from claude_monitoring.lifecycle import disable_system_proxy

                    disable_system_proxy()
                except Exception:
                    pass
                if pm.restart():
                    print("  ✅ Watchdog: mitmdump restarted")
                else:
                    print("  ❌ Watchdog: max restart attempts reached — giving up")
            elif pm is not None:
                healthy_streak += 1
                if healthy_streak >= HEALTHY_TICKS_BEFORE_RESET:
                    pm.reset_restart_count()
            stop_event.wait(30)

    watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True, name="Watchdog")
    watchdog_thread.start()

    def signal_handler(sig, frame):
        print("\n\n  Shutting down...")
        # Phase 1: use ProxyManager for clean shutdown — it kills mitmdump
        # AND disables the system proxy. Fallback to direct networksetup
        # if no ProxyManager is registered (e.g. --start without --with-proxy).
        pm = globals().get("_PROXY_MANAGER")
        if pm is not None:
            try:
                pm.stop(disable_proxy=True)
            except Exception:
                pass
        else:
            try:
                subprocess.run(
                    ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"],
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass
        # Remove PID file so --status doesn't report stale state
        remove_pid_file(get_monitor_pid_file())
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
    parser.add_argument(
        "--enable-system-proxy", action="store_true", help="Enable macOS system proxy (AI domains only)"
    )
    parser.add_argument("--disable-system-proxy", action="store_true", help="Disable macOS system proxy")
    parser.add_argument("--status", action="store_true", help="Show runtime status (monitor, proxy, cert, security)")
    parser.add_argument("--status-json", action="store_true", help="Show runtime status as JSON (for scripts)")
    parser.add_argument("--setup", action="store_true", help="Run the first-time setup wizard (force re-run)")
    parser.add_argument("--cleanup", action="store_true", help="Remove duplicate captures, empty sessions, etc.")
    parser.add_argument("--dry-run", action="store_true", help="Modifier for --cleanup: preview without changes")
    parser.add_argument("--purge", action="store_true", help="Permanently uninstall and delete all monitoring data")
    parser.add_argument("--stop", action="store_true", help="Stop a running monitor + proxy cleanly (uses PID file)")
    parser.add_argument("--control-plane", type=str, default="", help="Control plane URL (e.g. http://localhost:9090)")
    parser.add_argument("--cp-api-key", type=str, default="", help="Control plane API key")
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

    args = parser.parse_args()

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

        sys.exit(0 if run_setup_wizard(force=True) else 1)
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
        start_monitoring(cp_url=args.control_plane or None, cp_api_key=args.cp_api_key or None)
    else:
        parser.print_help()
        print("\n  Quick start: python3 ai_monitor.py --start")


if __name__ == "__main__":
    main()
