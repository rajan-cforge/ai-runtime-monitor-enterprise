"""P6.2 — state-bar envelope builder for /api/state-bar.

Five read-only SQL helpers that feed the four state-bar cells
(monitor / fill_rate / alerts / attack_surface) plus the 7-day
fill-rate sparkline. Extracted from `dashboard_handler.py` so that
file stays under the 2900-line ceiling.

Data-truthful contract (load-bearing per judge p6.2.a2 + spec §4.5):

  * Empty data → 0 (a true negative the operator can act on).
  * Query failure → None (UI renders "—" / "Awaiting data" — never
    "0 critical" while sensitive-data alerts exist).

Mirrors the merged `_api_alerts` derivation
(dashboard_handler.py:1236) for alerts counts so the two derivations
cannot drift. Drops the trigger filter on `discovery_runs` so a
`cli`-triggered scan (P4.6 `--discover`) surfaces as the most-recent.
"""

from __future__ import annotations

import calendar
import json
import sqlite3
import time


def compute_monitor_status(conn) -> dict:
    """Last seen = MAX(timestamp) FROM api_calls. Status maps off the
    time-delta from now (capturing / idle / stopped). Query failure
    returns None so UI renders "—"."""
    try:
        row = conn.execute("SELECT MAX(timestamp) AS last_ts FROM api_calls").fetchone()
    except sqlite3.Error:
        return {"status": None, "last_seen_ts": None, "last_seen_relative": None}
    last_ts_raw = row["last_ts"] if row else None
    if not last_ts_raw:
        return {"status": "idle", "last_seen_ts": None, "last_seen_relative": None}
    # api_calls.timestamp is ISO text in UTC; parse to epoch.
    # Use calendar.timegm (not time.mktime — that interprets the struct
    # as LOCAL time, off-by-TZ-offset from the daemon's UTC writes).
    try:
        last_epoch = calendar.timegm(time.strptime(last_ts_raw[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return {"status": None, "last_seen_ts": None, "last_seen_relative": None}
    age = int(time.time()) - last_epoch
    if age < 300:
        status = "capturing"
    elif age < 3600:
        status = "idle"
    else:
        status = "stopped"
    return {"status": status, "last_seen_ts": last_epoch, "last_seen_relative": None}


def compute_fill_rate_24h(conn) -> dict:
    """`count(input_tokens>0) / count(*)` over chat-call paths, last 24h.

    Per directive line 1377 + judge D-path-filter-for-chat-calls: the
    `is_chat_call` column doesn't exist on v0.2.2, so we filter by
    endpoint_path LIKE the two empirical chat-call shapes (anthropic
    `/v1/messages%`, openai `%/chat/completions%`).

    Empty filter (no chat calls in window) → percentage=None +
    Awaiting-data signal. Query failure → all-None envelope.
    """
    cutoff = time.time() - (24 * 3600)
    cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(cutoff))
    try:
        rows = conn.execute(
            """SELECT destination_service AS svc,
                      COUNT(*) AS total,
                      SUM(CASE WHEN input_tokens > 0 THEN 1 ELSE 0 END) AS filled
               FROM api_calls
               WHERE timestamp > ?
                 AND (endpoint_path LIKE '/v1/messages%'
                   OR endpoint_path LIKE '%/chat/completions%')
               GROUP BY destination_service""",
            (cutoff_iso,),
        ).fetchall()
    except sqlite3.Error:
        return {"percentage": None, "filled": None, "total": None, "by_service": {}}
    by_service: dict = {}
    total = 0
    filled = 0
    for r in rows:
        svc = r["svc"] or "unknown"
        t = int(r["total"] or 0)
        f = int(r["filled"] or 0)
        by_service[svc] = {"filled": f, "total": t}
        total += t
        filled += f
    if total == 0:
        # True empty (no chat calls) — different from query failure.
        return {"percentage": None, "filled": 0, "total": 0, "by_service": by_service}
    return {
        "percentage": round(100.0 * filled / total),
        "filled": filled,
        "total": total,
        "by_service": by_service,
    }


def compute_fill_rate_sparkline_7d(conn) -> list:
    """7 daily fill-rate buckets, oldest→newest. Each entry is a
    percentage (int 0-100) or None when the day had zero chat calls.
    UI renders None as a zero-height bar (skips the `.now` class)."""
    result: list = []
    now = int(time.time())
    for days_back in range(6, -1, -1):
        day_end = now - (days_back * 86400)
        day_start = day_end - 86400
        day_start_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(day_start))
        day_end_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(day_end))
        try:
            row = conn.execute(
                """SELECT COUNT(*) AS total,
                          SUM(CASE WHEN input_tokens > 0 THEN 1 ELSE 0 END) AS filled
                   FROM api_calls
                   WHERE timestamp >= ?
                     AND timestamp < ?
                     AND (endpoint_path LIKE '/v1/messages%'
                       OR endpoint_path LIKE '%/chat/completions%')""",
                (day_start_iso, day_end_iso),
            ).fetchone()
        except sqlite3.Error:
            result.append(None)
            continue
        t = int(row["total"] or 0)
        f = int(row["filled"] or 0)
        result.append(round(100.0 * f / t) if t > 0 else None)
    return result


def compute_alerts_counts(conn) -> dict:
    """Mirror _api_alerts' derivation so the two derivations cannot drift:
    events LEFT JOIN alert_triage on event_id; dismissed = verdict='dismissed'
    (P9.3 schema migration 0.2.2.003); severity parsed from data_json in
    Python.

    Returns None counts on query failure (UI → "—"); returns 0/0 on an
    empty events table (a true negative). Pinned by
    TestComputeAlertsCounts inversion tests.
    """
    try:
        rows = conn.execute(
            """SELECT e.data_json, t.verdict AS triage_verdict
               FROM events e
               LEFT JOIN alert_triage t ON e.id = t.event_id
               WHERE e.event_type = 'sensitive_data'"""
        ).fetchall()
    except sqlite3.Error:
        return {"critical_count": None, "total_count": None}
    critical = 0
    total = 0
    for r in rows:
        if r["triage_verdict"] == "dismissed":
            continue  # dismissed; same exclusion _api_alerts applies
        try:
            data = json.loads(r["data_json"])
        except (json.JSONDecodeError, TypeError):
            data = {}
        sev = data.get("severity", "medium")  # same default as _api_alerts
        total += 1
        if sev == "critical":
            critical += 1
    return {"critical_count": critical, "total_count": total}


def compute_attack_surface_last_scan(conn) -> dict:
    """Most-recent completed discovery scan across ALL triggers
    (cli / scheduled / on_demand). Per judge p6.2.a2
    D-no-trigger-filter-on-last-scan: a `vigil --discover` (cli) scan
    would have been hidden by a trigger filter — the mockup cell means
    'most recent completed scan, full stop'."""
    try:
        row = conn.execute(
            """SELECT MAX(completed_at) AS last_scan_ts
               FROM discovery_runs
               WHERE completed_at IS NOT NULL"""
        ).fetchone()
        in_progress_row = conn.execute(
            """SELECT 1 FROM discovery_runs
               WHERE completed_at IS NULL LIMIT 1"""
        ).fetchone()
    except sqlite3.Error:
        return {"last_scan_ts": None, "in_progress": False}
    return {
        "last_scan_ts": row["last_scan_ts"] if row else None,
        "in_progress": in_progress_row is not None,
    }


def build_envelope(conn) -> dict:
    """Assemble the 5-key envelope shape the /api/state-bar route
    returns. Single source of truth for the state-bar contract."""
    return {
        "monitor": compute_monitor_status(conn),
        "fill_rate": compute_fill_rate_24h(conn),
        "fill_rate_sparkline_7d": compute_fill_rate_sparkline_7d(conn),
        "alerts": compute_alerts_counts(conn),
        "attack_surface": compute_attack_surface_last_scan(conn),
    }
