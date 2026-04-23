# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Client sync agent for AI Runtime Monitor control plane integration.

Background thread that periodically reads new data from the local monitor.db
and POSTs it to the control plane server.
"""

import json
import platform
import socket
import sqlite3
import threading

from claude_monitoring.config import get_db_path
from claude_monitoring.utils import now_iso

# Fields that may carry free-form text captured from agent sessions and
# could incidentally contain secrets (API keys pasted into prompts, AWS
# keys surfaced in tool outputs). The pre-sync sanitizer walks every
# payload, and wherever it encounters one of these keys with a string
# value, it runs scan_sensitive + mask_value inline. Defense in depth —
# the primary sensitive-data pipeline already masks on capture, but the
# sync layer must not blindly trust upstream for P1-04.
_SANITIZE_TEXT_FIELDS = {
    "text",
    "snippet",
    "matched_value",
    "match_context",
    "command",
    "output",
    "input_preview",
    "content",
    "content_text",
    "title",
    "cwd",
    "summary",
}


class SyncAgent:
    """Background thread that syncs local monitor.db to the control plane."""

    def __init__(self, cp_url, api_key, interval=30):
        self.cp_url = cp_url.rstrip("/")
        self.api_key = api_key
        self.interval = interval
        self.endpoint_id = None
        self._stop = threading.Event()
        self._backoff_time = 1
        self._max_backoff = 60

    def start(self):
        """Start sync loop in daemon thread."""
        thread = threading.Thread(target=self._sync_loop, daemon=True, name="SyncAgent")
        thread.start()
        return thread

    def stop(self):
        self._stop.set()

    def _sync_loop(self):
        """Main loop: read new data, POST to CP, update watermarks."""
        while not self._stop.is_set():
            try:
                self._do_sync()
                self._backoff_time = 1  # reset on success
            except Exception as e:
                print(f"  [SyncAgent] Sync failed: {e}")
                self._stop.wait(min(self._backoff_time, self._max_backoff))
                self._backoff_time = min(self._backoff_time * 2, self._max_backoff)
                continue
            self._stop.wait(self.interval)

    def _do_sync(self):
        """Single sync cycle."""
        import requests

        db_path = get_db_path()
        if not db_path.exists():
            return

        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        # Ensure sync_state table exists
        conn.execute("""CREATE TABLE IF NOT EXISTS sync_state (
            table_name TEXT PRIMARY KEY,
            last_synced_id INTEGER DEFAULT 0,
            last_sync_time TEXT
        )""")
        conn.commit()

        watermarks = {}
        for row in conn.execute("SELECT table_name, last_synced_id FROM sync_state").fetchall():
            watermarks[row["table_name"]] = row["last_synced_id"]

        # Read new data. P0-01: the helpers now return (rows, max_id)
        # and watermarks advance to the max id actually seen in the
        # batch — NOT `previous + len(batch)`, which was silently
        # wrong when there were id gaps (deleted rows, INSERT OR
        # IGNORE paths) AND was completely broken for sessions where
        # the query ignored last_id entirely.
        new_sessions, sessions_max_id = self._read_sessions(conn, watermarks.get("sessions", 0))
        new_events, events_max_id = self._read_events(conn, watermarks.get("events", 0))
        new_api_calls, api_calls_max_id = self._read_api_calls(conn, watermarks.get("api_calls", 0))
        new_alerts = self._extract_alerts(new_events)

        if not any([new_sessions, new_events, new_api_calls]):
            conn.close()
            return

        # Build payload
        payload = {
            "endpoint": self._get_endpoint_info(),
            "sessions": new_sessions,
            "events": new_events,
            "api_calls": new_api_calls,
            "alerts": new_alerts,
            "watermarks": {
                "events": events_max_id,
                "sessions": sessions_max_id,
                "api_calls": api_calls_max_id,
            },
        }

        # P1-04: scrub every free-form text field in the payload for
        # plaintext credentials before transmission. This is defense
        # in depth — the primary capture paths already mask on write,
        # but historical rows from before the masking fix, or any path
        # that stores raw text (future or current), must not leak to
        # the control plane. Uses the same scan_sensitive + mask_value
        # logic as the ingest-side capture.
        payload = _sanitize_payload(payload)

        response = requests.post(
            f"{self.cp_url}/api/v1/ingest",
            json=payload,
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
            timeout=10,
        )
        response.raise_for_status()

        result = response.json()
        self.endpoint_id = result.get("endpoint_id")

        # Update local watermarks
        for table_name, last_id in payload["watermarks"].items():
            conn.execute(
                "INSERT INTO sync_state (table_name, last_synced_id, last_sync_time) "
                "VALUES (?, ?, ?) ON CONFLICT(table_name) DO UPDATE SET "
                "last_synced_id = excluded.last_synced_id, last_sync_time = excluded.last_sync_time",
                (table_name, last_id, now_iso()),
            )
        conn.commit()
        conn.close()

        stored = result.get("stored", {})
        total = sum(stored.values()) if isinstance(stored, dict) else 0
        if total > 0:
            print(f"  [SyncAgent] Synced {total} records to {self.cp_url}")

    def _get_endpoint_info(self):
        return {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()} {platform.machine()}",
            "ip": "",
            "monitor_version": "0.2.0",
        }

    def _read_sessions(self, conn, last_id):
        """Read UNSYNCED sessions using rowid as the watermark.

        P0-01: the previous version was `ORDER BY rowid LIMIT 100` with
        no WHERE clause — it ignored last_id entirely and re-sent the
        first 100 rowids on every sync forever. Any sessions after
        rowid 100 were invisible to the control plane.

        Returns (rows, max_rowid_seen) so the caller can persist the
        correct watermark — simply adding len() to the previous
        watermark is wrong when there are rowid gaps (deleted rows).
        """
        rows = conn.execute(
            "SELECT rowid, * FROM sessions WHERE rowid > ? ORDER BY rowid LIMIT 100",
            (last_id,),
        ).fetchall()
        results = []
        max_rowid = last_id
        for r in rows:
            max_rowid = max(max_rowid, r["rowid"])
            results.append(
                {
                    "client_session_id": r["session_id"],
                    "start_time": r["start_time"],
                    "cwd": r["cwd"],
                    "model": r["model"],
                    "agent_type": r["agent_type"] if "agent_type" in r.keys() else None,
                    "title": r["title"] if "title" in r.keys() else None,
                    "total_input_tokens": r["total_input_tokens"] or 0,
                    "total_output_tokens": r["total_output_tokens"] or 0,
                    "total_turns": r["total_turns"] or 0,
                    "total_cost": r["total_cost"] or 0,
                    "last_activity": r["last_activity"],
                }
            )
        return results, max_rowid

    def _read_events(self, conn, last_id):
        """Read unsynced events. Returns (rows, max_id_seen)."""
        rows = conn.execute(
            "SELECT id, timestamp, session_id, event_type, source_layer, data_json "
            "FROM events WHERE id > ? ORDER BY id LIMIT 500",
            (last_id,),
        ).fetchall()
        results = []
        max_id = last_id
        for r in rows:
            max_id = max(max_id, r["id"])
            try:
                data = json.loads(r["data_json"])
            except (json.JSONDecodeError, TypeError):
                data = {}
            results.append(
                {
                    "client_event_id": r["id"],
                    "timestamp": r["timestamp"],
                    "session_id": r["session_id"],
                    "event_type": r["event_type"],
                    "source_layer": r["source_layer"],
                    "data_json": data,
                }
            )
        return results, max_id

    def _read_api_calls(self, conn, last_id):
        """Read unsynced api_calls. Returns (rows, max_id_seen)."""
        rows = conn.execute(
            "SELECT id, timestamp, session_id, model, destination_service, "
            "input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, "
            "estimated_cost_usd, latency_ms FROM api_calls WHERE id > ? ORDER BY id LIMIT 200",
            (last_id,),
        ).fetchall()
        results = []
        max_id = last_id
        for r in rows:
            max_id = max(max_id, r["id"])
            results.append(
                {
                    "client_call_id": r["id"],
                    "timestamp": r["timestamp"],
                    "session_id": r["session_id"],
                    "model": r["model"],
                    "destination_service": r["destination_service"],
                    "input_tokens": r["input_tokens"] or 0,
                    "output_tokens": r["output_tokens"] or 0,
                    "cache_read_tokens": r["cache_read_tokens"] or 0,
                    "cache_write_tokens": r["cache_write_tokens"] or 0,
                    "estimated_cost_usd": r["estimated_cost_usd"] or 0,
                    "latency_ms": r["latency_ms"] or 0,
                }
            )
        return results, max_id

    def _extract_alerts(self, events):
        """Extract sensitive_data events as alerts."""
        alerts = []
        for ev in events:
            if ev["event_type"] == "sensitive_data":
                data = ev["data_json"]
                alerts.append(
                    {
                        "client_event_id": ev["client_event_id"],
                        "timestamp": ev["timestamp"],
                        "session_id": ev["session_id"],
                        "severity": data.get("severity", "medium"),
                        "patterns": data.get("patterns", []),
                        "context": data.get("context", ""),
                        "snippet": data.get("snippet", ""),
                        "validated": data.get("validated", False),
                        "confidence": data.get("confidence"),
                    }
                )
        return alerts


def _sanitize_string(value: str) -> str:
    """Scan a free-form string for secrets and inline-mask each match.

    Uses the same scan_sensitive + mask_value pair that the primary
    capture pipelines use (monitor.py::_check_sensitive). Returns the
    input unchanged if no matches found or the scan fails.
    """
    if not value or not isinstance(value, str):
        return value
    try:
        from claude_monitoring.security import mask_value
        from claude_monitoring.utils import scan_sensitive

        matches = scan_sensitive(value[:5000])
        if not matches:
            return value
        sanitized = value
        for m in matches:
            raw = m.get("matched_value") or ""
            if raw and raw in sanitized:
                sanitized = sanitized.replace(raw, mask_value(raw))
        return sanitized
    except Exception:
        # Fail closed: if scan crashes, return input unchanged rather
        # than dropping the payload. The primary capture pipeline has
        # already sanitized most fields; this is belt-and-suspenders.
        return value


def _sanitize_payload(obj):
    """Recursively walk a payload and mask text fields in place.

    Only masks values under keys listed in ``_SANITIZE_TEXT_FIELDS``.
    Other fields (numbers, IDs, timestamps, model names, etc.) pass
    through unchanged so the control plane still gets useful telemetry.
    """
    if isinstance(obj, dict):
        return {
            k: (_sanitize_string(v) if (k in _SANITIZE_TEXT_FIELDS and isinstance(v, str)) else _sanitize_payload(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize_payload(item) for item in obj]
    return obj
