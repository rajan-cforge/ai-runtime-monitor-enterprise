"""DashboardHandler — HTTP request handler for the Vigil web dashboard.

Pure-move extraction from `monitor.py` (PR 2026-06-12, Rajan-ratified
Path 1 closeout after the file_size cap hit). Zero behavior change.
Every route keeps its `verify_token` gate via `_check_auth` per the
no-ungated-DashboardHandler-routes hard rule. Imports are listed
verbatim from `monitor.py`'s top-of-file; nothing was reordered or
deduplicated during the move.

Re-exported from `monitor.py` (`from claude_monitoring.dashboard_handler
import DashboardHandler, DASHBOARD_HTML`) so existing call sites
(internal + tests + first-party consumers) continue to work
without source change.

Follow-ups deferred per pure-move discipline (do NOT fold here):

- consolidate the `_api_*` methods into a delegate map keyed in one
  place (today they're individually registered in the `routes` dict
  inside `do_GET` and individually defined as methods);
- promote `_send_json` / `_send_html` / `_send_csv` to a shared
  response-helpers module;
- audit the silent `except Exception: pass` blocks (baselined design-
  pattern violations) for individual-purpose error handling.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

try:
    import psutil
except ImportError:
    psutil = None

# Late-bound back-reference to `monitor` module-level state (DB_PATH,
# live_feed, JSONLSessionWatcher, compute_forecast, etc.). monitor.py
# imports DashboardHandler from this module at top level, so we cannot
# eager-import from monitor at module load time. A direct
# `from claude_monitoring import monitor as _monitor` also breaks under
# `python -m claude_monitoring.monitor`: that runs monitor.py as
# `__main__` AND triggers a second load as `claude_monitoring.monitor`
# when dashboard_handler tries to import it, re-entering monitor.py at
# the same import line and failing on `DASHBOARD_HTML` not yet existing.
# This proxy defers the lookup to method-call time via sys.modules; by
# then both monitor and dashboard_handler are fully loaded. Tests using
# `patch("claude_monitoring.monitor.DB_PATH", ...)` continue to work
# because the proxy resolves the patched attribute on every access.
import sys

from claude_monitoring.constants import (
    BROWSER_SERVICE_AGENT_MAP,
    TOOL_RISK_MAP,
)
from claude_monitoring.db import get_thread_db
from claude_monitoring.utils import is_ai_process, now_iso, scan_sensitive


class _MonitorProxy:
    def __getattr__(self, name):
        return getattr(sys.modules["claude_monitoring.monitor"], name)


_monitor = _MonitorProxy()


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
            "/api/state-bar": self._api_state_bar,
            "/api/system-tab": self._api_system_tab,
            "/api/traffic/summary": self._api_traffic_summary,
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
            "/api/assets": self._api_assets,
            "/api/assets/new-in-24h": self._api_assets_new_in_24h,
            "/api/asset_detail": self._api_asset_detail,
            "/api/asset_activity": self._api_asset_activity,
            "/api/asset_history": self._api_asset_history,
        }

        # Match path prefixes for dynamic routes
        if path.startswith("/api/asset/"):
            remainder = path.split("/api/asset/", 1)[1]
            if remainder.endswith("/activity"):
                params["id"] = [remainder[: -len("/activity")]]
                path = "/api/asset_activity"
            elif remainder.endswith("/history"):
                params["id"] = [remainder[: -len("/history")]]
                path = "/api/asset_history"
            else:
                params["id"] = [remainder]
                path = "/api/asset_detail"
        elif path.startswith("/api/browser/session/"):
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
                _monitor.push_live_event(
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
                    "prompt_preview": _monitor.JSONLSessionWatcher._clean_title(data.get("text", "") or "")[:80],
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

        with _monitor.live_feed_lock:
            items = list(_monitor.live_feed)

        if since:
            items = [i for i in items if i.get("timestamp", "") > since]

        items = items[-limit:]
        self._send_json({"events": items})

    def _api_state_bar(self, params):
        """GET /api/state-bar — state-bar envelope per directive line 222
        + Round 4 mockup. Cells: monitor / fill_rate / alerts /
        attack_surface. Helpers live in `dashboard_state_bar` so this
        file stays under the 2900-line ceiling."""
        from claude_monitoring import dashboard_state_bar

        self._send_json(dashboard_state_bar.build_envelope(get_thread_db()))

    def _api_system_tab(self, params):
        """GET /api/system-tab — System-tab envelope per directive line
        223-228 + Round 4 mockup. Three sections: staleness_banners,
        capture_matrix, per_host_capture_rate. Helpers live in
        `dashboard_system_tab` so this file stays under the 2900-line
        ceiling."""
        from claude_monitoring import dashboard_system_tab

        self._send_json(dashboard_system_tab.build_envelope(get_thread_db()))

    def _api_traffic_summary(self, params):
        """GET /api/traffic/summary — API Traffic counter envelope per
        directive line 230. Three counters (intercepted / chat_calls /
        content_captured) + 24h fill rate. Helpers live in
        `dashboard_api_traffic`. Per judge p6.4.a2 the predicate is
        verbatim from P6.2's `filled` so the header counter, the row
        badge, and the state-bar fill-rate cannot drift."""
        from claude_monitoring import dashboard_api_traffic

        self._send_json(dashboard_api_traffic.build_envelope(get_thread_db()))

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
        forecast = _monitor.compute_forecast(db)

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
                "plan_info": _monitor.plan_info,
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
            # Lazy import to avoid circular: monitor.py imports
            # DashboardHandler from this module at top level.
            from claude_monitoring.monitor import _enrich_supply_chain_alert

            package_info = _enrich_supply_chain_alert(db, r["session_id"], data)

            alert_row = {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "session_id": r["session_id"],
                "session_title": _monitor.JSONLSessionWatcher._clean_title(r["title"])
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

    # ── Attack-surface assets endpoints ────────────────────────
    #
    # `dashboard-asset-view` PR (2026-06-11, judge-queued + Rajan-
    # ratified). Body lives in `attack_surface/dashboard_api.py` so
    # monitor.py stays under the 5500-line ceiling. The handlers are
    # thin wrappers — the rendering rules (Amendment C) and SQL live in
    # the extracted module.

    def _api_assets(self, params):
        """Asset list — delegates to `attack_surface.dashboard_api.list_assets`."""
        from claude_monitoring.attack_surface.dashboard_api import list_assets

        self._send_json(list_assets(get_thread_db(), params))

    def _api_asset_detail(self, params):
        """Asset detail — delegates to `attack_surface.dashboard_api.get_asset_detail`."""
        from claude_monitoring.attack_surface.dashboard_api import get_asset_detail

        payload, status = get_asset_detail(get_thread_db(), params)
        self._send_json(payload, status)

    def _api_asset_activity(self, params):
        """Per-asset runtime activity correlation — P4.3 (spec §7 + §7.1.1).

        Thin handler: gates `capture_off` on heartbeat health (lifecycle
        concern, can't live in the data-layer correlator) and delegates
        the real work to `attack_surface.activity.correlate_asset_activity`.
        Same `_check_auth` gate as every other `/api/*` route; route
        registered in `do_GET`'s `routes` dict and path-prefix matched
        from `/api/asset/<id>/activity`.
        """
        from claude_monitoring.attack_surface.activity import correlate_asset_activity
        from claude_monitoring.lifecycle import HEARTBEAT_STALE_SECONDS, heartbeat_age_seconds

        asset_id = params.get("id", [""])[0]
        if not asset_id:
            self._send_json({"error": "missing id"}, 400)
            return
        window = params.get("window", ["24h"])[0]
        hb_age = heartbeat_age_seconds()
        capture_ok = hb_age is not None and hb_age < HEARTBEAT_STALE_SECONDS
        try:
            result = correlate_asset_activity(
                get_thread_db(),
                asset_id,
                window=window,
                capture_ok=capture_ok,
            )
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
            return
        if result.data_status == "asset_not_found":
            self._send_json({"error": "not found", "id": asset_id}, 404)
            return
        self._send_json(result.to_payload())

    def _api_asset_history(self, params):
        """Per-asset temporal audit trail — P4.4 (spec §9.1 + amendment).

        Returns reverse-chronological history rows for one asset, each
        joined to its producing discovery_runs row for trigger
        attribution. LEFT JOIN renders ``trigger="unknown"`` for orphan
        FKs (deleted run) so the endpoint never 500s on a half-consistent
        DB. Same ``_check_auth`` gate as every other ``/api/*`` route.
        """
        from claude_monitoring.attack_surface.dashboard_api import get_asset_history

        asset_id = params.get("id", [""])[0]
        if not asset_id:
            self._send_json({"error": "missing id"}, 400)
            return
        payload, status = get_asset_history(get_thread_db(), asset_id)
        self._send_json(payload, status)

    def _api_assets_new_in_24h(self, params):
        """Count assets with first_seen within the last 24h. Q1
        data-truthfulness condition (judge p4.4.a3): distinguish
        ``no_runs`` (discovery never executed) from ``no_new`` (runs
        exist, zero new in window). UI must render different copy.
        """
        from claude_monitoring.attack_surface.dashboard_api import get_new_in_24h

        payload, status = get_new_in_24h(get_thread_db())
        self._send_json(payload, status)

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
        with _monitor._scan_state_lock:
            if _monitor._scan_state["running"]:
                self._send_json(
                    {
                        "error": "scan already in progress",
                        "started_at": _monitor._scan_state["started_at"],
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
            fresh = _monitor._new_scan_state()
            _monitor._scan_state.clear()
            _monitor._scan_state.update(fresh)
            _monitor._scan_state["running"] = True
            _monitor._scan_state["started_at"] = datetime.now(timezone.utc).isoformat()

        def _progress_cb(phase: str, status: str, records: int = 0, error: str | None = None):
            """Called by vuln_scanner on each phase transition."""
            with _monitor._scan_state_lock:
                _monitor._scan_state["phase"] = phase
                if phase in _monitor._scan_state["per_source"]:
                    _monitor._scan_state["per_source"][phase] = {
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
                with _monitor._scan_state_lock:
                    _monitor._scan_state["totals"] = {
                        "vulns_found": int(results.get("vulns_found", 0)),
                        "packages_scanned": int(results.get("scanned", 0)),
                        "new_since_last_scan": int(results.get("new_since_last_scan", 0)),
                    }
                    _monitor._scan_state["phase"] = "done"
                    _monitor._scan_state["running"] = False
                    _monitor._scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            except Exception as exc:
                with _monitor._scan_state_lock:
                    _monitor._scan_state["running"] = False
                    _monitor._scan_state["phase"] = "error"
                    _monitor._scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                    _monitor._scan_state["error"] = str(exc)[:300]

        threading.Thread(target=_runner, daemon=True, name="SupplyChainScan").start()
        self._send_json({"started": True, "started_at": _monitor._scan_state["started_at"]})

    def _api_supply_chain_scan_progress(self, params):
        """GET current scan state snapshot (Feature B)."""
        with _monitor._scan_state_lock:
            snapshot = json.loads(json.dumps(_monitor._scan_state))  # deep copy
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
        with _monitor._scan_state_lock:
            if _monitor._scan_state["running"]:
                self._send_json(
                    {
                        "error": "scan already in progress",
                        "started_at": _monitor._scan_state["started_at"],
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

        content = generate_summary_report(_monitor.DB_PATH, days, fmt)

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


def _load_dashboard_html():
    """Load dashboard HTML from package data."""
    try:
        import importlib.resources

        return importlib.resources.files("claude_monitoring").joinpath("dashboard.html").read_text()
    except Exception:
        return "<html><body><h1>Dashboard HTML not found</h1></body></html>"


DASHBOARD_HTML = _load_dashboard_html()
