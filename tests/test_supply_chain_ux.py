# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for Feature A (intel source health), Feature B (async scan progress),
and Feature C (alert investigation enrichment).

These were added as part of the Supply Chain polish sprint. The three
features share a test file because they all revolve around the same
endpoints and DB tables.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from urllib.request import Request, urlopen

import pytest

from claude_monitoring.db import init_db
from claude_monitoring.threat_intel import record_intel_status

# ─────────────────────────────────────────────────────────────
# Shared fixtures — matches test_api.py pattern
# ─────────────────────────────────────────────────────────────


@pytest.fixture()
def sc_server(tmp_path, monkeypatch):
    """Spin up a DashboardHandler with a fresh DB for endpoint tests.

    Auth is disabled via DISABLE_DASHBOARD_AUTH=1 so tests don't need
    to manage tokens.
    """
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path = tmp_path / "monitor.db"
    init_db(db_path).close()

    monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
    monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
    monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
    monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
    from claude_monitoring import monitor as mon

    monkeypatch.setattr(mon, "DB_PATH", db_path)
    monkeypatch.setattr(mon, "OUTPUT_DIR", tmp_path)

    server = HTTPServer(("127.0.0.1", 0), mon.DashboardHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", db_path
    server.shutdown()


def _get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode())


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    req = Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except Exception as exc:
        # HTTPError exposes .code and .read() for error bodies
        from urllib.error import HTTPError

        if isinstance(exc, HTTPError):
            try:
                body = json.loads(exc.read().decode())
            except Exception:
                body = {}
            return exc.code, body
        raise


# ─────────────────────────────────────────────────────────────
# Feature A — intel state machine
# ─────────────────────────────────────────────────────────────


class TestIntelStateMachine:
    def test_gray_when_never_fetched(self, sc_server):
        base, _ = sc_server
        data = _get_json(f"{base}/api/supply-chain/intel-status")
        # threatfox and urlhaus should default to gray on a fresh DB
        tf = next(s for s in data["sources"] if s["short_name"] == "threatfox")
        uh = next(s for s in data["sources"] if s["short_name"] == "urlhaus")
        assert tf["state"] == "gray"
        assert uh["state"] == "gray"

    def test_green_when_fresh_success(self, sc_server):
        base, db_path = sc_server
        conn = sqlite3.connect(str(db_path))
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO intel_source_status (name, last_attempt, last_success, last_error, record_count, updated_at) "
            "VALUES (?, ?, ?, NULL, ?, ?)",
            ("threatfox", now, now, 523, now),
        )
        conn.commit()
        conn.close()

        data = _get_json(f"{base}/api/supply-chain/intel-status")
        tf = next(s for s in data["sources"] if s["short_name"] == "threatfox")
        assert tf["state"] == "green"
        assert tf["records"] == 523
        assert tf["active"] is True  # legacy field still works

    def test_yellow_when_stale_success(self, sc_server):
        base, db_path = sc_server
        conn = sqlite3.connect(str(db_path))
        stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn.execute(
            "INSERT INTO intel_source_status (name, last_attempt, last_success, last_error, record_count, updated_at) "
            "VALUES (?, ?, ?, NULL, ?, ?)",
            ("threatfox", stale, stale, 123, stale),
        )
        conn.commit()
        conn.close()

        data = _get_json(f"{base}/api/supply-chain/intel-status")
        tf = next(s for s in data["sources"] if s["short_name"] == "threatfox")
        assert tf["state"] == "yellow"
        assert tf["age_hours"] > 24

    def test_red_when_last_error_set(self, sc_server):
        base, db_path = sc_server
        conn = sqlite3.connect(str(db_path))
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO intel_source_status (name, last_attempt, last_success, last_error, record_count, updated_at) "
            "VALUES (?, ?, NULL, ?, 0, ?)",
            ("urlhaus", now, "connection refused", now),
        )
        conn.commit()
        conn.close()

        data = _get_json(f"{base}/api/supply-chain/intel-status")
        uh = next(s for s in data["sources"] if s["short_name"] == "urlhaus")
        assert uh["state"] == "red"
        assert uh["last_error"] == "connection refused"
        assert uh["active"] is False

    def test_endpoint_returns_all_five_sources(self, sc_server):
        base, _ = sc_server
        data = _get_json(f"{base}/api/supply-chain/intel-status")
        short_names = {s["short_name"] for s in data["sources"]}
        assert short_names == {"osv", "pip-audit", "threatfox", "urlhaus", "registry"}

    def test_records_success_via_helper(self, tmp_path, monkeypatch):
        """record_intel_status() writes a row the endpoint can then read."""
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "test.db")
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "test.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)

        conn = init_db(tmp_path / "test.db")
        try:
            record_intel_status(conn, "threatfox", success=True, record_count=77)
            row = conn.execute(
                "SELECT last_success, record_count FROM intel_source_status WHERE name='threatfox'"
            ).fetchone()
            assert row is not None
            assert row[1] == 77
        finally:
            conn.close()

    def test_records_failure_via_helper(self, tmp_path, monkeypatch):
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "test.db")
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "test.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)

        conn = init_db(tmp_path / "test.db")
        try:
            record_intel_status(conn, "urlhaus", success=False, error="timeout")
            row = conn.execute(
                "SELECT last_attempt, last_success, last_error FROM intel_source_status WHERE name='urlhaus'"
            ).fetchone()
            assert row is not None
            assert row[0] is not None  # last_attempt set
            assert row[1] is None  # last_success NOT set on failure
            assert row[2] == "timeout"
        finally:
            conn.close()

    def test_success_preserves_previous_record_count_on_failure(self, tmp_path, monkeypatch):
        """A later failure shouldn't zero out the previously cached record count."""
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "test.db")
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "test.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)

        conn = init_db(tmp_path / "test.db")
        try:
            record_intel_status(conn, "threatfox", success=True, record_count=42)
            record_intel_status(conn, "threatfox", success=False, error="later failure")
            row = conn.execute(
                "SELECT last_success, last_error, record_count FROM intel_source_status WHERE name='threatfox'"
            ).fetchone()
            assert row[0] is not None  # last_success preserved from earlier success
            assert row[1] == "later failure"
            assert row[2] == 42  # record_count preserved
        finally:
            conn.close()


class TestIntelRefreshEndpoint:
    def test_post_returns_started(self, sc_server, monkeypatch):
        base, _ = sc_server
        # Mock out the actual fetchers so the endpoint doesn't hit real APIs
        from claude_monitoring import threat_intel

        monkeypatch.setattr(threat_intel, "fetch_threatfox_iocs", lambda db=None: {"ips": {}, "domains": {}})
        monkeypatch.setattr(threat_intel, "fetch_urlhaus_iocs", lambda db: 0)
        status, body = _post_json(f"{base}/api/supply-chain/intel-refresh", {})
        assert status == 200
        assert body.get("started") is True


# ─────────────────────────────────────────────────────────────
# Feature B — async scan progress
# ─────────────────────────────────────────────────────────────


class TestAsyncScanProgress:
    def _reset_state(self):
        from claude_monitoring import monitor as mon

        with mon._scan_state_lock:
            mon._scan_state = mon._new_scan_state()

    def test_scan_post_returns_started(self, sc_server, monkeypatch):
        self._reset_state()
        base, _ = sc_server
        from claude_monitoring import vuln_scanner

        def fake_scan(db, progress_cb=None):
            if progress_cb:
                progress_cb("pip-audit", "done", records=0)
                progress_cb("osv", "done", records=0)
                progress_cb("threatfox", "done", records=0)
                progress_cb("urlhaus", "done", records=0)
                progress_cb("registry", "done", records=0)
            return {"scanned": 0, "vulns_found": 0, "new_since_last_scan": 0}

        monkeypatch.setattr(vuln_scanner, "run_full_scan", fake_scan)
        status, body = _post_json(f"{base}/api/supply-chain/scan", {})
        assert status == 200
        assert body.get("started") is True
        assert body.get("started_at") is not None

    def test_scan_progress_endpoint_shape(self, sc_server):
        self._reset_state()
        base, _ = sc_server
        data = _get_json(f"{base}/api/supply-chain/scan-progress")
        assert "running" in data
        assert "per_source" in data
        per = data["per_source"]
        assert set(per.keys()) == {"environment", "pip-audit", "osv", "threatfox", "urlhaus", "registry"}
        for src_state in per.values():
            assert "status" in src_state
            assert "records" in src_state
            assert "error" in src_state

    def test_scan_progress_reports_per_source_state(self, sc_server, monkeypatch):
        self._reset_state()
        base, _ = sc_server
        from claude_monitoring import vuln_scanner

        scan_done = threading.Event()

        def fake_scan(db, progress_cb=None):
            if progress_cb:
                progress_cb("pip-audit", "done", records=3)
                progress_cb("osv", "done", records=12)
                progress_cb("threatfox", "done", records=500)
                progress_cb("urlhaus", "done", records=250)
                progress_cb("registry", "done", records=19)
            scan_done.set()
            return {"scanned": 4, "vulns_found": 15, "new_since_last_scan": 2}

        monkeypatch.setattr(vuln_scanner, "run_full_scan", fake_scan)
        _post_json(f"{base}/api/supply-chain/scan", {})
        assert scan_done.wait(5)

        import time as _t

        data = None
        for _ in range(40):
            data = _get_json(f"{base}/api/supply-chain/scan-progress")
            if data.get("phase") == "done":
                break
            _t.sleep(0.05)

        assert data is not None
        assert data["phase"] == "done"
        assert data["running"] is False
        assert data["per_source"]["pip-audit"]["records"] == 3
        assert data["per_source"]["osv"]["records"] == 12
        assert data["per_source"]["threatfox"]["records"] == 500
        assert data["per_source"]["urlhaus"]["records"] == 250
        assert data["per_source"]["registry"]["records"] == 19
        assert data["totals"]["vulns_found"] == 15
        assert data["totals"]["packages_scanned"] == 4
        assert data["totals"]["new_since_last_scan"] == 2
        self._reset_state()

    def test_concurrent_scan_returns_409(self, sc_server):
        self._reset_state()
        base, _ = sc_server
        from claude_monitoring import monitor as mon

        with mon._scan_state_lock:
            mon._scan_state["running"] = True
            mon._scan_state["started_at"] = "2026-04-14T00:00:00+00:00"
        try:
            status, body = _post_json(f"{base}/api/supply-chain/scan", {})
            assert status == 409
            assert "already in progress" in body.get("error", "").lower()
        finally:
            self._reset_state()

    def test_scan_records_intel_status_for_osv_and_pip_audit(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row

        import claude_monitoring.threat_intel as ti
        import claude_monitoring.vuln_scanner as vs

        monkeypatch.setattr(vs, "run_pip_audit", lambda: [])
        monkeypatch.setattr(vs, "query_osv", lambda *a, **k: [])
        monkeypatch.setattr(ti, "fetch_threatfox_iocs", lambda db=None: {"ips": {}, "domains": {}})
        monkeypatch.setattr(ti, "fetch_urlhaus_iocs", lambda db: 0)

        try:
            vs.run_full_scan(conn)
            rows = {r["name"]: dict(r) for r in conn.execute("SELECT * FROM intel_source_status").fetchall()}
        finally:
            conn.close()
        assert "pip-audit" in rows
        assert "osv" in rows
        assert rows["pip-audit"]["last_success"] is not None
        assert rows["osv"]["last_success"] is not None


# ─────────────────────────────────────────────────────────────
# Feature C — alert investigation enrichment
# ─────────────────────────────────────────────────────────────


def _seed_malicious_alert(db_path, session_id="demo-1", pattern="vulnerable_package"):
    """Insert the rows needed to exercise _enrich_supply_chain_alert."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute(
        "INSERT INTO sessions (session_id, start_time, model, agent_type, title, last_activity) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, "2026-04-14T00:00:00Z", "claude-opus-4", "claude_code", "Demo", "2026-04-14T00:10:00Z"),
    )
    conn.execute(
        "INSERT INTO agent_dependencies (timestamp, session_id, agent_type, action, package_manager, "
        " package_name, package_version, pinned, risk_flags, risk_score, category) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "2026-04-14T00:05:00Z",
            session_id,
            "claude_code",
            "install",
            "npm",
            "strapi-plugin-cron",
            "1.0.0",
            0,
            json.dumps({"reasons": ["Scope mismatch (strapi-plugin-* without @strapi)"]}),
            8,
            "package",
        ),
    )
    conn.execute(
        "INSERT INTO package_vulnerabilities (scan_timestamp, package_name, package_version, "
        " ecosystem, vuln_id, severity, source, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "2026-04-14T00:06:00Z",
            "strapi-plugin-cron",
            "1.0.0",
            "npm",
            "MAL-2024-7153",
            "malicious",
            "osv",
            "Malicious package impersonating @strapi plugins",
        ),
    )
    conn.execute(
        "INSERT INTO package_registry_cache (package_name, manager, fetch_timestamp, metadata) VALUES (?, ?, ?, ?)",
        (
            "strapi-plugin-cron",
            "npm",
            "2026-04-14T00:06:30Z",
            json.dumps(
                {
                    "has_description": False,
                    "has_repository": False,
                    "has_install_scripts": True,
                }
            ),
        ),
    )
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) "
        "VALUES (?, ?, 'sensitive_data', 'supply_chain', ?)",
        (
            "2026-04-14T00:07:00Z",
            session_id,
            json.dumps(
                {
                    "patterns": [pattern],
                    "severity": "critical",
                    "categories": ["credential"],
                    "context": "supply_chain_scan",
                    "snippet": "strapi-plugin-cron detected as malicious",
                    "matched_value": "strapi-plugin-cron",
                    "confidence": "high",
                }
            ),
        ),
    )
    conn.commit()
    conn.close()


def _seed_non_supply_chain_alert(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) "
        "VALUES (?, ?, 'sensitive_data', 'jsonl', ?)",
        (
            "2026-04-14T00:00:00Z",
            None,
            json.dumps(
                {
                    "patterns": ["aws_key"],
                    "severity": "critical",
                    "categories": ["credential"],
                    "context": "tool_result",
                    "snippet": "matched",
                    "matched_value": "AKIA************XXXX",
                    "confidence": "high",
                }
            ),
        ),
    )
    conn.commit()
    conn.close()


class TestAlertEnrichment:
    def test_includes_package_for_supply_chain_pattern(self, sc_server):
        base, db_path = sc_server
        _seed_malicious_alert(db_path)
        data = _get_json(f"{base}/api/alerts?confidence=medium%2B")
        alerts = data["alerts"]
        assert len(alerts) == 1
        a = alerts[0]
        assert "package" in a
        assert a["package"]["name"] == "strapi-plugin-cron"
        assert a["package"]["manager"] == "npm"
        assert a["package"]["advisory_id"] == "MAL-2024-7153"
        assert a["package"]["advisory_url"] == "https://osv.dev/vulnerability/MAL-2024-7153"

    def test_advisory_url_uses_osv_for_mal_prefix(self, sc_server):
        base, db_path = sc_server
        _seed_malicious_alert(db_path)
        data = _get_json(f"{base}/api/alerts?confidence=medium%2B")
        assert "osv.dev/vulnerability/MAL-2024-7153" in data["alerts"][0]["package"]["advisory_url"]

    def test_investigation_includes_malicious_flag(self, sc_server):
        base, db_path = sc_server
        _seed_malicious_alert(db_path)
        data = _get_json(f"{base}/api/alerts?confidence=medium%2B")
        investigation = data["alerts"][0]["package"]["investigation"]
        # Must include the MAL- flag AND the risk_flags reasons AND the registry signals
        assert any("malicious" in item.lower() for item in investigation)
        assert any("scope mismatch" in item.lower() for item in investigation)
        assert any("description" in item.lower() for item in investigation)
        assert any("install scripts" in item.lower() for item in investigation)

    def test_omits_package_for_non_supply_chain(self, sc_server):
        base, db_path = sc_server
        _seed_non_supply_chain_alert(db_path)
        data = _get_json(f"{base}/api/alerts?confidence=medium%2B")
        assert len(data["alerts"]) == 1
        assert "package" not in data["alerts"][0]

    def test_investigation_includes_typosquat_for_typosquat_pattern(self, sc_server):
        base, db_path = sc_server
        _seed_malicious_alert(db_path, session_id="typo-1", pattern="typosquat")
        data = _get_json(f"{base}/api/alerts?confidence=medium%2B")
        assert len(data["alerts"]) == 1
        investigation = data["alerts"][0]["package"]["investigation"]
        assert any("typosquat" in item.lower() for item in investigation)


# ─────────────────────────────────────────────────────────────
# Bug 1 — Desktop Apps filter synthesizes sessions from api_calls
# ─────────────────────────────────────────────────────────────


def _seed_desktop_session(db_path, agent_type, title, api_service=None, call_count=0):
    """Bug 1 fix: desktop sessions live in the sessions table (inserted by
    ProcessScanner._ensure_desktop_session), and _api_sessions enriches
    them with api_calls stats. Tests simulate what ProcessScanner would do.
    """
    conn = sqlite3.connect(str(db_path))
    session_id = "desktop_" + agent_type
    now = "2026-04-14T00:00:00Z"
    conn.execute(
        """INSERT INTO sessions (session_id, agent_type, title, start_time, last_activity,
                                  total_turns, total_input_tokens, total_output_tokens, model)
           VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)
           ON CONFLICT(session_id) DO UPDATE SET last_activity=excluded.last_activity""",
        (session_id, agent_type, title, now, now, agent_type),
    )
    # Optionally seed api_calls for the enrichment path
    if api_service and call_count > 0:
        for i in range(call_count):
            conn.execute(
                "INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number, "
                "destination_host, destination_service, endpoint_path, http_method, http_status, "
                "model, stream, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, "
                "request_size_bytes, response_size_bytes, latency_ms, num_messages, "
                "system_prompt_chars, tool_call_count, sensitive_pattern_count, stop_reason, request_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    f"2026-04-14T00:0{i}:00Z",
                    f"req-{i}",  # per-request UUID (not tied to the synthetic session)
                    f"t{i}",
                    i,
                    f"api.{api_service.split('_')[0]}.com",
                    api_service,
                    "/v1/messages",
                    "POST",
                    200,
                    agent_type,
                    "true",
                    100 * (i + 1),
                    50 * (i + 1),
                    0,
                    0,
                    1000,
                    500,
                    300,
                    5,
                    100,
                    0,
                    0,
                    "end_turn",
                    f"req-{i}",
                ),
            )
    conn.commit()
    conn.close()
    return session_id


class TestDesktopSessionSynthesis:
    def test_desktop_filter_returns_session(self, sc_server):
        base, db_path = sc_server
        _seed_desktop_session(
            db_path,
            "claude_desktop",
            "Claude Desktop App",
            api_service="anthropic_api",
            call_count=5,
        )
        data = _get_json(f"{base}/api/sessions?source=desktop")
        sessions = data["sessions"]
        desktop = [s for s in sessions if s.get("source") == "desktop"]
        assert len(desktop) == 1
        claude = desktop[0]
        assert claude["agent_type"] == "claude_desktop"
        assert claude["total_turns"] == 5
        assert claude["total_input_tokens"] == 100 + 200 + 300 + 400 + 500
        assert claude["total_output_tokens"] == 50 + 100 + 150 + 200 + 250

    def test_desktop_filter_multiple_agents(self, sc_server):
        base, db_path = sc_server
        _seed_desktop_session(db_path, "claude_desktop", "Claude Desktop App")
        _seed_desktop_session(db_path, "chatgpt_desktop", "ChatGPT Desktop App")
        data = _get_json(f"{base}/api/sessions?source=desktop")
        agent_types = {s["agent_type"] for s in data["sessions"] if s.get("source") == "desktop"}
        assert "claude_desktop" in agent_types
        assert "chatgpt_desktop" in agent_types

    def test_desktop_filter_empty_when_no_desktop_session(self, sc_server):
        base, _ = sc_server
        data = _get_json(f"{base}/api/sessions?source=desktop")
        assert [s for s in data["sessions"] if s.get("source") == "desktop"] == []

    def test_all_sources_includes_desktop(self, sc_server):
        base, db_path = sc_server
        _seed_desktop_session(db_path, "claude_desktop", "Claude Desktop App")
        data = _get_json(f"{base}/api/sessions?source=all")
        sources = {s.get("source") for s in data["sessions"]}
        assert "desktop" in sources


class TestProcessScannerDesktopSession:
    def test_ensure_desktop_session_creates_row(self, tmp_path, monkeypatch):
        """ProcessScanner._ensure_desktop_session writes to the sessions table."""
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        init_db(db_path).close()

        from claude_monitoring.monitor import ProcessScanner

        ps = ProcessScanner()
        ps._ensure_desktop_session("ChatGPT", "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", 12345)
        row = ps.db.execute(
            "SELECT session_id, agent_type, title FROM sessions WHERE session_id='desktop_chatgpt_desktop'"
        ).fetchone()
        assert row is not None
        assert row["agent_type"] == "chatgpt_desktop"
        assert row["title"] == "ChatGPT Desktop App"

    def test_ensure_desktop_session_is_idempotent(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        init_db(db_path).close()

        from claude_monitoring.monitor import ProcessScanner

        ps = ProcessScanner()
        # Two helper processes of the same app → one session row
        ps._ensure_desktop_session("Claude Helper", "/Applications/Claude.app/...", 100)
        ps._ensure_desktop_session("Claude Helper (Renderer)", "/Applications/Claude.app/...", 101)
        rows = ps.db.execute("SELECT COUNT(*) as n FROM sessions WHERE agent_type='claude_desktop'").fetchone()
        assert rows["n"] == 1

    def test_ensure_desktop_session_ignores_non_ai(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        init_db(db_path).close()

        from claude_monitoring.monitor import ProcessScanner

        ps = ProcessScanner()
        ps._ensure_desktop_session("Finder", "/System/Library/CoreServices/Finder.app", 500)
        rows = ps.db.execute("SELECT COUNT(*) as n FROM sessions").fetchone()
        assert rows["n"] == 0


# ─────────────────────────────────────────────────────────────
# Bug 2 — Browser session detail returns newest visits first
# ─────────────────────────────────────────────────────────────


class TestBrowserSessionReverseOrder:
    def test_visits_returned_newest_first(self, sc_server):
        base, db_path = sc_server
        conn = sqlite3.connect(str(db_path))
        for i in range(5):
            conn.execute(
                "INSERT INTO browser_sessions (service, url, title, conversation_id, visit_time, "
                "duration_seconds, source, event_type, content_text, content_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "Claude Web",
                    "https://claude.ai/chat/conv-1",
                    "Test",
                    "conv-1",
                    f"2026-04-14T00:0{i}:00Z",
                    5.0,
                    "extension",
                    "user_prompt" if i % 2 == 0 else "assistant_response",
                    f"message {i}",
                    f"hash{i}",
                ),
            )
        conn.commit()
        conn.close()

        data = _get_json(f"{base}/api/browser/session_detail?conversation_id=conv-1")
        visits = data["visits"]
        assert len(visits) == 5
        # Newest first
        assert visits[0]["content_text"] == "message 4"
        assert visits[-1]["content_text"] == "message 0"
        # first_visit / last_visit computed correctly (chronological)
        assert data["first_visit"] < data["last_visit"]
