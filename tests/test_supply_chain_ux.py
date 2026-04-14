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
        assert set(per.keys()) == {"pip-audit", "osv", "threatfox", "urlhaus", "registry"}
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
