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
