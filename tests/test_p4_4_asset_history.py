"""P4.4 — asset history (audit trail) tests.

Phase A ratified (judge p4.4.a3 APPROVE 2026-06-13). D1-D5 + D4-amendment:

  D1. State hashed for "did it change" =
      {current_state, ontology_tags, risk_score, risk_band, risk_factors, version}.
      EXCLUDES last_seen/last_scanned (would defeat "only on change").
  D2. `changes_from_previous` JSON = {field: {old, new}} per changed field.
      Special token `_kind: "first_seen"` for initial discovery row.
  D3. `state_snapshot` = full materialized dict (replayable).
  D4. Cross-table join keyed on `asset_history.discovery_run_id INTEGER FK`
      to `discovery_runs.id`. Float-equality joins on timestamp would miss
      because the orchestrator's `started_at` float and audit.py's own
      `time.time()` are distinct calls (judge a2 inversion-hunt).
  D4-amendment. Spec §9.1 gets a one-column amendment in this PR's migration
      v0.2.2.002; LEFT JOIN renders `trigger="unknown"` for orphan FK.
  D5. History section appended after risk breakdown in renderAssetDetail.

Q1 condition (judge): the new_in_24h panel MUST distinguish
"discovery never ran" (no_runs) from "0 new in 24h" (no_new).
Tested in TestNewIn24hPanel.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.db import init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_asset(name: str, source: str = "ollama-models", **overrides) -> Asset:
    base = {
        "id": f"id-{name}",
        "type": "ai_tool",
        "parent_asset_id": None,
        "name": name,
        "version": None,
        "install_path": None,
        "source": source,
        "current_state": {},
        "discovered_at": 0.0,
    }
    base.update(overrides)
    return Asset(**base)


def _make_orchestrator(tmp_path: Path, conn: sqlite3.Connection):
    from claude_monitoring.attack_surface.orchestrator import (
        DiscoveryOrchestrator,
        ScanLock,
    )

    lock = ScanLock(lock_path=tmp_path / ".lock")
    return DiscoveryOrchestrator(sources=[], lock=lock, persistence_connection=conn)


# ---------------------------------------------------------------------------
# Migration v0.2.2.002 — asset_history.discovery_run_id schema amendment
# ---------------------------------------------------------------------------


class TestHistorySchemaAmendment:
    """D4-amendment: `asset_history` gets `discovery_run_id INTEGER REFERENCES
    discovery_runs(id)` + an index. Validates the migration applies cleanly
    and the rollback returns to the pre-amendment shape."""

    def test_discovery_run_id_column_exists_after_migration(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(asset_history)").fetchall()}
        assert "discovery_run_id" in cols, "migration v0.2.2.002 must add asset_history.discovery_run_id"

    def test_idx_history_run_index_exists(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        indexes = {
            row[1]
            for row in conn.execute(
                "SELECT * FROM sqlite_master WHERE type='index' AND tbl_name='asset_history'"
            ).fetchall()
        }
        assert "idx_history_run" in indexes, (
            "migration v0.2.2.002 must create idx_history_run on asset_history.discovery_run_id"
        )


# ---------------------------------------------------------------------------
# Writer: state-change detection + diff computation
# ---------------------------------------------------------------------------


class TestAssetHistoryWriter:
    """D1/D2/D3: writer emits one row per asset on first scan
    (_kind=first_seen) and one row per state-changed asset per subsequent
    scan. Identical-state scans are no-ops."""

    def test_first_scan_writes_first_seen_row(self, tmp_path):
        conn = init_db(tmp_path / "test.db")
        o = _make_orchestrator(tmp_path, conn)
        asset = _make_asset("ollama-llama3", source="ollama-models")
        scan_time = time.time()
        o._persist_assets([asset], scan_time=scan_time, discovery_run_id=1)
        rows = conn.execute(
            "SELECT asset_id, scan_timestamp, discovery_run_id, state_snapshot, changes_from_previous "
            "FROM asset_history WHERE asset_id = ?",
            (asset.id,),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][2] == 1
        diff = json.loads(rows[0][4])
        assert diff == {"_kind": "first_seen"}
        snapshot = json.loads(rows[0][3])
        # D3: snapshot is the full materialized dict (replayable).
        assert "current_state" in snapshot
        assert "ontology_tags" in snapshot
        conn.close()

    def test_identical_second_scan_writes_zero_rows(self, tmp_path):
        conn = init_db(tmp_path / "test.db")
        o = _make_orchestrator(tmp_path, conn)
        asset = _make_asset("ollama-llama3", source="ollama-models")
        o._persist_assets([asset], scan_time=time.time(), discovery_run_id=1)
        # Second scan with the SAME asset state — no new history row.
        o._persist_assets([asset], scan_time=time.time() + 1, discovery_run_id=2)
        count = conn.execute("SELECT COUNT(*) FROM asset_history WHERE asset_id = ?", (asset.id,)).fetchone()[0]
        assert count == 1, "identical-state second scan must be a writer no-op"
        conn.close()

    def test_state_change_writes_single_row_with_multi_field_diff(self, tmp_path):
        conn = init_db(tmp_path / "test.db")
        o = _make_orchestrator(tmp_path, conn)
        a1 = _make_asset(
            "ollama-llama3",
            source="ollama-models",
            version="0.5.0",
            current_state={"size_mb": 8000},
        )
        o._persist_assets([a1], scan_time=time.time(), discovery_run_id=1)
        # Scan 2: version bumped + current_state mutated → one row with both.
        a2 = _make_asset(
            "ollama-llama3",
            source="ollama-models",
            version="0.6.0",
            current_state={"size_mb": 9000},
        )
        o._persist_assets([a2], scan_time=time.time() + 1, discovery_run_id=2)
        rows = conn.execute(
            "SELECT changes_from_previous FROM asset_history WHERE asset_id = ? ORDER BY scan_timestamp DESC",
            (a1.id,),
        ).fetchall()
        assert len(rows) == 2
        latest_diff = json.loads(rows[0][0])
        # D2: per-field {old, new} for every changed field; one row, not
        # one row per field.
        assert "version" in latest_diff
        assert latest_diff["version"] == {"old": "0.5.0", "new": "0.6.0"}
        assert "current_state" in latest_diff
        conn.close()

    def test_excludes_last_seen_and_last_scanned_from_diff(self, tmp_path):
        """D1: timestamps change every scan and must NOT trigger a history
        row. Otherwise every scan writes one row per asset forever."""
        conn = init_db(tmp_path / "test.db")
        o = _make_orchestrator(tmp_path, conn)
        asset = _make_asset("ollama-llama3", source="ollama-models")
        # Three scans, each with a different scan_time. Asset state unchanged.
        for i, t in enumerate([time.time(), time.time() + 60, time.time() + 120]):
            o._persist_assets([asset], scan_time=t, discovery_run_id=i + 1)
        count = conn.execute("SELECT COUNT(*) FROM asset_history WHERE asset_id = ?", (asset.id,)).fetchone()[0]
        assert count == 1, "scan-time-only differences must not trigger history rows"
        conn.close()

    def test_per_item_isolation_one_asset_writer_failure_does_not_abort_others(self, tmp_path, monkeypatch):
        """Per-item isolation contract (project_v022_per_item_isolation):
        a single asset's history-write failure must not stop the rest of
        the scan from persisting their history rows."""
        conn = init_db(tmp_path / "test.db")
        o = _make_orchestrator(tmp_path, conn)
        good = _make_asset("good-asset", source="ollama-models")
        bad = _make_asset("bad-asset", source="ollama-models")

        # Inject a per-asset failure for `bad` only.
        original = o._record_history

        def _wrapped(conn_, asset_arg, *args, **kwargs):
            if asset_arg.id == bad.id:
                raise RuntimeError("simulated history-write failure")
            return original(conn_, asset_arg, *args, **kwargs)

        monkeypatch.setattr(o, "_record_history", _wrapped)
        o._persist_assets([good, bad], scan_time=time.time(), discovery_run_id=1)
        # `good` got its history row; `bad` did not; no exception escaped.
        good_count = conn.execute("SELECT COUNT(*) FROM asset_history WHERE asset_id = ?", (good.id,)).fetchone()[0]
        bad_count = conn.execute("SELECT COUNT(*) FROM asset_history WHERE asset_id = ?", (bad.id,)).fetchone()[0]
        assert good_count == 1, "good asset's history row must persist"
        assert bad_count == 0, "bad asset failed; no history row"
        conn.close()


# ---------------------------------------------------------------------------
# Endpoint: GET /api/asset/<id>/history
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_server(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path = tmp_path / "test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    init_db(db_path).close()
    with (
        patch("claude_monitoring.monitor.DB_PATH", db_path),
        patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
        patch("claude_monitoring.config.get_db_path", return_value=db_path),
        patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
        patch("claude_monitoring.db.get_db_path", return_value=db_path),
        patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
    ):
        from claude_monitoring.monitor import DashboardHandler

        server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{port}", db_path
        server.shutdown()


class TestAssetHistoryEndpoint:
    def test_endpoint_returns_empty_history_for_never_scanned_asset(self, api_server):
        base, db_path = api_server
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("asset-never-scanned", "ai_tool", "x", "ollama-models", 0, 0, 0, "{}"),
        )
        conn.commit()
        conn.close()
        resp = urlopen(f"{base}/api/asset/asset-never-scanned/history")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["history"] == []

    def test_endpoint_returns_404_for_unknown_asset(self, api_server):
        base, _ = api_server
        with pytest.raises(HTTPError) as exc:
            urlopen(f"{base}/api/asset/no-such-asset/history")
        assert exc.value.code == 404

    def test_endpoint_orders_newest_first(self, api_server):
        base, db_path = api_server
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("asset-1", "ai_tool", "x", "ollama-models", 0, 0, 0, "{}"),
        )
        # Three rows, oldest to newest insert order; endpoint must reverse.
        for ts, kind in [(100.0, "old"), (200.0, "mid"), (300.0, "new")]:
            conn.execute(
                "INSERT INTO asset_history (asset_id, scan_timestamp, state_snapshot, changes_from_previous) "
                "VALUES (?, ?, ?, ?)",
                ("asset-1", ts, "{}", json.dumps({"kind": kind})),
            )
        conn.commit()
        conn.close()
        resp = urlopen(f"{base}/api/asset/asset-1/history")
        data = json.loads(resp.read())
        kinds = [json.loads(row["changes_from_previous"])["kind"] for row in data["history"]]
        assert kinds == ["new", "mid", "old"], "history must be ordered newest first"


# ---------------------------------------------------------------------------
# Cross-table trigger-attribution join (D4)
# ---------------------------------------------------------------------------


class TestHistoryRunIdJoin:
    """D4: asset_history.discovery_run_id INTEGER FK joins to
    discovery_runs.id; the endpoint surfaces the trigger of the run that
    produced each history row."""

    @pytest.mark.parametrize("trigger", ["scheduled", "on_demand", "cli"])
    def test_endpoint_surfaces_trigger_for_each_valid_trigger(self, api_server, trigger):
        base, db_path = api_server
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (f"asset-{trigger}", "ai_tool", "x", "ollama-models", 0, 0, 0, "{}"),
        )
        cur = conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (time.time(), trigger, "{}"),
        )
        run_id = cur.lastrowid
        conn.execute(
            "INSERT INTO asset_history (asset_id, scan_timestamp, discovery_run_id, "
            "state_snapshot, changes_from_previous) VALUES (?, ?, ?, ?, ?)",
            (f"asset-{trigger}", time.time(), run_id, "{}", "{}"),
        )
        conn.commit()
        conn.close()
        resp = urlopen(f"{base}/api/asset/asset-{trigger}/history")
        data = json.loads(resp.read())
        assert len(data["history"]) == 1
        assert data["history"][0]["trigger"] == trigger


class TestHistoryOrphanedRunIdRenders:
    """D4 LEFT JOIN: a history row referencing a discovery_run that was
    deleted (or never existed because the FK isn't enforced — PRAGMA
    foreign_keys is OFF per P0.2 deviation #3) must still render with
    `trigger="unknown"` and NOT crash the endpoint."""

    def test_orphan_run_id_renders_trigger_unknown(self, api_server):
        base, db_path = api_server
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("asset-orphan", "ai_tool", "x", "ollama-models", 0, 0, 0, "{}"),
        )
        # discovery_run_id references a row that doesn't exist.
        conn.execute(
            "INSERT INTO asset_history (asset_id, scan_timestamp, discovery_run_id, "
            "state_snapshot, changes_from_previous) VALUES (?, ?, ?, ?, ?)",
            ("asset-orphan", time.time(), 999999, "{}", "{}"),
        )
        conn.commit()
        conn.close()
        resp = urlopen(f"{base}/api/asset/asset-orphan/history")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert len(data["history"]) == 1
        assert data["history"][0]["trigger"] == "unknown"


# ---------------------------------------------------------------------------
# new_in_24h panel — Q1 data-truthfulness condition
# ---------------------------------------------------------------------------


class TestNewIn24hPanel:
    """Q1 (judge ratified with data-truthfulness condition): the panel
    MUST distinguish 'discovery never ran' (no_runs) from '0 new in last
    24h' (no_new). Bare `0` that conflates the two is a CHANGES finding."""

    def test_no_runs_state_when_discovery_runs_empty(self, api_server):
        base, _ = api_server
        resp = urlopen(f"{base}/api/assets/new-in-24h")
        data = json.loads(resp.read())
        assert data["count"] == 0
        assert data["status"] == "no_runs"

    def test_no_new_state_when_runs_exist_but_no_recent_first_seen(self, api_server):
        base, db_path = api_server
        conn = sqlite3.connect(db_path)
        # One discovery_runs row exists, but the asset's first_seen is
        # > 24h ago, so the count is zero — DIFFERENT semantics than no_runs.
        old = time.time() - 48 * 3600
        conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (old, "scheduled", "{}"),
        )
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("old-asset", "ai_tool", "x", "ollama-models", old, old, old, "{}"),
        )
        conn.commit()
        conn.close()
        resp = urlopen(f"{base}/api/assets/new-in-24h")
        data = json.loads(resp.read())
        assert data["count"] == 0
        assert data["status"] == "no_new"

    def test_ok_state_counts_first_seen_within_last_24h(self, api_server):
        base, db_path = api_server
        conn = sqlite3.connect(db_path)
        now = time.time()
        conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (now - 60, "scheduled", "{}"),
        )
        # Two assets discovered within 24h, one outside.
        for aid, first_seen in [
            ("new-1", now - 3600),
            ("new-2", now - 7200),
            ("old-1", now - 48 * 3600),
        ]:
            conn.execute(
                "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (aid, "ai_tool", aid, "ollama-models", first_seen, first_seen, first_seen, "{}"),
            )
        conn.commit()
        conn.close()
        resp = urlopen(f"{base}/api/assets/new-in-24h")
        data = json.loads(resp.read())
        assert data["count"] == 2
        assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# Auth gate — Phase A flagged Phase C must-pass
# ---------------------------------------------------------------------------


class TestHistoryEndpointAuthGate:
    """Repo CLAUDE.md hard gate: no DashboardHandler route without
    verify_token. The new /api/asset/<id>/history endpoint must inherit
    `_check_auth`."""

    def test_unauthenticated_request_returns_401(self, tmp_path, monkeypatch):
        # NOTE: explicitly NOT setting DISABLE_DASHBOARD_AUTH — auth on.
        monkeypatch.delenv("DISABLE_DASHBOARD_AUTH", raising=False)
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir(exist_ok=True)
        init_db(db_path).close()
        with (
            patch("claude_monitoring.monitor.DB_PATH", db_path),
            patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
            patch("claude_monitoring.config.get_db_path", return_value=db_path),
            patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
            patch("claude_monitoring.db.get_db_path", return_value=db_path),
            patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
        ):
            from claude_monitoring.monitor import DashboardHandler

            server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
            port = server.server_address[1]
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                with pytest.raises(HTTPError) as exc:
                    urlopen(f"http://127.0.0.1:{port}/api/asset/anything/history")
                assert exc.value.code == 401
            finally:
                server.shutdown()
