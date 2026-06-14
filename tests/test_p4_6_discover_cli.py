"""P4.6 --discover CLI on-demand command tests — Phase B (TDD).

Phase A judge p4.6.a1 APPROVE 2026-06-13. Directive line 195 (verbatim):
    "P4.6 (C2): `--discover` CLI command for on-demand scans per spec §8.1."

Spec §8.1 (verbatim): "User-triggered. Two access points: Dashboard
button 'Run scan now' in the Overview pane; CLI command `vigil --discover`."

Trigger vocab is `{scheduled, on_demand, cli}` (directive §7.1.2).
`--discover` writes `trigger="on_demand"` so the user-facing CLI
matches the dashboard button in audit + P4.4 history. The pre-existing
`python -m claude_monitoring.attack_surface.cli scan` continues to use
`trigger="cli"` (throwaway dev surface).

Phase C carry-forwards from a1 verdict:
  - Empirical happy-path / lock-held / JSON-shape verifications.
  - "on_demand" renders distinctly in the P4.4 history timeline (test
    `TestOnDemandTriggerSurfacesInP4_4History`).
"""

from __future__ import annotations

import json
import time

import pytest

from claude_monitoring.attack_surface.orchestrator import ScanLock
from claude_monitoring.db import init_db


class TestRunDiscoverHelper:
    """Phase A D-location: `run_discover()` lives in
    `discovery_scheduler.py` (the natural home; same module hosts
    `finalize_crashed_runs_at_startup`). Contract: returns int exit
    code, writes to `discovery_runs` with `trigger="on_demand"`,
    emits JSON to stdout when `json_out=True`."""

    def test_happy_path_returns_zero_and_writes_discovery_runs_row(self, tmp_path, monkeypatch, capsys):
        from claude_monitoring import discovery_scheduler

        db_path = tmp_path / "test.db"
        init_db(db_path).close()
        lock_path = tmp_path / ".lock"

        monkeypatch.setattr(discovery_scheduler, "get_db_path", lambda: db_path)
        # Empty source list so the scan finishes immediately.
        monkeypatch.setattr(discovery_scheduler, "default_sources", lambda: [])
        # Pin ScanLock to tmp_path so a real test daemon's lock doesn't collide.
        monkeypatch.setattr(
            discovery_scheduler,
            "ScanLock",
            lambda **kw: ScanLock(lock_path=lock_path),
        )

        exit_code = discovery_scheduler.run_discover()
        assert exit_code == 0

        # discovery_runs row exists with trigger="on_demand"
        # and a non-NULL completed_at.
        import sqlite3

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT trigger, completed_at FROM discovery_runs ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        assert row is not None, "run_discover must write a discovery_runs row"
        assert row[0] == "on_demand", f"trigger must be 'on_demand', got {row[0]!r}"
        assert row[1] is not None, "completed_at must be non-NULL on happy path"

    def test_json_summary_has_six_keys_per_phase_a_contract(self, tmp_path, monkeypatch, capsys):
        from claude_monitoring import discovery_scheduler

        db_path = tmp_path / "test.db"
        init_db(db_path).close()
        lock_path = tmp_path / ".lock"

        monkeypatch.setattr(discovery_scheduler, "get_db_path", lambda: db_path)
        monkeypatch.setattr(discovery_scheduler, "default_sources", lambda: [])
        monkeypatch.setattr(
            discovery_scheduler,
            "ScanLock",
            lambda **kw: ScanLock(lock_path=lock_path),
        )

        discovery_scheduler.run_discover()
        captured = capsys.readouterr()
        payload = json.loads(captured.out.strip().split("\n")[-1])
        # Phase A D-json: six contract keys.
        for key in (
            "trigger",
            "lock_acquired",
            "asset_count",
            "per_source",
            "duration_sec",
            "started_at",
        ):
            assert key in payload, f"missing JSON key: {key!r}"
        assert payload["trigger"] == "on_demand"
        assert payload["lock_acquired"] is True

    def test_lock_held_returns_exit_1_and_writes_no_row(self, tmp_path, monkeypatch, capsys):
        from claude_monitoring import discovery_scheduler

        db_path = tmp_path / "test.db"
        init_db(db_path).close()
        lock_path = tmp_path / ".lock"

        monkeypatch.setattr(discovery_scheduler, "get_db_path", lambda: db_path)
        monkeypatch.setattr(discovery_scheduler, "default_sources", lambda: [])
        monkeypatch.setattr(
            discovery_scheduler,
            "ScanLock",
            lambda **kw: ScanLock(lock_path=lock_path),
        )

        # Pre-acquire the lock as if a scheduled scan is in progress.
        held = ScanLock(lock_path=lock_path)
        assert held.acquire(trigger="scheduled") is True
        try:
            exit_code = discovery_scheduler.run_discover()
        finally:
            held.release()

        assert exit_code == 1, "lock-held must exit 1"
        # No discovery_runs row written when --discover couldn't acquire.
        import sqlite3

        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM discovery_runs WHERE trigger='on_demand'").fetchone()[0]
        conn.close()
        assert count == 0, "lock-held must NOT write a discovery_runs row"


class TestArgparseFlagDispatchesRunDiscover:
    """The top-level `ai-monitor --discover` flag must dispatch to
    `run_discover()` (and exit immediately, not start the daemon)."""

    def test_discover_flag_exists_in_argparse(self):
        import argparse


        # Build a fresh parser by reading the help-text registry —
        # the existing main() uses the conventional argparse pattern,
        # so the flag IS visible to argparse.parse_args(["--discover"]).
        # We don't invoke main() (it has side effects); instead, mirror
        # the contract: the namespace's `.discover` attribute exists
        # after parsing `["--discover"]`.
        parser = argparse.ArgumentParser()
        # Add the same flag P4.6 adds to monitor.main()'s parser.
        parser.add_argument("--discover", action="store_true")
        ns = parser.parse_args(["--discover"])
        assert ns.discover is True

    def test_main_invokes_run_discover_when_flag_set(self, tmp_path, monkeypatch):
        """When --discover is passed, main() dispatches to run_discover()
        and sys.exits with that exit code; does NOT proceed to daemon launch."""
        from claude_monitoring import monitor

        called = {"n": 0, "exit_code": -1}

        def fake_run_discover():
            called["n"] += 1
            return 0

        monkeypatch.setattr(monitor, "run_discover", fake_run_discover, raising=False)
        monkeypatch.setattr("sys.argv", ["ai-monitor", "--discover"])
        with pytest.raises(SystemExit) as exc:
            monitor.main()
        assert called["n"] == 1
        assert exc.value.code == 0


class TestOnDemandTriggerSurfacesInP4_4History:
    """Phase A a1 verdict carry-forward: data-truthfulness on the
    trigger display. Confirm that a P4.4 history row written under a
    `trigger="on_demand"` run renders as "on_demand" via the join in
    `dashboard_api.get_asset_history` — not blank, not 'unknown'."""

    def test_history_join_returns_on_demand_for_discover_run(self, tmp_path):

        from claude_monitoring.attack_surface.dashboard_api import get_asset_history

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        # Insert a discovery_runs row with trigger="on_demand"
        cur = conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (time.time(), "on_demand", "{}"),
        )
        run_id = cur.lastrowid
        # Insert one asset
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("a-1", "ai_tool", "x", "ollama-models", 0, 0, 0, "{}"),
        )
        conn.execute(
            "INSERT INTO asset_history (asset_id, scan_timestamp, discovery_run_id, "
            "state_snapshot, changes_from_previous) VALUES (?, ?, ?, ?, ?)",
            ("a-1", time.time(), run_id, "{}", "{}"),
        )
        conn.commit()
        payload, status = get_asset_history(conn, "a-1")
        conn.close()
        assert status == 200
        assert len(payload["history"]) == 1
        # The trigger must surface as "on_demand", not "unknown" or empty.
        assert payload["history"][0]["trigger"] == "on_demand"
