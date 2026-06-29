"""P9.3 — Migration 0.2.2.003 round-trip + split-brain regression.

Locked by judge p9.3.a2 APPROVE Phase C hard gate #2 (M6):
  > simulated daemon restart after the migration MUST NOT re-create
  > `alert_dismissals`. This is the proof F2 is actually closed.

The migration must:
  1. CREATE `alert_triage` table with verdict TEXT column.
  2. INSERT-SELECT existing dismissals into alert_triage with verdict='dismissed'.
  3. DROP alert_dismissals.

AND the SAME PR must remove `db.py:245` legacy `CREATE TABLE IF NOT
EXISTS alert_dismissals` block — otherwise init_db() re-creates an
empty alert_dismissals on every daemon startup → split-brain.

Down-migration:
  1. CREATE alert_dismissals (4 cols same shape as legacy).
  2. INSERT-SELECT from alert_triage WHERE verdict='dismissed'.
  3. DROP alert_triage.
  4. TP/FP rows are LOST (acceptable — down restores pre-P9.3 state).
"""

from __future__ import annotations

import sqlite3

from claude_monitoring import db as db_module
from claude_monitoring.persistence.migrations import MIGRATIONS, apply_migrations


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    return c


def _table_exists(conn, name) -> bool:
    return conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _column_names(conn, table) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


class TestMigration002Registered:
    """Pin: migration 0.2.2.003 is registered in MIGRATIONS, monotonically
    after the existing 0.2.2.001 and 0.2.2.002."""

    def test_versions_are_monotonic_and_include_003(self):
        versions = [m.version for m in MIGRATIONS]
        assert "0.2.2.003" in versions, f"migration 0.2.2.003 must be registered; got {versions}"
        # Strictly monotonic (CI test_migrations_registry_versions_monotonic enforces).
        assert versions == sorted(versions), f"versions must be monotonic: {versions}"


class TestMigration003UpCreatesAlertTriageAndDropsDismissals:
    """Pin: up_sql creates alert_triage with the right columns + DROPs
    alert_dismissals + preserves rows with verdict='dismissed'."""

    def test_up_creates_table_and_drops_legacy(self):
        conn = _conn()
        # Simulate pre-P9.3 production state: v0.2.1-era init_db DID create
        # alert_dismissals, and rows accumulated there. We seed that state
        # manually because the P9.3 init_db no longer creates the table
        # (F2 split-brain closure).
        conn.execute(
            "CREATE TABLE alert_dismissals ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "event_id INTEGER NOT NULL UNIQUE, "
            "dismissed_at TEXT NOT NULL, "
            "reason TEXT)"
        )
        conn.executemany(
            "INSERT INTO alert_dismissals (event_id, dismissed_at, reason) VALUES (?, ?, ?)",
            [
                (42, "2026-06-22T00:00:00Z", "false_positive"),
                (43, "2026-06-22T01:00:00Z", "investigated"),
            ],
        )
        # Stamp schema_meta so apply_migrations knows we're at the pre-P9.3
        # baseline and only 0.2.2.003 should run (NOT the prior migrations
        # which depend on other tables not present here).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_meta ("
            "version TEXT PRIMARY KEY, applied_at REAL NOT NULL, description TEXT)"
        )
        conn.executemany(
            "INSERT INTO schema_meta (version, applied_at, description) VALUES (?, 0, '')",
            [("0.2.2.001",), ("0.2.2.002",)],
        )
        conn.commit()

        # Run all registered migrations — only 0.2.2.003 should execute.
        apply_migrations(conn)

        # alert_triage exists with expected columns.
        assert _table_exists(conn, "alert_triage")
        cols = _column_names(conn, "alert_triage")
        assert "event_id" in cols
        assert "verdict" in cols
        assert "reason" in cols
        assert "created_at" in cols  # D-csv created_at audit (a1 ratified)

        # alert_dismissals is DROPPED.
        assert not _table_exists(conn, "alert_dismissals"), (
            "legacy alert_dismissals must be DROPPED by migration 0.2.2.003"
        )

        # Legacy rows preserved with verdict='dismissed'.
        rows = conn.execute(
            "SELECT event_id, verdict, reason FROM alert_triage WHERE verdict='dismissed' ORDER BY event_id"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0]["event_id"] == 42
        assert rows[0]["verdict"] == "dismissed"
        assert rows[0]["reason"] == "false_positive"
        assert rows[1]["event_id"] == 43
        assert rows[1]["reason"] == "investigated"


class TestMigration003DownReverses:
    """Pin: down_sql reverses the up — recreates alert_dismissals from
    `verdict='dismissed'` rows; DROPs alert_triage; TP/FP rows are LOST
    (acceptable — restores pre-P9.3 state)."""

    def test_down_restores_alert_dismissals_drops_alert_triage(self, tmp_path):
        from claude_monitoring.persistence.migrations import MIGRATIONS

        # init_db takes a path, not a connection; the migration runs as part of
        # init_db itself.
        conn = db_module.init_db(tmp_path / "test.db")
        conn.row_factory = sqlite3.Row
        # Seed an alert_triage with one of each verdict.
        conn.executemany(
            "INSERT INTO alert_triage (event_id, verdict, reason, created_at) VALUES (?, ?, ?, ?)",
            [
                (100, "true_positive", None, "2026-06-24T00:00:00Z"),
                (101, "false_positive", None, "2026-06-24T01:00:00Z"),
                (102, "dismissed", "false_positive", "2026-06-24T02:00:00Z"),
            ],
        )
        conn.commit()

        # Apply down_sql for 0.2.2.003.
        m_003 = next(m for m in MIGRATIONS if m.version == "0.2.2.003")
        conn.executescript(m_003.down_sql)

        # alert_triage DROPPED.
        assert not _table_exists(conn, "alert_triage")
        # alert_dismissals RESTORED.
        assert _table_exists(conn, "alert_dismissals")
        rows = conn.execute("SELECT event_id, reason FROM alert_dismissals").fetchall()
        # ONLY the dismissed row survives.
        assert len(rows) == 1
        assert rows[0]["event_id"] == 102
        assert rows[0]["reason"] == "false_positive"


class TestMigration003ClosesSplitBrain:
    """Pin M6 (judge p9.3.a2 verdict hard carry-forward #2): a simulated
    daemon restart AFTER the migration runs MUST NOT re-CREATE
    alert_dismissals via init_db(). This is the proof F2 is actually
    closed — the migration DROP is futile without removing the legacy
    `db.py:245` CREATE."""

    def test_init_db_after_migration_does_not_recreate_alert_dismissals(self, tmp_path):
        db_path = tmp_path / "test.db"
        # Step 1: legacy daemon startup. init_db runs the migration framework
        # which creates alert_triage via 0.2.2.003. Migration runs ONCE because
        # schema_meta tracks applied versions.
        conn = db_module.init_db(db_path)
        assert not _table_exists(conn, "alert_dismissals"), (
            "precondition: post-init_db, alert_dismissals must NOT exist"
        )
        assert _table_exists(conn, "alert_triage"), "precondition: post-init_db, alert_triage must exist"
        conn.close()

        # Step 2: SIMULATED DAEMON RESTART — open the same DB path again.
        # F2 requires that the legacy CREATE TABLE IF NOT EXISTS
        # alert_dismissals block in db.py:245 has been REMOVED. If still
        # present, init_db() re-creates an empty alert_dismissals →
        # split-brain.
        conn2 = db_module.init_db(db_path)

        # Verdict: alert_dismissals must STILL not exist.
        assert not _table_exists(conn2, "alert_dismissals"), (
            "SPLIT-BRAIN: db.py:init_db() re-created alert_dismissals after "
            "the migration DROP. F2 fix incomplete — the legacy "
            "`CREATE TABLE IF NOT EXISTS alert_dismissals` block in db.py:245 "
            "must be REMOVED in the same PR. p9.3.a2 verdict hard "
            "carry-forward #2."
        )
        # And alert_triage must still be present (init_db must not have
        # removed it).
        assert _table_exists(conn2, "alert_triage"), "alert_triage must survive a subsequent init_db() call"
