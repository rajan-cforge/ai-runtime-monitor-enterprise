"""P1.5 — `discovery_runs` audit logging tests.

Per the ratified Phase B test list at
`~/Documents/vigil-notes/v022/phase-1/p1.5/phase-b-test-list.md`.

18 tests across 7 classes. P1.5 fills the observable stubs that P1.3
shipped; after this PR merges, the stub DEBUG phrase ("P1.5 stub —
no DB write yet") MUST be absent from production paths and the
`discovery_runs` table MUST receive real INSERT / UPDATE traffic.

**Per Rajan's 2026-06-05 architect-pass steer** on `failure_kind`
naming: option chosen is field name `outcome` storing
`LastRunOutcome.value` always (never null when the source ran), so
a column named `failure_kind` never holds the literal string
`"success"`.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.orchestrator import (
    PerSourceTelemetry,
    audit,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _conn(tmp_path: Path) -> sqlite3.Connection:
    """Fresh in-memory sqlite with the P0.2 schema applied."""
    from claude_monitoring.persistence.migrations import apply_migrations

    db = tmp_path / "audit.db"
    conn = sqlite3.connect(str(db))
    apply_migrations(conn)
    return conn


def _row_dict(conn: sqlite3.Connection, run_id: int) -> dict:
    """Return the discovery_runs row as a dict."""
    row = conn.execute(
        "SELECT id, started_at, completed_at, trigger, assets_discovered, "
        "new_assets, removed_assets, new_cves, errors FROM discovery_runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    assert row is not None, f"no row with id={run_id}"
    return {
        "id": row[0],
        "started_at": row[1],
        "completed_at": row[2],
        "trigger": row[3],
        "assets_discovered": row[4],
        "new_assets": row[5],
        "removed_assets": row[6],
        "new_cves": row[7],
        "errors": row[8],
    }


# ---------------------------------------------------------------------------
# Group 1 — TestAuditSchemaBaseline (drift guard)
# ---------------------------------------------------------------------------


class TestAuditSchemaBaseline:
    def test_discovery_runs_table_present(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        rows = list(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='discovery_runs'"))
        assert len(rows) == 1

    def test_discovery_runs_columns_match_spec(self, tmp_path: Path) -> None:
        """9 columns per spec §9.1 — drift guard."""
        conn = _conn(tmp_path)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(discovery_runs)")]
        assert cols == [
            "id",
            "started_at",
            "completed_at",
            "trigger",
            "assets_discovered",
            "new_assets",
            "removed_assets",
            "new_cves",
            "errors",
        ]


# ---------------------------------------------------------------------------
# Group 2 — TestAuditWritePath (two-write lifecycle)
# ---------------------------------------------------------------------------


class TestAuditWritePath:
    def test_record_run_started_inserts_row_with_null_completed_at(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="on_demand", source_count=2)
        assert run_id > 0
        row = _row_dict(conn, run_id)
        assert row["trigger"] == "on_demand"
        assert row["completed_at"] is None
        assert row["started_at"] is not None

    def test_record_run_finished_updates_existing_row(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="cli", source_count=1)
        per_source = (
            PerSourceTelemetry(
                name="ollama-models",
                asset_count=4,
                elapsed_sec=0.05,
                last_run_outcome=LastRunOutcome.SUCCESS,
            ),
        )
        audit.record_run_finished(conn, run_id, assets_discovered=4, per_source=per_source)
        row = _row_dict(conn, run_id)
        assert row["completed_at"] is not None
        assert row["assets_discovered"] == 4

    def test_record_run_finished_preserves_started_at(self, tmp_path: Path) -> None:
        """UPDATE must NOT touch `started_at`."""
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="scheduled", source_count=0)
        captured_started = _row_dict(conn, run_id)["started_at"]
        time.sleep(0.05)
        audit.record_run_finished(conn, run_id, assets_discovered=0, per_source=())
        row = _row_dict(conn, run_id)
        assert row["started_at"] == captured_started

    def test_record_run_crashed_marks_status_crashed_in_errors(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="on_demand", source_count=1)
        audit.record_run_crashed(
            conn,
            run_id,
            exception_type="DatabaseError",
            exception_message="connection reset",
        )
        row = _row_dict(conn, run_id)
        assert row["completed_at"] is not None
        errors = json.loads(row["errors"])
        assert errors["status"] == "crashed"
        assert errors["exception_type"] == "DatabaseError"

    def test_invalid_trigger_raises_value_error(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        with pytest.raises(ValueError, match="trigger"):
            audit.record_run_started(conn, trigger="bogus", source_count=1)


# ---------------------------------------------------------------------------
# Group 3 — TestPerSourceBreakdownRoundTrip (single JSON column)
# ---------------------------------------------------------------------------


class TestPerSourceBreakdownRoundTrip:
    def test_per_source_breakdown_round_trip(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="cli", source_count=3)
        per_source = (
            PerSourceTelemetry("a", 2, 0.01, LastRunOutcome.SUCCESS),
            PerSourceTelemetry("b", 0, 0.02, LastRunOutcome.TIMEOUT),
            PerSourceTelemetry("c", 0, 0.03, LastRunOutcome.ERROR),
        )
        audit.record_run_finished(conn, run_id, assets_discovered=2, per_source=per_source)
        row = _row_dict(conn, run_id)
        errors = json.loads(row["errors"])
        assert errors["status"] == "completed"
        sources = errors["sources"]
        assert len(sources) == 3
        by_name = {s["name"]: s for s in sources}
        assert by_name["a"]["asset_count"] == 2
        assert by_name["b"]["asset_count"] == 0
        assert by_name["c"]["asset_count"] == 0

    def test_breakdown_uses_outcome_value_lowercase(self, tmp_path: Path) -> None:
        """Per Rajan 2026-06-05: field named `outcome` (NOT `failure_kind`),
        always storing `LastRunOutcome.value` lowercase."""
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="on_demand", source_count=4)
        per_source = (
            PerSourceTelemetry("s1", 1, 0.01, LastRunOutcome.SUCCESS),
            PerSourceTelemetry("s2", 0, 0.02, LastRunOutcome.TIMEOUT),
            PerSourceTelemetry("s3", 0, 0.03, LastRunOutcome.ERROR),
            PerSourceTelemetry("s4", 0, 0.04, LastRunOutcome.CAPPED),
        )
        audit.record_run_finished(conn, run_id, assets_discovered=1, per_source=per_source)
        errors = json.loads(_row_dict(conn, run_id)["errors"])
        outcomes = {s["name"]: s["outcome"] for s in errors["sources"]}
        assert outcomes == {
            "s1": "success",
            "s2": "timeout",
            "s3": "error",
            "s4": "capped",
        }
        # No source dict has a `failure_kind` key
        assert all("failure_kind" not in s for s in errors["sources"])

    def test_breakdown_with_no_sources_uses_empty_list(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        run_id = audit.record_run_started(conn, trigger="scheduled", source_count=0)
        audit.record_run_finished(conn, run_id, assets_discovered=0, per_source=())
        errors = json.loads(_row_dict(conn, run_id)["errors"])
        assert errors["status"] == "completed"
        assert errors["sources"] == []


# ---------------------------------------------------------------------------
# Group 4 — TestCrashedScanFinalizer
# ---------------------------------------------------------------------------


class TestCrashedScanFinalizer:
    def test_finalize_marks_old_incomplete_runs_as_crashed(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        # Insert a row with started_at 700s ago, completed_at NULL
        now = time.time()
        conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (now - 700, "on_demand", json.dumps({"status": "running", "sources": []})),
        )
        conn.commit()
        n = audit.finalize_crashed_runs(conn, older_than_sec=600)
        assert n == 1
        row = next(iter(conn.execute("SELECT completed_at, errors FROM discovery_runs LIMIT 1")))
        assert row[0] is not None
        errors = json.loads(row[1])
        assert errors["status"] == "crashed"

    def test_finalize_skips_recent_incomplete_runs(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        now = time.time()
        conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (now - 30, "on_demand", json.dumps({"status": "running", "sources": []})),
        )
        conn.commit()
        n = audit.finalize_crashed_runs(conn, older_than_sec=600)
        assert n == 0

    def test_finalize_is_idempotent(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        now = time.time()
        conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
            (now - 700, "on_demand", json.dumps({"status": "running", "sources": []})),
        )
        conn.commit()
        assert audit.finalize_crashed_runs(conn, older_than_sec=600) == 1
        assert audit.finalize_crashed_runs(conn, older_than_sec=600) == 0


# ---------------------------------------------------------------------------
# Group 5 — TestRetentionSweep (90-day)
# ---------------------------------------------------------------------------


class TestRetentionSweep:
    def test_sweep_deletes_rows_older_than_90_days(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        now = time.time()
        # 91 days ago — should sweep
        conn.execute("INSERT INTO discovery_runs (started_at, trigger) VALUES (?, ?)", (now - 91 * 86400, "scheduled"))
        # 89 days ago — should keep
        conn.execute("INSERT INTO discovery_runs (started_at, trigger) VALUES (?, ?)", (now - 89 * 86400, "scheduled"))
        conn.commit()
        deleted = audit.sweep_old_runs(conn, retention_sec=90 * 86400)
        assert deleted == 1
        remaining = list(conn.execute("SELECT started_at FROM discovery_runs"))
        assert len(remaining) == 1
        assert remaining[0][0] >= now - 90 * 86400

    def test_sweep_preserves_recent_rows(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        now = time.time()
        conn.execute("INSERT INTO discovery_runs (started_at, trigger) VALUES (?, ?)", (now - 1, "scheduled"))
        conn.commit()
        assert audit.sweep_old_runs(conn, retention_sec=90 * 86400) == 0


# ---------------------------------------------------------------------------
# Group 6 — TestAuditReadPath
# ---------------------------------------------------------------------------


class TestAuditReadPath:
    def test_read_recent_runs_orders_by_started_at_desc(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        # Insert in non-descending order
        for offset in (100, 10, 50):
            audit.record_run_started(conn, trigger="scheduled", source_count=0)
            # Backdate the just-inserted row
            conn.execute(
                "UPDATE discovery_runs SET started_at = ? WHERE id = (SELECT MAX(id) FROM discovery_runs)",
                (time.time() - offset,),
            )
            conn.commit()
        runs = audit.read_recent_runs(conn, limit=10)
        starts = [r["started_at"] for r in runs]
        assert starts == sorted(starts, reverse=True)

    def test_read_recent_runs_respects_limit(self, tmp_path: Path) -> None:
        conn = _conn(tmp_path)
        for _ in range(5):
            audit.record_run_started(conn, trigger="on_demand", source_count=0)
        runs = audit.read_recent_runs(conn, limit=3)
        assert len(runs) == 3


# ---------------------------------------------------------------------------
# Group 7 — Stub-phrase absence (Option β transition guard)
# ---------------------------------------------------------------------------


class TestStubPhraseAbsent:
    """After P1.5 fills the bodies, the P1.3 stub DEBUG phrase ("P1.5 stub —
    no DB write yet") MUST NOT appear when the audit functions run. Per
    Rajan's 2026-06-05 substring-match ratification."""

    def test_record_run_started_no_stub_phrase(self, tmp_path: Path, caplog) -> None:
        conn = _conn(tmp_path)
        with caplog.at_level("DEBUG", logger="ai-runtime-monitor.attack_surface.orchestrator.audit"):
            audit.record_run_started(conn, trigger="cli", source_count=1)
        assert not any("P1.5 stub" in r.message for r in caplog.records)

    def test_record_run_finished_no_stub_phrase(self, tmp_path: Path, caplog) -> None:
        conn = _conn(tmp_path)
        rid = audit.record_run_started(conn, trigger="cli", source_count=0)
        with caplog.at_level("DEBUG", logger="ai-runtime-monitor.attack_surface.orchestrator.audit"):
            audit.record_run_finished(conn, rid, assets_discovered=0, per_source=())
        assert not any("P1.5 stub" in r.message for r in caplog.records)

    def test_finalize_crashed_runs_no_stub_phrase(self, tmp_path: Path, caplog) -> None:
        conn = _conn(tmp_path)
        with caplog.at_level("DEBUG", logger="ai-runtime-monitor.attack_surface.orchestrator.audit"):
            audit.finalize_crashed_runs(conn)
        assert not any("P1.5 stub" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Group 8 — Doc-touch (DATA-CLASSIFICATION includes discovery_runs Internal)
# ---------------------------------------------------------------------------


class TestDataClassificationDoc:
    def test_data_classification_doc_has_discovery_runs_internal_entry(self) -> None:
        from pathlib import Path as P

        repo_root = P(__file__).resolve().parent.parent
        doc = (repo_root / "docs" / "spec" / "DATA-CLASSIFICATION.md").read_text()
        # `discovery_runs` must appear, with Internal tier nearby
        idx = doc.find("discovery_runs")
        assert idx != -1, "DATA-CLASSIFICATION.md missing discovery_runs entry"
        # Internal tier word within 200 chars of the mention
        window = doc[max(0, idx - 200) : idx + 200]
        assert "Internal" in window
