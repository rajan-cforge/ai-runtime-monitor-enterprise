"""TDD test suite for v0.2.2 P0.2 — attack-surface tables migration.

Exercises the first real Migration registered in the v0.2.2 framework: six
tables + ten indexes per spec §9.1, with six ratified deviations documented
in ``~/Documents/vigil-notes/architect-pass-P0.2.md``:

1. ``references`` (SQL reserved keyword in spec §9.1) → renamed to
   ``cve_references`` in both ``asset_cves`` and ``cve_cache``. Pinned by
   ``test_*_uses_cve_references_not_references``.
2. ``TIMESTAMP`` column type preserved per spec; populated via
   ``time.time()`` (Unix epoch float) for consistency with ``schema_meta``.
3. FK enforcement via ``PRAGMA foreign_keys = ON`` deferred to a dedicated
   PR; FK clauses are documentation-only in P0.2 (matches existing convention).
4. ``Migration.down_sql`` field added to the P0.0 contract as an optional
   ``str = ""``. Tests for the extension live in ``test_migrations.py``.
5. ``current_state TEXT NOT NULL`` (tightened from spec's nullable) to match
   the ``Asset`` dataclass contract in directive §7.1.
6. Single ``Migration`` record (one ``up_sql`` covering all six tables + ten
   indexes); per-migration transactionality per P0.0 contract point 11.

Total: 14 tests. All fail initially (MIGRATIONS is empty until Phase C lands
the registration); all turn green after Phase C.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from claude_monitoring.persistence import migrations as mig

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PRE_V022_SCHEMA_FIXTURE = FIXTURES_DIR / "pre_v022_schema.sql"
PRE_V022_SCHEMA_WITH_DATA_FIXTURE = FIXTURES_DIR / "pre_v022_schema_with_data.sql"

MIGRATION_VERSION = "0.2.2.001"

EXPECTED_TABLES = {
    "assets",
    "asset_cves",
    "asset_history",
    "cve_cache",
    "discovery_runs",
    "permission_grants",
}

EXPECTED_INDEXES = {
    "idx_assets_type",
    "idx_assets_parent",
    "idx_assets_risk_band",
    "idx_assets_last_seen",
    "idx_cves_severity",
    "idx_cves_discovered",
    "idx_history_asset",
    "idx_cve_cache_ecosystem",
    "idx_cve_cache_fetched",
    "idx_runs_started",
    # P4.4 (v0.2.2.002 amendment): asset_history.discovery_run_id FK index.
    "idx_history_run",
}


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _load_sql_fixture(conn: sqlite3.Connection, fixture: Path) -> None:
    conn.executescript(fixture.read_text())
    conn.commit()


@pytest.fixture
def empty_db(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "monitor.db")
    yield conn
    conn.close()


@pytest.fixture
def pre_v022_db(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "monitor.db")
    _load_sql_fixture(conn, PRE_V022_SCHEMA_FIXTURE)
    yield conn
    conn.close()


@pytest.fixture
def pre_v022_db_with_data(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "monitor.db")
    _load_sql_fixture(conn, PRE_V022_SCHEMA_WITH_DATA_FIXTURE)
    yield conn
    conn.close()


def _table_columns(conn: sqlite3.Connection, table: str) -> dict[str, tuple[str, int, str | None]]:
    """Return {column_name: (type, notnull, default)} for a table."""
    rows = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
    return {r[1]: (r[2], r[3], r[4]) for r in rows}


# ---------------------------------------------------------------------------
# Group 1 — registry contract
# ---------------------------------------------------------------------------


class TestP02MigrationRegistered:
    def test_registry_contains_the_p0_2_migration(self) -> None:
        """MIGRATIONS includes the 0.2.2.001 migration after P0.2 lands."""
        versions = [m.version for m in mig.MIGRATIONS]
        assert MIGRATION_VERSION in versions, f"expected MIGRATIONS to contain {MIGRATION_VERSION!r}; have: {versions}"

    def test_migration_has_non_empty_down_sql(self) -> None:
        """The P0.2 migration MUST ship a non-empty down_sql so the
        migration-rollback-test CI gate has something to exercise."""
        m = next(m for m in mig.MIGRATIONS if m.version == MIGRATION_VERSION)
        assert m.down_sql and m.down_sql.strip(), "P0.2 migration must declare down_sql for the rollback gate"


# ---------------------------------------------------------------------------
# Group 2 — schema correctness after apply
# ---------------------------------------------------------------------------


class TestP02SchemaCreation:
    def test_creates_all_six_tables(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        tables = {r[0] for r in empty_db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        missing = EXPECTED_TABLES - tables
        assert not missing, f"migration didn't create tables: {missing}"

    def test_creates_all_ten_indexes(self, empty_db: sqlite3.Connection) -> None:
        """Strict equality on the index set scoped to P0.2's attack-surface
        tables — defends against unintended extras or duplicates as well as
        missing indexes. Scoping by ``tbl_name`` keeps the test stable when
        future migrations contribute indexes on other tables."""
        mig.apply_migrations(empty_db)
        indexes = {
            r[0]
            for r in empty_db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND sql IS NOT NULL "
                "AND tbl_name IN ('assets','asset_cves','asset_history',"
                "'cve_cache','discovery_runs','permission_grants')"
            ).fetchall()
        }
        assert indexes == EXPECTED_INDEXES, (
            f"P0.2 index set mismatch: missing={EXPECTED_INDEXES - indexes}, unexpected={indexes - EXPECTED_INDEXES}"
        )

    def test_assets_columns_match_spec(self, empty_db: sqlite3.Connection) -> None:
        """Spec §9.1 column list for `assets`, with current_state tightened
        to NOT NULL per architect-pass §3 deviation 5."""
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "assets")
        expected_columns = {
            "id",
            "type",
            "parent_asset_id",
            "name",
            "version",
            "install_path",
            "source",
            "first_seen",
            "last_seen",
            "last_scanned",
            "current_state",
            "ontology_tags",
            "risk_score",
            "risk_band",
            "risk_factors",
            "is_vigil_component",
        }
        assert set(cols.keys()) == expected_columns, f"assets columns mismatch: got {set(cols.keys())}"
        # Per-column type and nullability spot-checks
        assert cols["id"][0] == "TEXT", "assets.id should be TEXT"
        assert cols["type"][1] == 1, "assets.type should be NOT NULL"
        assert cols["name"][1] == 1, "assets.name should be NOT NULL"
        assert cols["first_seen"][1] == 1, "assets.first_seen should be NOT NULL"
        assert cols["current_state"][1] == 1, "assets.current_state should be NOT NULL (architect-pass §3 deviation 5)"
        assert cols["is_vigil_component"][2] == "0", "assets.is_vigil_component DEFAULT 0"

    def test_asset_cves_uses_cve_references_not_references(self, empty_db: sqlite3.Connection) -> None:
        """Spec §9.1 ships ``references`` (SQL reserved keyword) — empirically
        proven not to parse. Architect-pass §3 deviation 1 ratifies the rename
        to ``cve_references``. This test pins the deviation."""
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "asset_cves")
        assert "cve_references" in cols, "asset_cves must have `cve_references` column (architect-pass deviation 1)"
        assert "references" not in cols, (
            "asset_cves must NOT use `references` column "
            "(SQLite reserved keyword — empirical test confirmed parse fails)"
        )

    def test_asset_cves_columns_match_spec(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "asset_cves")
        expected_columns = {
            "asset_id",
            "cve_id",
            "severity",
            "published",
            "description",
            "cve_references",  # spec §9.1 deviation: renamed from `references`
            "discovered_at",
        }
        assert set(cols.keys()) == expected_columns, f"asset_cves columns mismatch: got {set(cols.keys())}"
        assert cols["asset_id"][1] == 1
        assert cols["cve_id"][1] == 1
        assert cols["discovered_at"][1] == 1

    def test_asset_history_columns_match_spec(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "asset_history")
        expected_columns = {
            "asset_id",
            "scan_timestamp",
            "state_snapshot",
            "changes_from_previous",
            # P4.4 (v0.2.2.002 amendment): exact integer FK to discovery_runs(id)
            # — replaces the fragile timestamp-equality join. PRAGMA
            # foreign_keys is OFF per P0.2 deviation #3, so the REFERENCES
            # clause is documentary; orphan FKs render trigger="unknown".
            "discovery_run_id",
        }
        assert set(cols.keys()) == expected_columns
        assert cols["asset_id"][1] == 1
        assert cols["scan_timestamp"][1] == 1
        assert cols["state_snapshot"][1] == 1

    def test_cve_cache_uses_cve_references_not_references(self, empty_db: sqlite3.Connection) -> None:
        """Same spec deviation as asset_cves — `references` → `cve_references`."""
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "cve_cache")
        assert "cve_references" in cols
        assert "references" not in cols

    def test_cve_cache_columns_match_spec(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "cve_cache")
        expected_columns = {
            "package_ecosystem",
            "package_name",
            "cve_id",
            "severity",
            "affected_versions",
            "published",
            "description",
            "cve_references",
            "fetched_at",
        }
        assert set(cols.keys()) == expected_columns
        assert cols["package_ecosystem"][1] == 1
        assert cols["package_name"][1] == 1
        assert cols["cve_id"][1] == 1
        assert cols["fetched_at"][1] == 1

    def test_discovery_runs_columns_match_spec(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "discovery_runs")
        expected_columns = {
            "id",
            "started_at",
            "completed_at",
            "trigger",
            "assets_discovered",
            "new_assets",
            "removed_assets",
            "new_cves",
            "errors",
        }
        assert set(cols.keys()) == expected_columns
        assert cols["id"][0] == "INTEGER"
        assert cols["started_at"][1] == 1

    def test_permission_grants_columns_match_spec(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        cols = _table_columns(empty_db, "permission_grants")
        expected_columns = {"integration", "granted_at", "granted_scope"}
        assert set(cols.keys()) == expected_columns
        assert cols["integration"][1] == 1
        assert cols["granted_at"][1] == 1


# ---------------------------------------------------------------------------
# Group 3 — idempotency + audit
# ---------------------------------------------------------------------------


class TestP02IdempotencyAndAudit:
    def test_migration_records_schema_meta_row(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        rows = empty_db.execute(
            "SELECT version, description FROM schema_meta WHERE version = ?",
            (MIGRATION_VERSION,),
        ).fetchall()
        assert len(rows) == 1
        version, description = rows[0]
        assert version == MIGRATION_VERSION
        # Spot-check the description mentions the load-bearing table list
        assert "attack-surface" in description.lower() or "attack surface" in description.lower()

    def test_migration_idempotent_on_re_run(self, empty_db: sqlite3.Connection) -> None:
        mig.apply_migrations(empty_db)
        mig.apply_migrations(empty_db)
        rows = empty_db.execute(
            "SELECT COUNT(*) FROM schema_meta WHERE version = ?",
            (MIGRATION_VERSION,),
        ).fetchone()
        assert rows[0] == 1, "duplicate migration row from re-run"
        # And the tables are still there exactly once.
        cnt = empty_db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='assets'").fetchone()[0]
        assert cnt == 1


# ---------------------------------------------------------------------------
# Group 4 — pre-existing data preservation
# ---------------------------------------------------------------------------


class TestP02DataPreservation:
    def test_preserves_existing_legacy_data(self, pre_v022_db_with_data: sqlite3.Connection) -> None:
        """Pre-v0.2.2 install with rows → P0.2 migration leaves legacy data
        untouched while adding the six new tables."""
        before = {
            "sessions": pre_v022_db_with_data.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "api_calls": pre_v022_db_with_data.execute("SELECT COUNT(*) FROM api_calls").fetchone()[0],
            "extension_heartbeats": pre_v022_db_with_data.execute(
                "SELECT COUNT(*) FROM extension_heartbeats"
            ).fetchone()[0],
        }
        assert before == {"sessions": 1, "api_calls": 3, "extension_heartbeats": 2}

        mig.apply_migrations(pre_v022_db_with_data)

        after = {
            "sessions": pre_v022_db_with_data.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "api_calls": pre_v022_db_with_data.execute("SELECT COUNT(*) FROM api_calls").fetchone()[0],
            "extension_heartbeats": pre_v022_db_with_data.execute(
                "SELECT COUNT(*) FROM extension_heartbeats"
            ).fetchone()[0],
        }
        assert after == before, f"legacy row counts shifted: {before} → {after}"

        # And the six new tables exist now.
        tables = {
            r[0] for r in pre_v022_db_with_data.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert EXPECTED_TABLES.issubset(tables)


# ---------------------------------------------------------------------------
# Group 5 — round-trip (apply + rollback)
# ---------------------------------------------------------------------------


class TestP02RoundTripRollback:
    def test_round_trip_apply_then_rollback(self, empty_db: sqlite3.Connection) -> None:
        """Apply migration → 6 tables present + schema_meta row + indexes.
        Rollback → all 6 tables gone, all 10 indexes gone, schema_meta row gone.

        Exercises the migration-rollback-test CI gate (directive §11.2).
        """
        m = next(m for m in mig.MIGRATIONS if m.version == MIGRATION_VERSION)
        mig.apply_migration(empty_db, m)

        tables = {r[0] for r in empty_db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert EXPECTED_TABLES.issubset(tables)
        assert (
            empty_db.execute(
                "SELECT COUNT(*) FROM schema_meta WHERE version=?",
                (MIGRATION_VERSION,),
            ).fetchone()[0]
            == 1
        )

        mig.rollback_migration(empty_db, m)

        tables_after = {r[0] for r in empty_db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        leftover = EXPECTED_TABLES & tables_after
        assert not leftover, f"rollback left tables behind: {leftover}"

        # schema_meta row removed too
        assert (
            empty_db.execute(
                "SELECT COUNT(*) FROM schema_meta WHERE version=?",
                (MIGRATION_VERSION,),
            ).fetchone()[0]
            == 0
        )
