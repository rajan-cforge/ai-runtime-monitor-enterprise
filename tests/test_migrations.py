"""TDD test suite for v0.2.2 P0.0 — schema_meta + apply_migrations framework.

These tests are written BEFORE implementation per the v0.2.2 sprint discipline.
They MUST all fail initially (the persistence.migrations module does not exist).
Phase C implementation lands the framework that turns each test green.

Test groups:

1. schema_meta creation + idempotency (4 tests)
2. Migration dataclass construction-time validation (4 tests)
3. MIGRATIONS registry contract (1 test — monotonic ordering)
4. Atomic transaction behavior (2 tests)
5. Daemon-coordination — 4-state PID-file coverage + canonical-default (5 tests)

Total: 16 tests. After Phase C, all 16 turn green.

Per-test fixture pattern: each test gets a fresh tempfile DB so tests are
hermetic and parallelizable. Tests that need representative legacy data
load `tests/fixtures/pre_v022_schema_with_data.sql`; tests that need a
clean schema load `tests/fixtures/pre_v022_schema.sql`.

Dead-PID acquisition: tests use `_get_definitely_dead_pid()` which spawns
a short-lived subprocess and returns its PID after the OS has reaped it.
More robust than asserting "PID 2 is dead" — works regardless of OS,
container, or future kernel behavior.
"""

from __future__ import annotations

import dataclasses
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

# Import the module under test. Phase B: this import fails (module does not
# exist yet). Phase C: implementation lands; this import succeeds.
from claude_monitoring.persistence import migrations as mig

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PRE_V022_SCHEMA_FIXTURE = FIXTURES_DIR / "pre_v022_schema.sql"
PRE_V022_SCHEMA_WITH_DATA_FIXTURE = FIXTURES_DIR / "pre_v022_schema_with_data.sql"


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _load_sql_fixture(conn: sqlite3.Connection, fixture: Path) -> None:
    """Execute every statement in a .sql fixture against the given connection."""
    conn.executescript(fixture.read_text())
    conn.commit()


def _get_definitely_dead_pid() -> int:
    """Return a PID guaranteed to no longer correspond to a live process.

    Strategy: spawn ``true`` via ``Popen``, ``wait()`` for it to exit, then
    return ``proc.pid``. Once ``wait`` has returned, the OS has reaped the
    zombie and the PID is dead. ``subprocess.run`` would not work here
    because ``CompletedProcess`` doesn't expose the child's PID.

    Robust across macOS, Linux, containers, and future kernel behavior —
    unlike asserting "PID 2 is always kthreadd/dead."
    """
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc.wait()
    return proc.pid


@pytest.fixture
def empty_db(tmp_path) -> sqlite3.Connection:
    """A brand-new SQLite db with zero tables — simulates a fresh first-run install."""
    db_path = tmp_path / "monitor.db"
    conn = sqlite3.connect(db_path)
    yield conn
    conn.close()


@pytest.fixture
def pre_v022_db(tmp_path) -> sqlite3.Connection:
    """Pre-v0.2.2 schema, no rows. Simulates an install that ran v0.2.1 code paths."""
    db_path = tmp_path / "monitor.db"
    conn = sqlite3.connect(db_path)
    _load_sql_fixture(conn, PRE_V022_SCHEMA_FIXTURE)
    yield conn
    conn.close()


@pytest.fixture
def pre_v022_db_with_data(tmp_path) -> sqlite3.Connection:
    """Pre-v0.2.2 schema + representative rows in sessions / api_calls / extension_heartbeats."""
    db_path = tmp_path / "monitor.db"
    conn = sqlite3.connect(db_path)
    _load_sql_fixture(conn, PRE_V022_SCHEMA_WITH_DATA_FIXTURE)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Group 1 — schema_meta creation + idempotency
# ---------------------------------------------------------------------------


class TestSchemaMetaCreation:
    def test_schema_meta_created_on_fresh_db(self, empty_db: sqlite3.Connection) -> None:
        """Empty DB → schema_meta table exists with the correct columns after apply_migrations()."""
        mig.apply_migrations(empty_db)

        cols = empty_db.execute("PRAGMA table_info('schema_meta')").fetchall()
        col_names = {c[1] for c in cols}
        assert col_names == {"version", "applied_at", "description"}, f"schema_meta columns mismatch: {col_names}"

    def test_pre_v022_db_gets_baseline_row(self, pre_v022_db: sqlite3.Connection) -> None:
        """Pre-v0.2.2 schema with legacy tables but no schema_meta → backfill inserts baseline row."""
        mig.apply_migrations(pre_v022_db)

        rows = pre_v022_db.execute(
            "SELECT version, description FROM schema_meta WHERE version LIKE '%-baseline'"
        ).fetchall()
        assert len(rows) == 1, f"expected exactly one baseline row, got {len(rows)}: {rows}"
        version, description = rows[0]
        assert version == "0.2.0-baseline", f"unexpected baseline version: {version!r}"
        assert "P0.0" in description, (
            f"baseline description should reference P0.0 for traceability; got: {description!r}"
        )
        assert "schema-meta framework" in description, (
            f"baseline description should say 'schema-meta framework' (not just 'table'); got: {description!r}"
        )

    def test_apply_migrations_idempotent(self, empty_db: sqlite3.Connection) -> None:
        """Running apply_migrations twice does not error and does not duplicate any row."""
        mig.apply_migrations(empty_db)
        mig.apply_migrations(empty_db)

        # No version should appear more than once in schema_meta.
        rows = empty_db.execute(
            "SELECT version, COUNT(*) FROM schema_meta GROUP BY version HAVING COUNT(*) > 1"
        ).fetchall()
        assert rows == [], f"duplicate migration rows detected: {rows}"

    def test_existing_legacy_data_unharmed(self, pre_v022_db_with_data: sqlite3.Connection) -> None:
        """Running apply_migrations does not delete, modify, or corrupt rows in legacy tables."""
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
        assert after == before, f"row counts changed across apply_migrations: before={before} after={after}"


# ---------------------------------------------------------------------------
# Group 2 — Migration dataclass construction-time validation
# ---------------------------------------------------------------------------


class TestMigrationDataclassContract:
    def test_migration_rejects_empty_version(self) -> None:
        """Migration construction rejects empty version (catches bad definitions at import time)."""
        with pytest.raises(ValueError, match="version"):
            mig.Migration(version="", description="d", up_sql="CREATE TABLE x (id INTEGER)")
        with pytest.raises(ValueError, match="version"):
            mig.Migration(version="   ", description="d", up_sql="CREATE TABLE x (id INTEGER)")

    def test_migration_rejects_empty_description(self) -> None:
        """Migration construction rejects empty description."""
        with pytest.raises(ValueError, match="description"):
            mig.Migration(version="1.0", description="", up_sql="CREATE TABLE x (id INTEGER)")
        with pytest.raises(ValueError, match="description"):
            mig.Migration(version="1.0", description="\t\n ", up_sql="CREATE TABLE x (id INTEGER)")

    def test_migration_rejects_empty_up_sql(self) -> None:
        """Migration construction rejects empty up_sql."""
        with pytest.raises(ValueError, match="up_sql"):
            mig.Migration(version="1.0", description="d", up_sql="")
        with pytest.raises(ValueError, match="up_sql"):
            mig.Migration(version="1.0", description="d", up_sql="   ")

    def test_migration_is_frozen(self) -> None:
        """@dataclass(frozen=True): attribute reassignment after construction must raise."""
        m = mig.Migration(version="1.0", description="d", up_sql="CREATE TABLE x (id INTEGER)")
        with pytest.raises(dataclasses.FrozenInstanceError):
            m.version = "1.1"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            m.description = "different"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Group 3 — MIGRATIONS registry contract
# ---------------------------------------------------------------------------


class TestMigrationsRegistryContract:
    def test_migrations_registry_versions_monotonic(self) -> None:
        """MIGRATIONS list order must equal version-sort order (catches merge-conflict bugs).

        For P0.0 the registry is empty (just the framework lands); this test passes
        vacuously and stays correct as P0.2 and beyond append migrations. If two PRs
        merge against each other with out-of-order versions, this test fires at CI.
        """
        versions = [m.version for m in mig.MIGRATIONS]
        assert versions == sorted(versions), (
            "MIGRATIONS list order does not match version sort order — "
            "likely a merge-conflict bug.\n"
            f"  actual list order: {versions}\n"
            f"  sorted by version: {sorted(versions)}"
        )


# ---------------------------------------------------------------------------
# Group 4 — atomic transaction behavior
# ---------------------------------------------------------------------------


class TestMigrationAtomicity:
    def test_uses_begin_immediate(self, empty_db: sqlite3.Connection, monkeypatch) -> None:
        """apply_migration must open a BEGIN IMMEDIATE TRANSACTION (per directive §7.6.1).

        Registers a dummy migration so the transaction path is exercised; an
        empty MIGRATIONS list would not exercise BEGIN IMMEDIATE because there
        is nothing to apply.

        Uses ``Connection.set_trace_callback`` (a built-in stdlib SQL spy)
        rather than monkey-patching ``Connection.execute`` directly —
        ``sqlite3.Connection.execute`` is a C-level read-only attribute and
        cannot be replaced.
        """
        noop = mig.Migration(
            version="0.0.0-noop-test",
            description="test fixture migration to exercise the transaction path",
            up_sql="CREATE TABLE test_noop (id INTEGER);",
        )
        monkeypatch.setattr(mig, "MIGRATIONS", [noop])

        executed: list[str] = []
        empty_db.set_trace_callback(executed.append)
        try:
            mig.apply_migrations(empty_db)
        finally:
            empty_db.set_trace_callback(None)

        assert any("BEGIN IMMEDIATE" in s.upper() for s in executed), (
            "expected at least one BEGIN IMMEDIATE statement during apply_migrations; "
            "observed:\n  - " + "\n  - ".join(executed)
        )

    def test_split_handles_semicolons_in_literals(self, empty_db: sqlite3.Connection) -> None:
        """Semicolons inside DEFAULT clauses / CHECK constraints / comments
        must not split a statement mid-stream.

        A naive ``up_sql.split(';')`` would produce 5+ invalid fragments here;
        :func:`sqlite3.complete_statement` chunks correctly.
        """
        migration = mig.Migration(
            version="0.0.0-semicolon-test",
            description="exercises semicolon-in-literal handling",
            up_sql=(
                "CREATE TABLE semicolon_test (\n"
                "    id INTEGER PRIMARY KEY,\n"
                "    note TEXT DEFAULT 'a;b;c'\n"
                ");\n"
                "CREATE INDEX idx_semicolon_test_note ON semicolon_test(note);\n"
            ),
        )
        mig.apply_migration(empty_db, migration)

        # Both statements applied.
        tables = {r[0] for r in empty_db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "semicolon_test" in tables
        indexes = {r[0] for r in empty_db.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
        assert "idx_semicolon_test_note" in indexes

        # DEFAULT literal preserved verbatim — proves the semicolons inside it
        # were not interpreted as statement terminators.
        empty_db.execute("INSERT INTO semicolon_test (id) VALUES (1)")
        note = empty_db.execute("SELECT note FROM semicolon_test WHERE id=1").fetchone()[0]
        assert note == "a;b;c", f"DEFAULT literal corrupted by SQL splitter: expected 'a;b;c', got {note!r}"

    def test_mid_migration_failure_rolls_back(self, empty_db: sqlite3.Connection) -> None:
        """If a registered migration raises mid-apply, the transaction must roll back cleanly.

        Contract: apply_migration() wraps any underlying error in MigrationError so callers
        have a stable exception class to catch. No partial DDL from the failing migration
        should be visible after rollback.
        """
        doomed = mig.Migration(
            version="0.0.0-doomed",
            description="intentionally fails for atomicity testing",
            up_sql="CREATE TABLE doomed_partial (id INTEGER); RAISE_NOT_VALID_SQL_HERE;",
        )

        with pytest.raises(mig.MigrationError):
            mig.apply_migration(empty_db, doomed)

        # Doomed migration must NOT have left a row in schema_meta.
        try:
            rows = empty_db.execute("SELECT version FROM schema_meta WHERE version = '0.0.0-doomed'").fetchall()
            assert rows == [], f"failed migration left a schema_meta row: {rows}"
        except sqlite3.OperationalError:
            # schema_meta itself may not exist if the failure aborted creation —
            # that is also acceptable atomic behavior.
            pass

        # The partial DDL from the failing migration must NOT be visible.
        tables = {r[0] for r in empty_db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "doomed_partial" not in tables, "failed migration left a partially-created table behind"


# ---------------------------------------------------------------------------
# Group 5 — daemon-coordination (PID-file 4-state coverage + canonical default)
# ---------------------------------------------------------------------------


class TestPidCoordination:
    """Per architect-pass guidance: cover all four PID-file states for check_daemon=True,
    plus the canonical-default-path resolution.

    In-process startup migration (check_daemon=False) never touches the PID file
    — that path is exercised implicitly by Group 1 tests.
    """

    def test_no_pid_file_passes(self, empty_db: sqlite3.Connection, tmp_path) -> None:
        """No PID file present → check_daemon=True allows migration."""
        pid_file = tmp_path / "monitor.pid"
        assert not pid_file.exists()
        # Should NOT raise.
        mig.apply_migrations(empty_db, check_daemon=True, pid_file_path=pid_file)

    def test_stale_pid_file_cleaned_up(self, empty_db: sqlite3.Connection, tmp_path) -> None:
        """PID file exists but PID is dead (stale from a crashed daemon) → clean up, proceed."""
        pid_file = tmp_path / "monitor.pid"
        dead_pid = _get_definitely_dead_pid()
        pid_file.write_text(str(dead_pid))
        assert pid_file.exists()

        # Should NOT raise.
        mig.apply_migrations(empty_db, check_daemon=True, pid_file_path=pid_file)

        # Stale file is cleaned up.
        assert not pid_file.exists(), "stale PID file should be removed"

    def test_corrupt_pid_file_cleaned_up(self, empty_db: sqlite3.Connection, tmp_path) -> None:
        """PID file exists but contents are non-integer → clean up, proceed."""
        pid_file = tmp_path / "monitor.pid"
        pid_file.write_text("not-a-pid-just-garbage")
        assert pid_file.exists()

        mig.apply_migrations(empty_db, check_daemon=True, pid_file_path=pid_file)

        assert not pid_file.exists(), "corrupt PID file should be removed"

    def test_live_pid_file_refuses(self, empty_db: sqlite3.Connection, tmp_path) -> None:
        """PID file exists with this test process's own PID (definitely alive) → refuse."""
        pid_file = tmp_path / "monitor.pid"
        live_pid = os.getpid()
        pid_file.write_text(str(live_pid))

        with pytest.raises(mig.DaemonActiveError) as excinfo:
            mig.apply_migrations(empty_db, check_daemon=True, pid_file_path=pid_file)

        # Per directive §7.6.2: error must be clear and reference the daemon.
        msg = str(excinfo.value)
        assert "daemon" in msg.lower(), f"DaemonActiveError message should mention 'daemon'; got: {msg!r}"
        assert "ai-monitor --stop" in msg, f"DaemonActiveError message should tell user how to fix; got: {msg!r}"

        # Live PID file is preserved (not cleaned up — the daemon owns it).
        assert pid_file.exists(), "live PID file must not be removed by refused migration"

    def test_check_daemon_uses_canonical_pid_path_when_unspecified(
        self, empty_db: sqlite3.Connection, tmp_path, monkeypatch
    ) -> None:
        """When pid_file_path is None and check_daemon=True, framework uses DEFAULT_PID_FILE_PATH.

        Per refined contract: caller should not need to know the canonical path —
        the framework resolves it internally.
        """
        canonical_mock = tmp_path / "claude_watch_output" / "monitor.pid"
        canonical_mock.parent.mkdir(parents=True)
        dead_pid = _get_definitely_dead_pid()
        canonical_mock.write_text(str(dead_pid))

        # Patch the module-level canonical-path constant.
        monkeypatch.setattr(mig, "DEFAULT_PID_FILE_PATH", canonical_mock)

        # No explicit pid_file_path argument — must resolve via DEFAULT_PID_FILE_PATH.
        mig.apply_migrations(empty_db, check_daemon=True)

        # Stale file at the canonical-mocked location is cleaned up — proves the
        # canonical path was consulted (otherwise the file would still be there).
        assert not canonical_mock.exists(), (
            "framework should have consulted DEFAULT_PID_FILE_PATH and cleaned the stale file"
        )
