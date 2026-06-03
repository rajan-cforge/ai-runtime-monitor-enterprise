"""v0.2.2 schema migration framework.

P0.0 introduces the framework with an empty :data:`MIGRATIONS` registry.
P0.2 will register the first real migration (the six attack-surface tables).

Locked contract (per ``~/Documents/vigil-notes/architect-pass-P0.0.md``):

1. :class:`Migration` is an immutable ``@dataclass(frozen=True)`` of
   ``(version, description, up_sql)``. Construction-time validation rejects
   empty fields.
2. :data:`MIGRATIONS` is an ordered list; list order is application order.
   A CI test asserts version strings sort monotonically across the list,
   so merge conflicts surface at PR review time rather than at runtime.
3. :func:`apply_migrations` is the framework entry point:
   ``apply_migrations(conn, *, check_daemon=False, pid_file_path=None)``.
4. :func:`apply_migration` applies a single migration in a BEGIN IMMEDIATE
   transaction with rollback on any error.
5. :class:`MigrationError` wraps any mid-migration failure with a stable
   exception class for callers to catch.
6. :class:`DaemonActiveError` is raised when ``check_daemon=True`` and a
   live daemon owns the PID file — migration is refused before any schema
   work is attempted.
7. In-process startup uses ``check_daemon=False`` (the
   :func:`claude_monitoring.db.init_db` path — the daemon migrating its
   own schema at boot, before opening for business).
8. The future external ``ai-monitor --migrate`` CLI path uses
   ``check_daemon=True`` to protect against the upgrade-tool race.
9. :data:`DEFAULT_PID_FILE_PATH` (``~/claude_watch_output/monitor.pid``)
   is used when ``check_daemon=True`` and ``pid_file_path`` is unspecified.
10. Backfill convention for pre-versioning installs: the framework inserts
    one ``(<version>-baseline, time.time(), "Backfilled by P0.0: …")``
    row into ``schema_meta`` so the migration runner has a known starting
    point. The ``-baseline`` suffix distinguishes backfill from real
    applied migrations.

See ``docs/spec/MIGRATIONS.md`` for the user-facing documentation,
including the legacy/framework two-mechanism coexistence note.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("ai-runtime-monitor.persistence.migrations")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


DEFAULT_PID_FILE_PATH: Path = Path.home() / "claude_watch_output" / "monitor.pid"
"""Canonical path to the monitor daemon's PID file.

Matches ``lifecycle.py`` and ``status.py``. Tests monkeypatch this constant
to point at a tmp location.
"""


BASELINE_VERSION: str = "0.2.0-baseline"
"""Version string used in the backfill row for pre-versioning installs."""


BASELINE_DESCRIPTION: str = (
    "Backfilled by P0.0: pre-versioning install state — schema-meta framework introduced in v0.2.2"
)
"""Description text for the backfill row."""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MigrationError(Exception):
    """Raised when a migration's schema work itself fails.

    Distinct from :class:`DaemonActiveError`, which means migration was
    refused before any schema work was attempted. Callers handle the two
    differently:

    - ``MigrationError`` → investigate why the schema work broke (DDL
      error, disk full, verification failure, ...).
    - ``DaemonActiveError`` → stop the daemon and retry.
    """


class DaemonActiveError(Exception):
    """Raised when ``check_daemon=True`` and a live daemon PID file exists.

    The migration was NOT attempted. Caller should stop the daemon
    (e.g., ``ai-monitor --stop``) and retry. The PID file is preserved
    (the daemon owns it).
    """


# ---------------------------------------------------------------------------
# Migration dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Migration:
    """An immutable migration definition.

    Construction-time validation catches bad migration definitions at import
    time rather than at apply time — empty version/description/up_sql all
    raise :class:`ValueError`.

    Attributes:
        version: Unique version identifier (e.g., ``"0.2.2.001"``). Must be
            non-empty after strip. The :data:`MIGRATIONS` list is in
            application order; per convention, version strings sort
            monotonically across the list (enforced by the
            ``test_migrations_registry_versions_monotonic`` CI test).
        description: Human-readable summary; surfaced in ``schema_meta`` and
            logs. Must be non-empty after strip.
        up_sql: SQL statements to apply. Multiple statements separated by
            ``;``. Statements are chunked by :func:`sqlite3.complete_statement`
            at apply time, so semicolons inside string literals, CHECK
            constraints, triggers, or comments are handled correctly. Each
            statement must be terminated by ``;`` — an unterminated final
            statement raises :class:`ValueError` (wrapped as
            :class:`MigrationError`) at apply time. Must be non-empty after
            strip.
    """

    version: str
    description: str
    up_sql: str

    def __post_init__(self) -> None:
        if not self.version or not self.version.strip():
            raise ValueError("Migration.version must be a non-empty string")
        if not self.description or not self.description.strip():
            raise ValueError("Migration.description must be a non-empty string")
        if not self.up_sql or not self.up_sql.strip():
            raise ValueError("Migration.up_sql must be a non-empty string")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


MIGRATIONS: list[Migration] = []
"""Ordered registry of migrations.

P0.0 ships an empty registry — the framework lands without any actual
migrations. P0.2 will register the first real migration (the six
attack-surface tables from spec §9.1) by appending to this list.

Contract: list order IS application order. The
``test_migrations_registry_versions_monotonic`` CI test asserts version
strings sort monotonically across the list, so merge conflicts (two PRs
each appending an out-of-order version) surface at PR time, not at
runtime.
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_schema_meta(conn: sqlite3.Connection) -> None:
    """Create the ``schema_meta`` table if it doesn't exist. Idempotent."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_meta (
            version TEXT PRIMARY KEY,
            applied_at REAL NOT NULL,
            description TEXT
        )
        """
    )


def _backfill_baseline_if_needed(conn: sqlite3.Connection) -> None:
    """Insert the baseline row if this looks like a pre-versioning install.

    Heuristic: ``schema_meta`` has zero rows AND a legacy table exists. We
    check for ``api_calls`` as the canonical legacy table (largest and
    oldest in the existing schema). A truly fresh install (no legacy
    tables) gets no backfill — the migration runner just records each
    real migration as it applies.
    """
    has_rows = conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0]
    if has_rows:
        return
    legacy = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_calls'").fetchone()
    if not legacy:
        return  # truly fresh install
    conn.execute(
        "INSERT INTO schema_meta (version, applied_at, description) VALUES (?, ?, ?)",
        (BASELINE_VERSION, time.time(), BASELINE_DESCRIPTION),
    )
    conn.commit()


def _pid_is_alive(pid: int) -> bool:
    """Return True if ``pid`` corresponds to a live process.

    Uses ``os.kill(pid, 0)`` — sends signal 0 which does nothing but lets
    the kernel tell us whether the PID exists. ``ProcessLookupError`` →
    dead; any other OS-level signal failure → conservatively treat as
    alive (refusing migration is the safe choice when state is ambiguous).
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we can't signal it. Conservatively alive.
        return True
    except OSError as exc:
        # Unknown errno from the kernel (could be a future code, an unusual
        # macOS/Linux mismatch, etc.). Mirror the PermissionError branch:
        # conservatively treat as alive rather than letting an ambiguous
        # signal failure unblock migration.
        logger.warning(
            "os.kill(%d, 0) raised unexpected OSError %s; conservatively treating PID as alive",
            pid,
            exc,
        )
        return True
    return True


def _check_daemon_not_active(pid_file_path: Path) -> None:
    """Refuse migration if a live daemon owns ``pid_file_path``.

    Handles all four PID-file states:

    1. No PID file → no-op (passes).
    2. PID file with corrupt contents → remove the file, pass.
    3. PID file with dead PID → remove the file, pass.
    4. PID file with live PID → raise :class:`DaemonActiveError`, file
       preserved (the daemon owns it).
    """
    if not pid_file_path.exists():
        return
    try:
        contents = pid_file_path.read_text().strip()
        pid = int(contents)
    except (ValueError, OSError):
        logger.warning(
            "PID file at %s is corrupt or unreadable; removing as stale",
            pid_file_path,
        )
        try:
            pid_file_path.unlink()
        except OSError:
            pass
        return
    if _pid_is_alive(pid):
        raise DaemonActiveError(
            f"Vigil daemon (PID {pid}) is running. Run `ai-monitor --stop` first, then retry the migration."
        )
    logger.info("PID file at %s holds dead PID %d; removing as stale", pid_file_path, pid)
    try:
        pid_file_path.unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# SQL splitting helper
# ---------------------------------------------------------------------------


def _split_sql_statements(sql: str) -> list[str]:
    """Split a multi-statement SQL string into individual statements.

    Uses :func:`sqlite3.complete_statement` to walk the input line-by-line,
    accumulating into a buffer until SQLite's own parser agrees the buffer
    is one or more complete statements. Correctly handles semicolons inside:

    - string literals (``DEFAULT 'a;b;c'``)
    - CHECK constraint expressions
    - trigger bodies
    - SQL comments

    A naive ``sql.split(';')`` mishandles all of the above and would silently
    corrupt any migration that uses them. :func:`sqlite3.complete_statement`
    is the SQLite-native chunker and is what we want.

    Returns:
        Ordered list of complete SQL statements (whitespace-stripped).
        Trailing-only whitespace is ignored. Empty input → empty list.

    Raises:
        ValueError: If the input contains an incomplete final statement
            (e.g., unclosed parenthesis, unterminated string literal).
            Catching this at the splitter is better than at execute time
            because the error message points at the migration author's
            actual mistake.
    """
    statements: list[str] = []
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            stripped = buffer.strip()
            if stripped:
                statements.append(stripped)
            buffer = ""
    if buffer.strip():
        raise ValueError(f"Incomplete SQL statement at end of migration: {buffer.strip()!r}")
    return statements


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def apply_migration(conn: sqlite3.Connection, migration: Migration) -> None:
    """Apply a single migration within a ``BEGIN IMMEDIATE TRANSACTION``.

    On any error during the transaction (DDL failure, verification failure,
    disk full, ...) the entire migration rolls back and :class:`MigrationError`
    is raised — no partial state is left in the database.

    Idempotency: if the migration's version already exists in
    ``schema_meta``, this is a no-op. The existence check happens *inside*
    the transaction so concurrent invocations cannot both pass the check
    and race into a UNIQUE-constraint violation (TOCTOU-safe).

    Args:
        conn: SQLite connection. Must be writable. The framework manages
            its own transactions; the caller must not have an open
            transaction when invoking this function.
        migration: The :class:`Migration` to apply.

    Raises:
        MigrationError: If any statement in ``migration.up_sql`` fails or
            the schema_meta insert fails, or if the SQL splitter rejects
            the migration (incomplete final statement). The original
            exception is attached via ``__cause__``.
    """
    _ensure_schema_meta(conn)

    try:
        conn.execute("BEGIN IMMEDIATE TRANSACTION")

        # Idempotency check inside the transaction: TOCTOU-safe against
        # concurrent migrators.
        existing = conn.execute(
            "SELECT 1 FROM schema_meta WHERE version = ?",
            (migration.version,),
        ).fetchone()
        if existing:
            conn.execute("ROLLBACK")
            return  # already applied

        for statement in _split_sql_statements(migration.up_sql):
            conn.execute(statement)
        conn.execute(
            "INSERT INTO schema_meta (version, applied_at, description) VALUES (?, ?, ?)",
            (migration.version, time.time(), migration.description),
        )
        conn.execute("COMMIT")
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise MigrationError(f"Migration {migration.version!r} failed: {exc}") from exc


def apply_migrations(
    conn: sqlite3.Connection,
    *,
    check_daemon: bool = False,
    pid_file_path: Path | None = None,
) -> None:
    """Apply all pending migrations in the :data:`MIGRATIONS` registry.

    Args:
        conn: SQLite connection. Must be writable. The framework manages
            its own transactions; the caller must not have an open
            transaction when calling.
        check_daemon: If ``True``, refuse to migrate when a live daemon
            PID file exists. Used by the (future) external ``--migrate``
            CLI path. The in-process startup migration
            (:func:`claude_monitoring.db.init_db`) uses ``False`` — the
            daemon is migrating its own schema before opening for
            business; refusing on its own PID file would be a chicken-
            and-egg failure.
        pid_file_path: Override the canonical PID file path. When
            ``check_daemon=True`` and this is ``None``, the framework
            resolves to :data:`DEFAULT_PID_FILE_PATH`
            (``~/claude_watch_output/monitor.pid``). Ignored when
            ``check_daemon=False``.

    Raises:
        DaemonActiveError: If ``check_daemon=True`` and a live daemon owns
            the PID file. Migration is NOT attempted.
        MigrationError: If any registered migration fails mid-apply.
            Earlier migrations that succeeded in this invocation stay
            applied (per-migration transactionality).
    """
    if check_daemon:
        path = pid_file_path if pid_file_path is not None else DEFAULT_PID_FILE_PATH
        _check_daemon_not_active(path)

    _ensure_schema_meta(conn)
    _backfill_baseline_if_needed(conn)

    for migration in MIGRATIONS:
        apply_migration(conn, migration)
