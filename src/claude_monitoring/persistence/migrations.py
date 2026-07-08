"""v0.2.2 schema migration framework.

P0.0 introduces the framework with an empty :data:`MIGRATIONS` registry.
P0.2 will register the first real migration (the six attack-surface tables).

Locked contract (per ``~/Documents/vigil-notes/v022/phase-0/p0.0/architect-pass.md``):

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
    raise :class:`ValueError`. ``down_sql`` is optional (default empty); an
    empty ``down_sql`` is a deliberate "apply-only" migration, and any call
    to :func:`rollback_migration` against it raises :class:`MigrationError`
    rather than silently no-op'ing.

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
        down_sql: SQL statements that reverse ``up_sql``. Same chunking and
            termination rules as ``up_sql``. Default ``""`` means
            "apply-only — rollback unsupported." When non-empty, exercised by
            :func:`rollback_migration` and by the ``migration-rollback-test``
            CI gate (directive §11.2). Added to the contract in v0.2.2 P0.2
            per the architect-pass §8 escape hatch in P0.0.
    """

    version: str
    description: str
    up_sql: str
    down_sql: str = ""

    def __post_init__(self) -> None:
        if not self.version or not self.version.strip():
            raise ValueError("Migration.version must be a non-empty string")
        if not self.description or not self.description.strip():
            raise ValueError("Migration.description must be a non-empty string")
        if not self.up_sql or not self.up_sql.strip():
            raise ValueError("Migration.up_sql must be a non-empty string")
        # down_sql intentionally permits empty; rollback_migration enforces
        # the apply-only contract by raising at rollback time.


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_P0_2_ATTACK_SURFACE_UP_SQL = """\
CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    parent_asset_id TEXT,
    name TEXT NOT NULL,
    version TEXT,
    install_path TEXT,
    source TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    last_scanned TIMESTAMP NOT NULL,
    current_state TEXT NOT NULL,
    ontology_tags TEXT,
    risk_score INTEGER,
    risk_band TEXT,
    risk_factors TEXT,
    is_vigil_component INTEGER DEFAULT 0,
    FOREIGN KEY (parent_asset_id) REFERENCES assets(id)
);

CREATE INDEX idx_assets_type ON assets(type);
CREATE INDEX idx_assets_parent ON assets(parent_asset_id);
CREATE INDEX idx_assets_risk_band ON assets(risk_band);
CREATE INDEX idx_assets_last_seen ON assets(last_seen);

-- asset_cves: spec §9.1 per-asset CVE join table. DDL'd here for the
-- schema-rollback gate (round-trip drop/create) AND to reserve the
-- surface for v0.3+ reverse-CVE-to-asset queries. Empty through v0.2.2:
-- per-asset CVE data is materialized inline as `assets.risk_factors.cves`
-- JSON via the §6.10 v1 schema (see scan-scoring-callsite PR #115). See
-- spec §9.1.1 amendment (Rajan 2026-06-11, P4.2) for the storage-shape
-- ratification + v0.3 reactivation path. DO NOT add INSERT/SELECT
-- against this table without a follow-up directive amendment.
CREATE TABLE asset_cves (
    asset_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity REAL,
    published TIMESTAMP,
    description TEXT,
    cve_references TEXT,
    discovered_at TIMESTAMP NOT NULL,
    PRIMARY KEY (asset_id, cve_id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE INDEX idx_cves_severity ON asset_cves(severity);
CREATE INDEX idx_cves_discovered ON asset_cves(discovered_at);

CREATE TABLE asset_history (
    asset_id TEXT NOT NULL,
    scan_timestamp TIMESTAMP NOT NULL,
    state_snapshot TEXT NOT NULL,
    changes_from_previous TEXT,
    PRIMARY KEY (asset_id, scan_timestamp),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE INDEX idx_history_asset ON asset_history(asset_id);

-- cve_cache: spec §9.1 per-(ecosystem, package, cve_id) vuln master.
-- DDL'd here for the schema-rollback gate (round-trip drop/create) AND
-- to reserve the surface for v0.3+ reverse-CVE queries (severity
-- histograms, fleet-wide aging). Empty through v0.2.2: CVE feed
-- caching ships as two file-backed caches under
-- `${VIGIL_OUTPUT}/cves/` per `attack_surface/cves/` (PR #114) —
-- querybatch 24h symmetric TTL, vulns 7d TTL, chmod 600, atomic
-- tempfile+rename writes. File storage chosen for privacy-posture
-- isolation: CVE query metadata MUST NOT share row space with
-- capture data in monitor.db. See spec §9.1.1 amendment (Rajan
-- 2026-06-11, P4.2). `cve_references` column name preserved (vs
-- spec's `references` which is a reserved SQL keyword that fails
-- to parse); ratified as canonical for v0.3+ SQL consumers in the
-- amendment.
CREATE TABLE cve_cache (
    package_ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity REAL,
    affected_versions TEXT,
    published TIMESTAMP,
    description TEXT,
    cve_references TEXT,
    fetched_at TIMESTAMP NOT NULL,
    PRIMARY KEY (package_ecosystem, package_name, cve_id)
);

CREATE INDEX idx_cve_cache_ecosystem ON cve_cache(package_ecosystem, package_name);
CREATE INDEX idx_cve_cache_fetched ON cve_cache(fetched_at);

CREATE TABLE discovery_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    trigger TEXT,
    assets_discovered INTEGER,
    new_assets INTEGER,
    removed_assets INTEGER,
    new_cves INTEGER,
    errors TEXT
);

CREATE INDEX idx_runs_started ON discovery_runs(started_at);

CREATE TABLE permission_grants (
    integration TEXT NOT NULL,
    granted_at TIMESTAMP NOT NULL,
    granted_scope TEXT,
    PRIMARY KEY (integration)
);
"""
"""Up-SQL for v0.2.2.001 — six attack-surface tables + ten indexes.

Spec §9.1 of v022-attack-surface-feature-spec-v1-LOCKED.md with six
architect-pass-ratified deviations:

1. ``cve_references`` (renamed from spec's ``references``, a SQLite
   reserved keyword that fails to parse) in both ``asset_cves`` and
   ``cve_cache``. Test: ``test_*_uses_cve_references_not_references``.
2. ``TIMESTAMP`` column type preserved per spec; populated via
   ``time.time()`` (Unix epoch float) for consistency with ``schema_meta``.
3. ``FOREIGN KEY`` clauses are present per spec but enforcement requires
   ``PRAGMA foreign_keys = ON`` which is OFF by default in db.py — clauses
   are documentation-only in P0.2; enabling PRAGMA is deferred to a
   dedicated PR with a sweep of the legacy 20 tables for orphan rows.
4. (Framework contract change, not a schema deviation.) ``Migration``
   dataclass extended with optional ``down_sql: str = ""`` to support
   the rollback gate.
5. ``assets.current_state TEXT NOT NULL`` (tightened from spec's
   nullable) — matches the Asset dataclass contract in directive §7.1.
6. Single ``Migration`` record covers all six tables + ten indexes;
   per-migration transactionality per P0.0 contract point 11.

See ``~/Documents/vigil-notes/architect-pass-P0.2.md`` for ratification.
"""


_P0_2_ATTACK_SURFACE_DOWN_SQL = """\
DROP TABLE IF EXISTS permission_grants;
DROP TABLE IF EXISTS discovery_runs;
DROP TABLE IF EXISTS cve_cache;
DROP TABLE IF EXISTS asset_history;
DROP TABLE IF EXISTS asset_cves;
DROP TABLE IF EXISTS assets;
"""
"""Down-SQL for v0.2.2.001.

Drops the six attack-surface tables in reverse dependency order so the FK
declarations don't refuse the drop. SQLite drops dependent indexes
automatically as part of ``DROP TABLE``, so no explicit ``DROP INDEX``
statements are needed. Exercised by the round-trip rollback test and the
``migration-rollback-test`` CI gate (directive §11.2).
"""


_P4_4_HISTORY_RUN_ID_UP_SQL = """\
ALTER TABLE asset_history ADD COLUMN discovery_run_id INTEGER REFERENCES discovery_runs(id);
CREATE INDEX idx_history_run ON asset_history(discovery_run_id);
"""
"""Up-SQL for v0.2.2.002 — asset_history.discovery_run_id FK.

P4.4 (judge p4.4.a3 APPROVE 2026-06-13) — spec §9.1 amendment. Adds an
exact integer FK so the cross-table trigger-attribution join is
`asset_history.discovery_run_id == discovery_runs.id`, not a fragile
float-equality on timestamps. The prior draft assumed
``discovery_runs.started_at == assets.last_scanned`` via a shared
``time.time()`` value, but the orchestrator's ``started_at`` and
``audit.record_run_started``'s internal ``time.time()`` are distinct
calls producing distinct floats — judge p4.4.a2 caught this.

PRAGMA foreign_keys is OFF (per P0.2 deviation #3), so the REFERENCES
clause is documentary; orphan FK values render `trigger="unknown"` in
the endpoint via LEFT JOIN.
"""


_P4_4_HISTORY_RUN_ID_DOWN_SQL = """\
DROP INDEX IF EXISTS idx_history_run;
ALTER TABLE asset_history DROP COLUMN discovery_run_id;
"""
"""Down-SQL for v0.2.2.002.

Reverses the P4.4 amendment cleanly. SQLite 3.35+ supports
``ALTER TABLE ... DROP COLUMN`` natively; the round-trip rollback gate
exercises this path.
"""


_P9_3_ALERT_TRIAGE_UP_SQL = """\
CREATE TABLE IF NOT EXISTS alert_triage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE,
    verdict TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_dismissals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE,
    dismissed_at TEXT NOT NULL,
    reason TEXT
);
INSERT INTO alert_triage (event_id, verdict, reason, created_at)
    SELECT event_id, 'dismissed', reason, dismissed_at FROM alert_dismissals;
DROP TABLE alert_dismissals;
"""
"""Up-SQL for v0.2.2.003 — alert_triage generalization of alert_dismissals.

P9.3 (judge p9.3.a2 APPROVE 2026-06-24) per LOCKED phase9 scope lines 49-60.

Generalizes the legacy ``alert_dismissals`` table into ``alert_triage`` with
an explicit ``verdict`` column ∈ {true_positive, false_positive, dismissed,
muted}. P9.3 ships ZERO mute capability — the column is plain TEXT (no
CHECK constraint) so P9.4 lands by adding ``muted`` to the LIVE endpoint
allowlist + UI affordance + security guardrails, with no re-migration.

Sequence:
  1. CREATE alert_triage with verdict NOT NULL + created_at audit column.
  2. INSERT-SELECT existing dismissals → verdict='dismissed'. Reason and
     dismissed_at (→ created_at) preserved verbatim.
  3. DROP alert_dismissals.

CRITICAL: the legacy ``CREATE TABLE IF NOT EXISTS alert_dismissals`` block
in ``db.py:init_db()`` MUST be removed in the same PR — otherwise the DROP
here is undone on every daemon restart (split-brain). See M6 regression
test in ``tests/test_alerts_triage_migration.py``.

Foreign-key clause omitted per P0.2 deviation #3 (PRAGMA foreign_keys is
OFF in db.py); event_id orphans are tolerated like every other table.
"""


_P9_3_ALERT_TRIAGE_DOWN_SQL = """\
CREATE TABLE IF NOT EXISTS alert_dismissals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE,
    dismissed_at TEXT NOT NULL,
    reason TEXT
);
INSERT INTO alert_dismissals (event_id, dismissed_at, reason)
    SELECT event_id, created_at, reason FROM alert_triage WHERE verdict = 'dismissed';
DROP TABLE alert_triage;
"""
"""Down-SQL for v0.2.2.003.

Reverses the up cleanly. TP/FP rows are intentionally LOST on
down-migration — restoring the pre-P9.3 state means restoring an absence
of TP/FP capability. Operators downgrading lose their TP/FP labels but
keep all their dismissals.
"""


_P8_D_PERMISSION_AUDIT_UP_SQL = """\
CREATE TABLE permission_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('granted', 'revoked')),
    event_at TIMESTAMP NOT NULL,
    granted_scope TEXT
);
CREATE INDEX idx_permission_audit_integration ON permission_audit(integration);
CREATE INDEX idx_permission_audit_event_at ON permission_audit(event_at);
"""
"""Up-SQL for v0.2.2.004 — P8-D append-only permission audit history.

Per Rajan JD-2 ratification 2026-07-08 (Option C): separate append-only
permission_audit table; existing permission_grants (P0.2-shipped) stays
as the current-state view (last-write-wins UPSERT).

The audit table preserves EVERY grant/revoke event as an immutable row,
so grant → revoke → re-grant cycles never lose prior timestamps. Meets
LOCKED spec §4.5.1 requirement 6 ("User-visible audit log") in the
integrity-preserving way.

Schema follows the shape proposed in p8-D.a1.result.md JD-2 Option C:
- id: surrogate PK, auto-incremented (event ordering + reference)
- integration: which integration was granted/revoked
- event: 'granted' or 'revoked' (CHECK-enforced at DB layer; not
  Python-only, so any bad write fails hard rather than corrupting audit)
- event_at: when the event happened
- granted_scope: optional scope string for the grant (NULL on revoke)

CHECK-constraint choice: Rajan JD-2 required "append-only" — the CHECK
means the write path CANNOT accidentally UPDATE a row to a different
event value (would be a schema violation). Enforcement at DB layer
rather than Python is a safe-default (§8 empirical ratchet cannot be
bypassed by an application bug).

Spec §9.1 amendment inline per project_v022_phase1_ratifications.md
Decision 5 precedent — attach the amendment paragraph to the Phase C
submission for Rajan external ratification (CF-11).

Safe-default flip contract (p8-D.a1.verdict.md §4): NO token column, NO
credential column, NO PII beyond localhost operator implicit identity.
Adding any such column flips PR to security-C4 → HALT for Rajan.

Foreign-key clause omitted per P0.2 deviation #3 (PRAGMA foreign_keys
is OFF in db.py); integration-name orphans tolerated like every other
table.
"""


_P8_D_PERMISSION_AUDIT_DOWN_SQL = """\
DROP TABLE IF EXISTS permission_audit;
"""
"""Down-SQL for v0.2.2.004.

Drops permission_audit; SQLite drops the two indexes automatically as
part of DROP TABLE. Audit history is intentionally LOST on down-migration
— restoring the pre-P8-D state means restoring an absence of the audit
capability. permission_grants (existing table, P0.2-shipped) is
unaffected.
"""


MIGRATIONS: list[Migration] = [
    Migration(
        version="0.2.2.001",
        description=(
            "Add attack-surface tables (assets, asset_cves, asset_history, "
            "cve_cache, discovery_runs, permission_grants) per spec §9.1 + "
            "P0.2 architect-pass deviations"
        ),
        up_sql=_P0_2_ATTACK_SURFACE_UP_SQL,
        down_sql=_P0_2_ATTACK_SURFACE_DOWN_SQL,
    ),
    Migration(
        version="0.2.2.002",
        description=(
            "P4.4: asset_history.discovery_run_id INTEGER FK to discovery_runs(id) "
            "+ idx_history_run; replaces fragile timestamp-equality join with "
            "exact integer FK (spec §9.1 amendment per judge p4.4.a3)"
        ),
        up_sql=_P4_4_HISTORY_RUN_ID_UP_SQL,
        down_sql=_P4_4_HISTORY_RUN_ID_DOWN_SQL,
    ),
    Migration(
        version="0.2.2.003",
        description=(
            "P9.3: generalize alert_dismissals into alert_triage "
            "(verdict ∈ {true_positive, false_positive, dismissed, "
            "muted}; LIVE endpoint allowlist excludes muted until P9.4)"
        ),
        up_sql=_P9_3_ALERT_TRIAGE_UP_SQL,
        down_sql=_P9_3_ALERT_TRIAGE_DOWN_SQL,
    ),
    Migration(
        version="0.2.2.004",
        description=(
            "P8-D: append-only permission_audit table for grant/revoke "
            "history (spec §9.1 amendment per Rajan JD-2 ratification "
            "2026-07-08 Option C); permission_grants unchanged as "
            "current-state view"
        ),
        up_sql=_P8_D_PERMISSION_AUDIT_UP_SQL,
        down_sql=_P8_D_PERMISSION_AUDIT_DOWN_SQL,
    ),
]
"""Ordered registry of migrations.

Contract: list order IS application order. The
``test_migrations_registry_versions_monotonic`` CI test asserts version
strings sort monotonically across the list, so merge conflicts (two PRs
each appending an out-of-order version) surface at PR time, not at
runtime.

P0.0 introduced the framework with an empty registry; P0.2 lands the
first real migration here. Subsequent migrations append to this list.
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


def rollback_migration(conn: sqlite3.Connection, migration: Migration) -> None:
    """Roll back a single migration via its ``down_sql``.

    Runs in a ``BEGIN IMMEDIATE TRANSACTION`` with the same atomicity
    guarantees as :func:`apply_migration`: on any error, ROLLBACK is issued
    and a :class:`MigrationError` is raised. The ``schema_meta`` audit row
    is preserved on failure so the caller knows the migration is still
    "applied" and can retry after fixing the down_sql.

    Idempotency: if the migration is not currently recorded in
    ``schema_meta`` (never applied OR already rolled back), this is a
    no-op. Mirrors :func:`apply_migration`'s already-applied skip.

    Side effect on the no-op path: ``schema_meta`` is ensured (created
    if absent) BEFORE the existence check so the SELECT can run against a
    well-formed table. Calling ``rollback_migration`` against a never-
    touched DB therefore creates ``schema_meta`` even though the rollback
    itself is a no-op. Matches the side effect of :func:`apply_migration`.

    Failure-mode note: the ``DELETE FROM schema_meta`` is the *last* DML
    in the transaction. If any down_sql statement fails, ROLLBACK reverts
    both the DDL changes already executed AND the (not-yet-executed) row
    deletion — i.e., the audit row is preserved by SQLite's transaction
    semantics, not by a separate save step.

    Args:
        conn: SQLite connection. Same preconditions as :func:`apply_migration`
            (writable; no open transaction).
        migration: The :class:`Migration` to roll back.

    Raises:
        MigrationError: If ``migration.down_sql`` is empty (apply-only
            migration; rollback unsupported), or if the down_sql execution
            fails for any reason. Original exception attached via
            ``__cause__``.
    """
    if not migration.down_sql or not migration.down_sql.strip():
        raise MigrationError(
            f"Migration {migration.version!r} has empty down_sql; "
            "rollback unsupported. Migrations may be flagged apply-only by "
            "omitting down_sql at construction time."
        )

    _ensure_schema_meta(conn)

    try:
        conn.execute("BEGIN IMMEDIATE TRANSACTION")

        # Idempotency check inside the transaction (parallel to apply_migration).
        existing = conn.execute(
            "SELECT 1 FROM schema_meta WHERE version = ?",
            (migration.version,),
        ).fetchone()
        if not existing:
            conn.execute("ROLLBACK")
            return  # not applied — nothing to roll back

        for statement in _split_sql_statements(migration.down_sql):
            conn.execute(statement)
        conn.execute(
            "DELETE FROM schema_meta WHERE version = ?",
            (migration.version,),
        )
        conn.execute("COMMIT")
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise MigrationError(f"Rollback of migration {migration.version!r} failed: {exc}") from exc


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
