# Schema Migrations (v0.2.2+)

**Status:** v1.0 — introduced in v0.2.2 P0.0 (`feat/v022-p0.0-schema-meta`)
**Authoritative implementation:** `src/claude_monitoring/persistence/migrations.py`
**Contract ratification:** `~/Documents/vigil-notes/architect-pass-P0.0.md`

This document is the user-facing contract for the v0.2.2 schema migration
framework. The architect-pass document (linked above) is the locked contract
for the *implementation*; this doc is for downstream consumers (future PR
authors registering migrations, contributors reading the codebase).

---

## 1. Purpose

`monitor.db` accumulates schema changes over time. v0.2.1 and earlier used
an inline imperative pattern: `init_db()` issues `CREATE TABLE IF NOT
EXISTS` for every table, plus `try/except ALTER TABLE ... ADD COLUMN` for
evolutionary changes. The pattern works but has no observability —
there's no way to ask "which migrations have been applied?" or to enforce
ordering, atomicity, or rollback.

v0.2.2 P0.0 introduces a **versioned migration framework** that records
each applied schema change in a `schema_meta` table. New tables (v0.2.2
and beyond) are added via the framework. The framework lives in
`src/claude_monitoring/persistence/migrations.py`.

---

## 2. Two-mechanism coexistence

P0.0 is **additive**. The legacy pattern continues to work for the 20
pre-v0.2.2 tables; the framework adds a parallel mechanism for everything
forward.

| Aspect | Legacy (existing tables) | Migration framework (v0.2.2+) |
|---|---|---|
| Used for | The 20 pre-v0.2.2 tables (`api_calls`, `sessions`, ...) | All new tables shipped in v0.2.2+ |
| Mechanism | `CREATE TABLE IF NOT EXISTS` + `try/except ALTER TABLE ... ADD COLUMN` in `db.py::init_db` | Versioned `Migration` records applied in `BEGIN IMMEDIATE` transactions, recorded in `schema_meta` |
| Acceptable for | Column backfills on existing tables | New tables and any C3+ schema change |
| Observability | None — only SQLite duplicate-column errors signal "already applied" | Full audit row per applied migration with timestamp + description |
| Atomicity | Per-statement; no transaction | Per-migration; atomic rollback on any failure |
| Rollback | None | `down_sql` (not in P0.0 dataclass; may be added when first non-trivial rollback is needed) |
| Coordination | None — runs every time `init_db()` is called | PID-coordination supported for external invocations |

**Future direction:** if the migration framework proves itself through
v0.2.2, future PRs may retro-version the legacy tables. Not in P0.0
scope.

---

## 3. The locked contract

The public surface is exported from `claude_monitoring.persistence`:

```python
from claude_monitoring.persistence import (
    Migration,            # @dataclass(frozen=True)
    MIGRATIONS,           # list[Migration]
    apply_migration,      # apply one
    apply_migrations,     # apply all pending
    MigrationError,       # mid-migration schema work failed
    DaemonActiveError,    # refused: a live daemon owns the PID file
    DEFAULT_PID_FILE_PATH,
)
```

### `Migration`

```python
@dataclass(frozen=True)
class Migration:
    version: str        # unique, e.g. "0.2.2.001"
    description: str    # human-readable summary
    up_sql: str         # statements separated by ';'
    down_sql: str = ""  # rollback statements (P0.2+); default empty = apply-only
```

Construction-time validation rejects empty `version`, empty `description`,
empty `up_sql`. `down_sql` is optional with default `""`; an empty
`down_sql` is a deliberate "apply-only" migration. `frozen=True` makes
instances immutable.

The `down_sql` field was added in v0.2.2 P0.2 per the P0.0 architect-pass
§8 escape hatch ("if P0.2's architect-pass identifies the need, the field
can be added as an optional `down_sql: str = ''`"). Backwards-compatible
extension: every existing call site that omitted `down_sql` continues to
work; only `rollback_migration` requires non-empty `down_sql`.

### `MIGRATIONS`

An ordered `list[Migration]`. **List order is application order.** The
CI test `test_migrations_registry_versions_monotonic` asserts that
version strings sort monotonically across the list, so a merge conflict
(two PRs each appending an out-of-order version) surfaces at PR review
time rather than at runtime.

P0.0 ships with `MIGRATIONS = []`. P0.2 will append the first real
migration (the six attack-surface tables from spec §9.1).

### `apply_migrations(conn, *, check_daemon=False, pid_file_path=None)`

Framework entry point. Ensures `schema_meta` exists, backfills the
baseline row if this looks like a pre-versioning install (legacy tables
present but `schema_meta` empty), then iterates `MIGRATIONS` in order
applying any not already in `schema_meta`.

- `check_daemon=False` (default) — **in-process startup pattern.** Used
  by `db.py::init_db`. The daemon is migrating its own schema at boot,
  before opening for business; PID-coordination would create a chicken-
  and-egg failure (the daemon would refuse to start because its own PID
  file is about to be written).
- `check_daemon=True` — **external pattern.** Reserved for a future
  `ai-monitor --migrate` CLI command or upgrade tools. Refuses migration
  if a live daemon owns the PID file. The spec's "no live migration"
  intent (directive §7.6.2) is about protecting against external
  processes racing the daemon, not about the daemon initializing
  itself.
- `pid_file_path` — defaults to `DEFAULT_PID_FILE_PATH`
  (`~/claude_watch_output/monitor.pid`) when `check_daemon=True` and
  unspecified. The framework resolves the canonical path internally so
  callers don't need to know it.

### `apply_migration(conn, migration)`

Applies a single migration in a `BEGIN IMMEDIATE TRANSACTION`. On any
error, rolls back and raises `MigrationError`. Idempotent: if
`migration.version` is already in `schema_meta`, this is a no-op.

### `rollback_migration(conn, migration)`

The inverse of `apply_migration`. Executes `migration.down_sql` in a
`BEGIN IMMEDIATE TRANSACTION`, then removes the `schema_meta` audit row.
Same atomicity guarantees: on any error, ROLLBACK is issued and the
`schema_meta` row is preserved so the caller knows the migration is
still "applied" and can retry after fixing the down_sql.

- **Empty `down_sql`** → raises `MigrationError("…has empty down_sql;
  rollback unsupported.")`. Apply-only migrations are flagged at
  construction by omitting `down_sql`, and `rollback_migration` enforces
  the contract at call time rather than silently no-op'ing.
- **Migration not in `schema_meta`** → no-op (parallel to
  `apply_migration`'s idempotency on already-applied).
- **Successful rollback** → schema state returned to the pre-migration
  shape; audit row deleted; migration becomes re-appliable.

Exercised by the `migration-rollback-test` CI gate (directive §11.2) and
by the round-trip test pattern in `tests/test_p0_2_attack_surface_migration.py::TestP02RoundTripRollback`.

### `MigrationError` vs `DaemonActiveError`

Different failure modes, different recovery:

- `MigrationError` — the schema work itself failed (DDL error, disk full,
  verification failure). Investigate why. The original exception is
  attached via `__cause__`.
- `DaemonActiveError` — migration was refused *before* any schema work
  was attempted because a live daemon owns the PID file. Stop the daemon
  (`ai-monitor --stop`) and retry.

---

## 4. Adding a new migration (recipe)

For P0.2 and forward, the pattern is:

1. Append a `Migration(...)` to `MIGRATIONS` in
   `src/claude_monitoring/persistence/migrations.py`:
   ```python
   MIGRATIONS = [
       Migration(
           version="0.2.2.001",
           description="Add attack-surface tables (assets, asset_cves, ...)",
           up_sql="""
               CREATE TABLE assets (
                   id TEXT PRIMARY KEY,
                   ...
               );
               CREATE INDEX idx_assets_type ON assets(type);
               -- statements separated by ';'
           """,
       ),
   ]
   ```
2. Verify the version string sorts AFTER all preceding versions in the
   list. `test_migrations_registry_versions_monotonic` will fail at CI
   if you got this wrong.
3. Write tests against the migration: fresh install applies it; pre-
   existing install applies it; idempotent on re-run; rollback works.
4. Run quality gates: `pytest tests/test_migrations.py`, `ruff check`,
   `ruff format --check`, plus the standard suite.
5. C3 criticality (per directive §5) — architect-pass mandatory.

---

## 5. PID coordination — four-state contract

When `check_daemon=True`, the framework handles four PID-file states:

| State | Detection | Action |
|---|---|---|
| No PID file | `pid_file_path.exists() == False` | Pass through; no-op |
| Corrupt contents | `int(read_text())` raises `ValueError` | Remove the file; pass through |
| Dead PID | `os.kill(pid, 0)` raises `ProcessLookupError` | Remove the file; pass through |
| Live PID | `os.kill(pid, 0)` returns | Raise `DaemonActiveError`; **preserve file** |

The live-PID branch preserves the PID file because the daemon owns it;
removing the file would mislead a subsequent `ai-monitor --stop` invocation
that reads the file to find which PID to signal.

`PermissionError` from `os.kill` is treated as "alive" — the process
exists but is owned by another user. Conservatively refusing migration
is the safe choice.

---

## 6. Backfill convention

When `apply_migrations` runs against a pre-versioning install (legacy
tables present but `schema_meta` empty), it inserts one baseline row:

```python
("0.2.0-baseline", time.time(), "Backfilled by P0.0: pre-versioning install state — schema-meta framework introduced in v0.2.2")
```

The `-baseline` suffix is the convention for backfilled rows; real
applied migrations use their own version strings (`0.2.2.001`,
`0.2.2.002`, ...). This distinction is searchable: `SELECT * FROM
schema_meta WHERE version LIKE '%-baseline'` lists only backfills.

Detection heuristic: `schema_meta` has zero rows AND the `api_calls`
table exists. A truly fresh install (no legacy tables) gets no backfill
— the migration runner just records each real migration as it applies.

---

## 7. Testing strategy

Test fixtures live in `tests/fixtures/`:

- `pre_v022_schema.sql` — 20-table v0.2.1 schema, no rows. Use for tests
  that need a clean pre-versioning starting point.
- `pre_v022_schema_with_data.sql` — subset of the schema with
  representative rows (1 session, 3 api_calls, 2 extension_heartbeats).
  Use for tests that need to assert data preservation.

Tests for the framework live in `tests/test_migrations.py`. Tests for
new migrations should follow the same structure — fixture-based, hermetic
(`tmp_path` per test), and assert both schema state and existing-data
preservation.

---

## 8. References

- Implementation directive: `~/Documents/vigil-notes/v022-implementation-directive-v1-LOCKED.md` §7.6
- Feature spec: `~/Documents/vigil-notes/v022-attack-surface-feature-spec-v1-LOCKED.md` §9.1
- Architect-pass ratification: `~/Documents/vigil-notes/architect-pass-P0.0.md`
- Phase A investigation: `~/Documents/vigil-notes/v022-p0.0-phase-a-investigation.md`
