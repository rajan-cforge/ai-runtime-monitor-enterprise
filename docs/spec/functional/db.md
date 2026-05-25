# Functional Spec — db.py

**Module:** `src/claude_monitoring/db.py`
**Status:** v0.2 launch candidate

## 1. Purpose

`db.py` owns the SQLite database lifecycle: schema creation, connection management, and the small set of helper functions that the rest of the codebase uses to write structured data. Most queries are issued from the calling module (`monitor.py`, `sync.py`) directly via `sqlite3`; this module exists to centralize the schema and a few hot-path helpers.

The database is the single persistence layer for the entire daemon. There is no separate cache, no message queue, no in-memory fan-out. Every event captured by any scanner ends up in one of seven tables.

## 2. Public contract

### 2.1 Initialization

```python
def init_db(db_path: Path | None = None) -> sqlite3.Connection:
    """Create the database file and apply the full schema.
    
    Idempotent: safe to call on an existing database. CREATE TABLE IF NOT EXISTS
    is used throughout. Indexes are also created idempotently.
    
    Returns a connection with row_factory=sqlite3.Row and WAL mode enabled.
    """
```

### 2.2 Connection helpers

```python
def get_thread_db(db_path: Path | None = None) -> sqlite3.Connection:
    """Return a thread-local connection. Creates one if the current thread
    doesn't have one yet. Used by scanner threads to avoid sharing connections.
    """
```

### 2.3 Insert helpers (hot path)

```python
def insert_api_call(db_path: Path, record: dict) -> bool:
    """Insert an api_calls row. Returns True on success, False on any error
    (non-fatal — the caller's dual-write to CSV is the system of record).

    Takes a database path (not a live connection) and opens its own short-lived
    connection. Called by watch.py::ClaudeWatchAddon for every captured
    response. ``record`` keys match ``CSV_COLUMNS``.
    """
```

## 3. Inputs

- **Configuration:** database path from `config.get_db_path()`
- **Optional SQLCipher key:** when `HAS_SQLCIPHER` is True, derived from config or KMS (v0.3+)

## 4. Outputs

- **File:** `~/claude_watch_output/monitor.db` (and `-wal`, `-shm` companion files)
- **Database mutations:** table creation, index creation, insert/update via the helpers

## 5. Side effects

- **Disk write:** the database file
- **File permission:** chmod 600 enforced on the database file (also by `security.enforce_permissions`)
- **WAL files:** SQLite writes `-wal` and `-shm` companion files; these are normal SQLite artifacts

## 6. SQLCipher integration

Module-level constant:

```python
HAS_SQLCIPHER = False  # set to True if sqlcipher3 is importable
try:
    import sqlcipher3
    HAS_SQLCIPHER = True
except ImportError:
    pass
```

When `HAS_SQLCIPHER` is True, the connection is opened via `sqlcipher3.connect()` with the encryption key derived from a per-install secret stored alongside the dashboard token (chmod 600). When False, standard `sqlite3.connect()` is used.

The fallback is intentional: SQLCipher is an optional dependency (`pip install 'ai-runtime-monitor[security]'`). The free tier ships without it; the Pro tier installs it. Users without it still get file-level protection via chmod 600 and macOS FileVault.

## 7. Schema overview

Seven primary tables, plus a `sync_state` table for control plane integration:

| Table | Purpose | Hot path? |
|-------|---------|-----------|
| `sessions` | One row per AI agent session (CLI or browser) | Read-heavy |
| `events` | All captured events, structured per-type via `data_json` | Insert-heavy |
| `api_calls` | Proxy-captured HTTP requests/responses | Insert-heavy (when proxy active) |
| `processes` | AI process lifecycle | Insert + UPDATE |
| `connections` | Network connections | Insert-heavy |
| `file_events` | File modifications by AI agents | Insert-heavy |
| `browser_sessions` | Chrome history-derived AI usage | Insert + read |
| `sync_state` | Watermarks for control plane delivery | Read + update |
| `package_vulnerabilities` | Supply-chain scanner output | Periodic write |
| `agent_dependencies` | Installed packages per agent | Periodic write |
| `intel_source_status` | Health of threat intel feeds | Periodic write |
| `scan_history` | Supply-chain scan timeline | Periodic write |
| `extension_heartbeats` | Browser extension health | Periodic write |

Detailed column-level schema is in [ARCHITECTURE.md](../../ARCHITECTURE.md#8-database-schema).

## 8. Indexing strategy

Every WHERE clause in any query path has a corresponding index:

- Timestamp-based queries (the most common pattern in the dashboard) hit `idx_*_ts`
- Session-scoped queries hit `idx_*_session`
- Type-filtered event queries hit `idx_events_type`
- Watermark-based incremental reads hit `rowid` (SQLite's implicit primary key)

Indexes are created in `init_db` and not adjusted at runtime. The total index overhead is acceptable for a few million rows (typical maximum); past that, partitioning by time (monthly tables) would be the next move.

## 9. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| Database file not writable | `init_db` raises | Fix directory permissions |
| Schema migration needed (v0.3+) | New columns missing on existing DB | Migration runner adds them |
| WAL file growth (long-running) | Disk usage climbs | SQLite checkpoints automatically; manual `PRAGMA wal_checkpoint` available |
| Concurrent writer collision | Insert retries (SQLite handles this internally with `busy_timeout`) | Auto-recovers |
| Corrupted database | Daemon refuses to start; status reports the error | Recovery: restore from backup or wipe |

## 10. Hot-path notes

Inserts run on every scanner cycle. Patterns to preserve:

- `INSERT OR IGNORE` for tables with natural unique constraints (deduplication free)
- Parameterized queries always (no string interpolation; this is a security requirement too)
- No SELECT inside scanner threads except for watermark reads
- WAL mode allows concurrent reads while a write is in progress

Read-heavy patterns (dashboard queries):

- Always include `LIMIT` to bound query cost
- Always include `ORDER BY` on an indexed column
- Pagination via `LIMIT/OFFSET` (acceptable for tables < 1M rows; v1.0 may switch to keyset pagination)

## 11. Extension points

- **Add a new table:** add CREATE TABLE to `init_db`, add indexes, document in ARCHITECTURE.md schema section
- **Add a new column to an existing table:** add to CREATE TABLE for fresh installs; add migration script for upgrades
- **Add a new insert helper:** follow the `insert_api_call` pattern (path + dict in, bool out, non-fatal: log and return False on error rather than raising)

## 12. Migration story (v0.3+)

v0.2 has no schema migration mechanism — fresh installs only. v0.3 adds:

- `schema_version` table tracking the current version
- `migrations/` directory with numbered migration scripts
- `init_db` runs pending migrations on startup
- Each migration is idempotent and reversible

Until v0.3 ships, upgrades from v0.2 to a future version may require running `ai-monitor --purge && ai-monitor --setup`. This is documented in the v0.2 release notes.

## 13. Testing

- **Unit tests:** `tests/test_db.py` covers schema creation idempotency, insert helpers, error paths
- **Concurrent access:** explicit tests with multiple threads inserting and reading
- **Large data:** stress test with 100K rows to verify index performance

## 14. Dependencies

- Standard library: `sqlite3`, `pathlib`, `threading` (for thread-local connections)
- Project modules: `config`
- Third-party (optional): `sqlcipher3` (when `[security]` extra is installed)

## 15. Future direction

- **Schema migrations (v0.3)** — see Section 12
- **Partitioning by month (v1.0)** — large fleet deployments may need this
- **Replication to control plane (v1.0)** — pluggable replication mechanism
- **Encrypted at rest by default (v1.0 Enterprise)** — SQLCipher in the standard install, not just `[security]` extra
- **Async access via aiosqlite (v1.0)** — when the daemon refactors to asyncio
