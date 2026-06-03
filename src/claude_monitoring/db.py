# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Database layer for AI Runtime Monitor.

Handles SQLite initialization, schema management, and thread-safe connections.

Encryption at rest is OPTIONAL. If ``sqlcipher3-binary`` is installed
(``pip install ai-runtime-monitor[security]``), the database is encrypted
transparently with a key derived from the host. Otherwise we fall back to
plain sqlite3 + chmod 600 + FileVault. The code path is identical either
way so enabling encryption is a single ``pip install`` away.
"""

import hashlib
import os
import socket
import sqlite3

from claude_monitoring.config import get_db_path, get_output_dir
from claude_monitoring.persistence import migrations as _persistence_migrations

try:
    import sqlcipher3 as _sqlcipher  # type: ignore[import-not-found]

    HAS_SQLCIPHER = True
except ImportError:
    _sqlcipher = None  # type: ignore[assignment]
    HAS_SQLCIPHER = False


def _get_db_encryption_key() -> str:
    """Derive a deterministic encryption key from machine-local identifiers.

    This is NOT a password — it's a key tied to (machine, user) so the DB
    can be decrypted on the host that created it but not trivially opened
    on another machine. For a true user-supplied passphrase, we'd wrap this
    with OS keychain integration, which is future work.
    """
    import uuid

    machine_id = str(uuid.getnode())
    hostname = socket.gethostname()
    username = os.getenv("USER", "unknown")
    material = f"{machine_id}:{hostname}:{username}:ai-runtime-monitor-v1"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _connect(db_path: str, check_same_thread: bool = False):
    """Open a connection, using SQLCipher when available."""
    if HAS_SQLCIPHER:
        conn = _sqlcipher.connect(db_path, check_same_thread=check_same_thread)
        key = _get_db_encryption_key()
        conn.execute(f"PRAGMA key = '{key}'")
        return conn
    return sqlite3.connect(db_path, check_same_thread=check_same_thread)


def init_db(db_path=None):
    """Initialize SQLite database with all required tables.

    Args:
        db_path: Override database path (used in tests). If None, uses config.

    Returns:
        sqlite3.Connection with WAL mode enabled.
    """
    if db_path is None:
        db_path = get_db_path()

    get_output_dir().mkdir(parents=True, exist_ok=True)
    conn = _connect(str(db_path), check_same_thread=False)
    try:
        os.chmod(str(db_path), 0o600)
    except Exception:
        pass
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # v0.2.2 P0.0: versioned-migration framework runs first. In-process
    # startup pattern — check_daemon=False because the daemon is migrating
    # its own schema before opening for business. See docs/spec/MIGRATIONS.md.
    _persistence_migrations.apply_migrations(conn)

    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        source_layer TEXT NOT NULL,
        data_json TEXT NOT NULL
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        start_time TEXT,
        cwd TEXT,
        model TEXT,
        total_cost REAL DEFAULT 0,
        total_input_tokens INTEGER DEFAULT 0,
        total_output_tokens INTEGER DEFAULT 0,
        total_turns INTEGER DEFAULT 0,
        jsonl_path TEXT,
        last_activity TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER NOT NULL,
        name TEXT,
        cmdline TEXT,
        start_time TEXT,
        end_time TEXT,
        cpu_percent REAL DEFAULT 0,
        memory_percent REAL DEFAULT 0,
        status TEXT DEFAULT 'running'
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        process_name TEXT,
        remote_host TEXT,
        remote_port INTEGER,
        status TEXT,
        service TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        path TEXT NOT NULL,
        operation TEXT NOT NULL,
        session_id TEXT,
        size INTEGER DEFAULT 0
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS browser_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        url TEXT,
        title TEXT,
        conversation_id TEXT,
        visit_time TEXT NOT NULL,
        duration_seconds REAL DEFAULT 0,
        foreground_seconds REAL DEFAULT 0,
        tab_id INTEGER,
        window_id INTEGER
    )""")

    # Section 6: extension heartbeat — content scripts post selector match
    # counts every 60s. Used by /api/browser/extension-health to alert when
    # Anthropic/OpenAI/Google ship DOM changes that break our scraping.
    c.execute("""CREATE TABLE IF NOT EXISTS extension_heartbeats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        user_matches INTEGER DEFAULT 0,
        assistant_matches INTEGER DEFAULT 0,
        captures_sent INTEGER DEFAULT 0,
        selector_failure INTEGER DEFAULT 0,
        UNIQUE(hostname)
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS api_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        turn_id TEXT,
        turn_number INTEGER,
        destination_host TEXT,
        destination_service TEXT,
        endpoint_path TEXT,
        http_method TEXT,
        http_status INTEGER,
        model TEXT,
        stream TEXT,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        cache_read_tokens INTEGER DEFAULT 0,
        cache_write_tokens INTEGER DEFAULT 0,
        estimated_cost_usd REAL DEFAULT 0,
        request_size_bytes INTEGER DEFAULT 0,
        response_size_bytes INTEGER DEFAULT 0,
        latency_ms INTEGER DEFAULT 0,
        num_messages INTEGER DEFAULT 0,
        system_prompt_chars INTEGER DEFAULT 0,
        last_user_msg_preview TEXT,
        assistant_msg_preview TEXT,
        tool_calls TEXT,
        tool_call_count INTEGER DEFAULT 0,
        bash_commands TEXT,
        files_read TEXT,
        files_written TEXT,
        urls_fetched TEXT,
        sensitive_patterns TEXT,
        sensitive_pattern_count INTEGER DEFAULT 0,
        stop_reason TEXT,
        request_id TEXT
    )""")

    # Add title column to sessions if missing (migration)
    try:
        c.execute("ALTER TABLE sessions ADD COLUMN title TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add agent_type column to sessions if missing (migration)
    try:
        c.execute("ALTER TABLE sessions ADD COLUMN agent_type TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add source column to browser_sessions if missing (migration)
    try:
        c.execute("ALTER TABLE browser_sessions ADD COLUMN source TEXT DEFAULT 'history'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add content capture columns for browser extension (migration)
    for col in ["event_type TEXT", "content_text TEXT", "content_hash TEXT"]:
        try:
            c.execute(f"ALTER TABLE browser_sessions ADD COLUMN {col}")  # nosec B608
        except sqlite3.OperationalError:
            pass

    # Add source column to api_calls — distinguishes browser_proxy metadata
    # from full API call captures (Section 5)
    try:
        c.execute("ALTER TABLE api_calls ADD COLUMN source TEXT DEFAULT 'proxy'")
    except sqlite3.OperationalError:
        pass

    c.execute("""CREATE TABLE IF NOT EXISTS alert_dismissals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL UNIQUE,
        dismissed_at TEXT NOT NULL,
        reason TEXT
    )""")

    # Persistent file positions — survives monitor restarts
    c.execute("""CREATE TABLE IF NOT EXISTS file_positions (
        file_path TEXT PRIMARY KEY,
        byte_offset INTEGER NOT NULL DEFAULT 0,
        last_read TEXT
    )""")

    # Supply chain dependency tracking
    c.execute("""CREATE TABLE IF NOT EXISTS agent_dependencies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        agent_type TEXT,
        action TEXT NOT NULL,
        package_manager TEXT NOT NULL,
        package_name TEXT NOT NULL,
        package_version TEXT,
        pinned BOOLEAN DEFAULT 0,
        registry_url TEXT,
        lockfile_path TEXT,
        command TEXT,
        risk_flags TEXT DEFAULT '[]',
        risk_score INTEGER DEFAULT 0,
        category TEXT DEFAULT 'package',
        project TEXT,
        dedup_hash TEXT UNIQUE
    )""")

    # Migrations for supply chain columns
    for col, default in [("risk_score", "0"), ("category", "'package'"), ("project", "NULL")]:
        try:
            c.execute(f"ALTER TABLE agent_dependencies ADD COLUMN {col} TEXT DEFAULT {default}")  # nosec B608
        except sqlite3.OperationalError:
            pass

    # Environment package inventory
    c.execute("""CREATE TABLE IF NOT EXISTS environment_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_timestamp TEXT,
        package_name TEXT NOT NULL,
        package_version TEXT,
        manager TEXT NOT NULL,
        source TEXT DEFAULT 'environment',
        UNIQUE(package_name, manager)
    )""")

    # Vulnerability scanning
    c.execute("""CREATE TABLE IF NOT EXISTS package_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_timestamp TEXT NOT NULL,
        package_name TEXT NOT NULL,
        package_version TEXT,
        ecosystem TEXT,
        vuln_id TEXT NOT NULL,
        aliases TEXT DEFAULT '[]',
        severity TEXT,
        cvss_score REAL,
        fix_version TEXT,
        description TEXT,
        source TEXT,
        published TEXT,
        modified TEXT,
        UNIQUE(package_name, package_version, vuln_id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        packages_scanned INTEGER,
        vulns_found INTEGER,
        sources TEXT
    )""")

    # Threat intelligence IOCs
    c.execute("""CREATE TABLE IF NOT EXISTS threat_iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL,
        ioc_value TEXT NOT NULL,
        threat_type TEXT,
        malware_family TEXT,
        confidence INTEGER DEFAULT 0,
        source TEXT,
        first_seen TEXT,
        fetch_timestamp TEXT NOT NULL,
        UNIQUE(ioc_type, ioc_value, source)
    )""")

    # Registry metadata cache
    c.execute("""CREATE TABLE IF NOT EXISTS package_registry_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT,
        manager TEXT,
        fetch_timestamp TEXT,
        metadata TEXT,
        UNIQUE(package_name, manager)
    )""")

    # Feature A: Per-source health tracking. One row per named intel
    # source (osv, pip-audit, threatfox, urlhaus, registry). The status
    # endpoint computes a 4-state color from these columns:
    #   - last_success <= 24h → green
    #   - last_success > 24h  → yellow
    #   - last_error set      → red
    #   - both null           → gray (never fetched)
    c.execute("""CREATE TABLE IF NOT EXISTS intel_source_status (
        name TEXT PRIMARY KEY,
        last_attempt TEXT,
        last_success TEXT,
        last_error TEXT,
        record_count INTEGER DEFAULT 0,
        updated_at TEXT NOT NULL
    )""")
    # Backfill from existing threat_iocs.fetch_timestamp so the first
    # load after upgrade doesn't show green sources as gray.
    try:
        for src in ("threatfox", "urlhaus"):
            row = c.execute(
                "SELECT MAX(fetch_timestamp), COUNT(*) FROM threat_iocs WHERE source=?",
                (src,),
            ).fetchone()
            if row and row[0]:
                c.execute(
                    """INSERT OR IGNORE INTO intel_source_status
                       (name, last_attempt, last_success, last_error, record_count, updated_at)
                       VALUES (?, ?, ?, NULL, ?, ?)""",
                    (src, row[0], row[0], row[1] or 0, row[0]),
                )
    except Exception:
        pass

    # Package watchlist with prioritized scanning
    c.execute("""CREATE TABLE IF NOT EXISTS package_watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL,
        manager TEXT NOT NULL,
        watch_reason TEXT NOT NULL,
        added_timestamp TEXT NOT NULL,
        priority TEXT DEFAULT 'normal',
        last_checked TEXT,
        check_interval_hours INTEGER DEFAULT 24,
        UNIQUE(package_name, manager)
    )""")

    # Package maintainer history tracking
    c.execute("""CREATE TABLE IF NOT EXISTS package_maintainer_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL,
        manager TEXT NOT NULL,
        scan_timestamp TEXT NOT NULL,
        maintainer_data TEXT NOT NULL,
        publisher TEXT,
        version TEXT,
        UNIQUE(package_name, manager, version)
    )""")

    # Add dedup_hash column to events if missing (migration for dedup fix)
    try:
        c.execute("ALTER TABLE events ADD COLUMN dedup_hash TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(dedup_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_last ON sessions(last_activity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_browser_conv ON browser_sessions(conversation_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_browser_visit ON browser_sessions(visit_time)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_connections_pid ON connections(pid)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_calls_ts ON api_calls(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_calls_session ON api_calls(session_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_calls_service ON api_calls(destination_service)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_deps_ts ON agent_dependencies(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_deps_pkg ON agent_dependencies(package_name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_deps_risk ON agent_dependencies(risk_flags)")

    # Backfill content_hash for browser_sessions + remove extension duplicates
    try:
        import hashlib as _hl

        null_rows = c.execute(
            "SELECT id, content_text FROM browser_sessions WHERE content_hash IS NULL AND content_text IS NOT NULL"
        ).fetchall()
        for row in null_rows:
            h = _hl.sha256(row[1][:200].encode()).hexdigest()[:16]
            c.execute("UPDATE browser_sessions SET content_hash=? WHERE id=?", (h, row[0]))
        if null_rows:
            c.execute("""DELETE FROM browser_sessions WHERE source='extension' AND id NOT IN (
                SELECT MIN(id) FROM browser_sessions WHERE source='extension' AND content_text IS NOT NULL
                GROUP BY conversation_id, event_type, content_hash)""")
    except Exception:
        pass

    conn.commit()
    return conn


def get_thread_db(db_path=None):
    """Get a thread-local database connection with Row factory.

    Args:
        db_path: Override database path (used in tests). If None, uses config.

    Returns:
        sqlite3.Connection with WAL mode and Row factory enabled.
    """
    if db_path is None:
        db_path = get_db_path()

    conn = _connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def insert_api_call(db_path, record):
    """Insert an API call record into the api_calls table.

    Used by watch.py for dual-write (CSV + SQLite).
    Non-fatal: returns False on any error.

    Args:
        db_path: Path to the SQLite database.
        record: Dict with API call data (keys match CSV_COLUMNS).

    Returns:
        True if insert succeeded, False otherwise.
    """
    try:
        if not db_path or not db_path.exists():
            return False
        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.execute(
            """INSERT INTO api_calls (
                timestamp, session_id, turn_id, turn_number,
                destination_host, destination_service, endpoint_path, http_method,
                http_status, model, stream, input_tokens, output_tokens,
                cache_read_tokens, cache_write_tokens, estimated_cost_usd,
                request_size_bytes, response_size_bytes, latency_ms, num_messages,
                system_prompt_chars, last_user_msg_preview, assistant_msg_preview,
                tool_calls, tool_call_count, bash_commands, files_read, files_written,
                urls_fetched, sensitive_patterns, sensitive_pattern_count,
                stop_reason, request_id, source
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record.get("timestamp", ""),
                record.get("session_id", ""),
                record.get("turn_id", ""),
                record.get("turn_number", 0),
                record.get("destination_host", ""),
                record.get("destination_service", ""),
                record.get("endpoint_path", ""),
                record.get("http_method", ""),
                record.get("http_status", 0),
                record.get("model", ""),
                record.get("stream", ""),
                record.get("input_tokens", 0),
                record.get("output_tokens", 0),
                record.get("cache_read_tokens", 0),
                record.get("cache_write_tokens", 0),
                record.get("estimated_cost_usd", 0),
                record.get("request_size_bytes", 0),
                record.get("response_size_bytes", 0),
                record.get("latency_ms", 0),
                record.get("num_messages", 0),
                record.get("system_prompt_chars", 0),
                record.get("last_user_msg_preview", ""),
                record.get("assistant_msg_preview", ""),
                record.get("tool_calls", "[]"),
                record.get("tool_call_count", 0),
                record.get("bash_commands", "[]"),
                record.get("files_read", "[]"),
                record.get("files_written", "[]"),
                record.get("urls_fetched", "[]"),
                record.get("sensitive_patterns", ""),
                record.get("sensitive_pattern_count", 0),
                record.get("stop_reason", ""),
                record.get("request_id", ""),
                record.get("source", "proxy"),
            ),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False
