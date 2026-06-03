-- pre_v022_schema.sql
--
-- Captured from a v0.2.1 fresh-install `monitor.db` on 2026-06-03.
-- This is the canonical "pre-v0.2.2" schema — what the database looks like
-- BEFORE the v0.2.2 P0.0 migration framework (schema_meta table + MIGRATIONS
-- registry) runs against it.
--
-- Use this fixture in any test that needs to assert:
--   - apply_migrations() on this state introduces schema_meta cleanly
--   - the backfill row "0.2.0-baseline" is inserted exactly once
--   - the legacy 20-table schema is preserved unchanged after migration
--
-- For tests that also need representative ROWS in the legacy tables,
-- use `pre_v022_schema_with_data.sql` instead.
--
-- Generated via: sqlite3 ~/claude_watch_output/monitor.db ".schema"
-- Sanitized: sqlite_sequence (auto-managed internal table) excluded.

CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        source_layer TEXT NOT NULL,
        data_json TEXT NOT NULL
    , dedup_hash TEXT);
CREATE TABLE sessions (
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
    , title TEXT, agent_type TEXT);
CREATE TABLE processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER NOT NULL,
        name TEXT,
        cmdline TEXT,
        start_time TEXT,
        end_time TEXT,
        cpu_percent REAL DEFAULT 0,
        memory_percent REAL DEFAULT 0,
        status TEXT DEFAULT 'running'
    );
CREATE TABLE connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        process_name TEXT,
        remote_host TEXT,
        remote_port INTEGER,
        status TEXT,
        service TEXT
    );
CREATE TABLE file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        path TEXT NOT NULL,
        operation TEXT NOT NULL,
        session_id TEXT,
        size INTEGER DEFAULT 0
    );
CREATE TABLE browser_sessions (
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
    , source TEXT DEFAULT 'history', event_type TEXT, content_text TEXT, content_hash TEXT);
CREATE TABLE extension_heartbeats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        user_matches INTEGER DEFAULT 0,
        assistant_matches INTEGER DEFAULT 0,
        captures_sent INTEGER DEFAULT 0,
        selector_failure INTEGER DEFAULT 0,
        UNIQUE(hostname)
    );
CREATE TABLE api_calls (
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
    , source TEXT DEFAULT 'proxy');
CREATE TABLE alert_dismissals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL UNIQUE,
        dismissed_at TEXT NOT NULL,
        reason TEXT
    );
CREATE TABLE file_positions (
        file_path TEXT PRIMARY KEY,
        byte_offset INTEGER NOT NULL DEFAULT 0,
        last_read TEXT
    );
CREATE TABLE agent_dependencies (
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
    );
CREATE TABLE environment_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_timestamp TEXT,
        package_name TEXT NOT NULL,
        package_version TEXT,
        manager TEXT NOT NULL,
        source TEXT DEFAULT 'environment',
        UNIQUE(package_name, manager)
    );
CREATE TABLE package_vulnerabilities (
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
    );
CREATE TABLE scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        packages_scanned INTEGER,
        vulns_found INTEGER,
        sources TEXT
    );
CREATE TABLE threat_iocs (
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
    );
CREATE TABLE package_registry_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT,
        manager TEXT,
        fetch_timestamp TEXT,
        metadata TEXT,
        UNIQUE(package_name, manager)
    );
CREATE TABLE intel_source_status (
        name TEXT PRIMARY KEY,
        last_attempt TEXT,
        last_success TEXT,
        last_error TEXT,
        record_count INTEGER DEFAULT 0,
        updated_at TEXT NOT NULL
    );
CREATE TABLE package_watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL,
        manager TEXT NOT NULL,
        watch_reason TEXT NOT NULL,
        added_timestamp TEXT NOT NULL,
        priority TEXT DEFAULT 'normal',
        last_checked TEXT,
        check_interval_hours INTEGER DEFAULT 24,
        UNIQUE(package_name, manager)
    );
CREATE TABLE package_maintainer_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL,
        manager TEXT NOT NULL,
        scan_timestamp TEXT NOT NULL,
        maintainer_data TEXT NOT NULL,
        publisher TEXT,
        version TEXT,
        UNIQUE(package_name, manager, version)
    );
CREATE INDEX idx_events_ts ON events(timestamp);
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_events_type ON events(event_type);
CREATE UNIQUE INDEX idx_events_dedup ON events(dedup_hash);
CREATE INDEX idx_sessions_last ON sessions(last_activity);
CREATE INDEX idx_file_events_ts ON file_events(timestamp);
CREATE INDEX idx_processes_pid ON processes(pid);
CREATE INDEX idx_browser_conv ON browser_sessions(conversation_id);
CREATE INDEX idx_browser_visit ON browser_sessions(visit_time);
CREATE INDEX idx_connections_pid ON connections(pid);
CREATE INDEX idx_connections_ts ON connections(timestamp);
CREATE INDEX idx_api_calls_ts ON api_calls(timestamp);
CREATE INDEX idx_api_calls_session ON api_calls(session_id);
CREATE INDEX idx_api_calls_service ON api_calls(destination_service);
CREATE INDEX idx_deps_ts ON agent_dependencies(timestamp);
CREATE INDEX idx_deps_pkg ON agent_dependencies(package_name);
CREATE INDEX idx_deps_risk ON agent_dependencies(risk_flags);
CREATE TABLE crashes (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, reason TEXT NOT NULL, details TEXT);
