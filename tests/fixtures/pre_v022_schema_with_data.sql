-- pre_v022_schema_with_data.sql
--
-- Same schema as `pre_v022_schema.sql`, plus a handful of representative
-- rows so tests can assert that apply_migrations() preserves existing data
-- in legacy tables when adding the v0.2.2 schema_meta framework.
--
-- Row content is synthetic — deterministic timestamps + placeholder values,
-- never real captured data. Test assertions should reference the explicit
-- IDs / values inserted here, not derived expectations.
--
-- Use this fixture in any test that needs to assert:
--   - existing rows survive the v0.2.2 P0.0 migration (no data loss)
--   - row counts in legacy tables are unchanged after apply_migrations()
--   - the backfill row is added even when api_calls already has rows

-- ============================================================
-- SCHEMA (same as pre_v022_schema.sql)
-- ============================================================

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
CREATE TABLE extension_heartbeats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        user_matches INTEGER DEFAULT 0,
        assistant_matches INTEGER DEFAULT 0,
        extra TEXT
    );

CREATE INDEX idx_api_calls_ts ON api_calls(timestamp);
CREATE INDEX idx_api_calls_session ON api_calls(session_id);
CREATE INDEX idx_api_calls_service ON api_calls(destination_service);
CREATE INDEX idx_sessions_last ON sessions(last_activity);
CREATE INDEX idx_events_ts ON events(timestamp);
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_events_type ON events(event_type);
CREATE UNIQUE INDEX idx_events_dedup ON events(dedup_hash);

-- ============================================================
-- REPRESENTATIVE DATA
-- ============================================================
-- 1 session, 3 api_calls (mixed Anthropic + envelope-only), 2 extension_heartbeats.
-- All timestamps deterministic (2026-06-01 fixed window) for repeatable tests.

INSERT INTO sessions (session_id, start_time, cwd, model, total_cost, total_input_tokens, total_output_tokens, total_turns, jsonl_path, last_activity, title, agent_type) VALUES
    ('fixture-session-001', '2026-06-01T12:00:00Z', '/tmp/fixture-cwd', 'claude-sonnet-4-5', 0.0234, 1234, 567, 3, '/tmp/fixture.jsonl', '2026-06-01T12:05:30Z', 'fixture conversation', 'claude_code');

INSERT INTO api_calls (timestamp, session_id, destination_host, destination_service, endpoint_path, http_method, http_status, model, input_tokens, output_tokens, estimated_cost_usd, source) VALUES
    ('2026-06-01T12:00:15Z', 'fixture-session-001', 'api.anthropic.com', 'anthropic_api', '/v1/messages', 'POST', 200, 'claude-sonnet-4-5', 412, 189, 0.0078, 'proxy'),
    ('2026-06-01T12:01:42Z', 'fixture-session-001', 'api.anthropic.com', 'anthropic_api', '/v1/messages', 'POST', 200, 'claude-sonnet-4-5', 561, 203, 0.0095, 'proxy'),
    ('2026-06-01T12:03:09Z', 'fixture-session-001', 'api.anthropic.com', 'anthropic_api', '/v1/environments/env_fixture/work/poll?ack=true', 'GET', 200, NULL, 0, 0, 0.0, 'proxy');

INSERT INTO extension_heartbeats (hostname, timestamp, user_matches, assistant_matches, extra) VALUES
    ('claude.ai', '2026-06-01T12:02:00Z', 3, 5, '{"selector_version":"v3"}'),
    ('chatgpt.com', '2026-06-01T12:04:30Z', 0, 2, '{"selector_version":"v3"}');
