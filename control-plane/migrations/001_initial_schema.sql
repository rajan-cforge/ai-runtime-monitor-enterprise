-- Registered endpoints (auto-created on first ingest POST)
CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    endpoint_id UUID DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    ip_address TEXT,
    os TEXT,
    monitor_version TEXT,
    api_key_hash TEXT NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_heartbeat TIMESTAMPTZ,
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_id ON endpoints(endpoint_id);

-- Fleet sessions (mirrors client sessions + endpoint_id)
CREATE TABLE IF NOT EXISTS fleet_sessions (
    id SERIAL PRIMARY KEY,
    endpoint_id UUID NOT NULL REFERENCES endpoints(endpoint_id),
    client_session_id TEXT NOT NULL,
    start_time TIMESTAMPTZ,
    cwd TEXT,
    model TEXT,
    agent_type TEXT,
    title TEXT,
    total_cost REAL DEFAULT 0,
    total_input_tokens BIGINT DEFAULT 0,
    total_output_tokens BIGINT DEFAULT 0,
    total_turns INTEGER DEFAULT 0,
    last_activity TIMESTAMPTZ,
    UNIQUE(endpoint_id, client_session_id)
);

-- Fleet events (mirrors client events + endpoint_id)
CREATE TABLE IF NOT EXISTS fleet_events (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    client_event_id INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    session_id TEXT,
    event_type TEXT NOT NULL,
    source_layer TEXT NOT NULL,
    data_json JSONB NOT NULL,
    UNIQUE(endpoint_id, client_event_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_events_ts ON fleet_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_fleet_events_type ON fleet_events(event_type);
CREATE INDEX IF NOT EXISTS idx_fleet_events_endpoint ON fleet_events(endpoint_id);

-- Fleet alerts (denormalized sensitive_data events for fast queries)
CREATE TABLE IF NOT EXISTS fleet_alerts (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    client_event_id INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    session_id TEXT,
    severity TEXT NOT NULL,
    patterns TEXT[],
    context TEXT,
    snippet TEXT,
    validated BOOLEAN DEFAULT false,
    confidence TEXT,
    dismissed BOOLEAN DEFAULT false,
    dismissed_at TIMESTAMPTZ,
    UNIQUE(endpoint_id, client_event_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_alerts_severity ON fleet_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_fleet_alerts_endpoint ON fleet_alerts(endpoint_id);

-- Fleet API calls (mirrors client api_calls + endpoint_id)
CREATE TABLE IF NOT EXISTS fleet_api_calls (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    client_call_id INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    session_id TEXT,
    model TEXT,
    destination_service TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0,
    cache_write_tokens INTEGER DEFAULT 0,
    estimated_cost_usd REAL DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    UNIQUE(endpoint_id, client_call_id)
);

-- Sync watermarks (tracks what each endpoint last sent)
CREATE TABLE IF NOT EXISTS sync_watermarks (
    endpoint_id UUID NOT NULL,
    table_name TEXT NOT NULL,
    last_client_id BIGINT DEFAULT 0,
    last_sync TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY(endpoint_id, table_name)
);
