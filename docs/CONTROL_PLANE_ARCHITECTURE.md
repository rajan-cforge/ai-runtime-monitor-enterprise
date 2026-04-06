# Control Plane Architecture — AI Runtime Monitor Fleet Aggregation

## Overview

The control plane aggregates monitoring data from multiple endpoints (developer laptops, CI machines, Docker containers) into a single fleet dashboard. Each endpoint runs `ai-monitor` locally with full standalone functionality. The CP adds fleet-wide visibility.

## Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Docker)                        │
│                    Central aggregation server                    │
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │  Ingest API :9090│───▶│  Fleet Dashboard  │                   │
│  │  (FastAPI)       │    │  :9090/dashboard   │                   │
│  └────────┬─────────┘    └──────────────────┘                   │
│           │                                                      │
│  ┌────────▼─────────┐    ┌──────────────────┐                   │
│  │  Fleet DB        │    │ Endpoint Registry │                   │
│  │  (Postgres)      │    │ Auto-register on  │                   │
│  │                  │    │ first POST        │                   │
│  └──────────────────┘    └──────────────────┘                   │
│                                                                  │
│  ┌──────────────────┐                                           │
│  │  Future: ACMS    │                                           │
│  │  Memory Module   │                                           │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
        ▲                                    ▲
        │ POST /api/v1/ingest                │ POST /api/v1/ingest
        │ (every 30s)                        │ (every 30s)
        │                                    │
┌───────┴──────────────────┐   ┌─────────────┴────────────────┐
│ CLIENT 1: MacBook        │   │ CLIENT 2: Docker Container   │
│ 192.168.x.x (real)       │   │ 172.17.0.x (simulated)       │
│                          │   │                              │
│ ┌──────────┬───────────┐ │   │ ┌──────────┬───────────┐    │
│ │ai-monitor│ monitor.db│ │   │ │ai-monitor│ monitor.db│    │
│ └──────────┴───────────┘ │   │ └──────────┴───────────┘    │
│ ┌──────────┬───────────┐ │   │ ┌──────────┬───────────┐    │
│ │Claude    │ OpenClaw   │ │   │ │Claude    │ Cursor    │    │
│ │Code      │            │ │   │ │Code      │           │    │
│ └──────────┴───────────┘ │   │ └──────────┴───────────┘    │
│ ┌──────────────────────┐ │   │                              │
│ │    ClawGuard skill   │ │   │                              │
│ └──────────────────────┘ │   │                              │
└──────────────────────────┘   └──────────────────────────────┘
```

## Data Flow: Endpoint to Control Plane

```
STEP 1: Client captures (existing, no changes)
─────────────────────────────────────────────
  All 5 monitoring layers run locally:
  - Layer 1a: JSONL session tailing (Claude Code, OpenClaw)
  - Layer 1b: Network connections (psutil)
  - Layer 2:  HTTPS proxy (mitmproxy, optional)
  - Layer 3:  Process scanning (psutil)
  - Layer 4:  File activity (watchdog)
  - Layer 5:  Chrome history
  
  All data → local monitor.db (SQLite)
  Local dashboard still works at :9081

STEP 2: Sync agent (NEW — runs on client)
─────────────────────────────────────────────
  Background thread in ai-monitor process.
  Runs every 30 seconds.
  
  Reads from local monitor.db:
    SELECT * FROM events WHERE id > {last_synced_event_id}
    SELECT * FROM sessions WHERE rowid > {last_synced_session_rowid}
    SELECT * FROM api_calls WHERE id > {last_synced_api_call_id}
    SELECT * FROM browser_sessions WHERE id > {last_synced_browser_id}
  
  Tracks sync state in local table:
    sync_state (table_name TEXT PK, last_synced_id INTEGER, last_sync_time TEXT)

STEP 3: POST to control plane
─────────────────────────────────────────────
  POST https://{cp_url}/api/v1/ingest
  Headers:
    X-API-Key: {api_key}
    Content-Type: application/json
  
  Body:
  {
    "endpoint": {
      "hostname": "Mac-3155",
      "os": "Darwin 25.3.0 arm64",
      "ip": "192.168.1.50",
      "monitor_version": "0.2.0"
    },
    "sessions": [
      {
        "client_session_id": "ed3e62f3",
        "start_time": "2026-04-01T06:25:00Z",
        "cwd": "~/Documents/talosAI",
        "model": "opus-4-6",
        "agent_type": "claude_code",
        "title": "Continue from where we left off...",
        "total_input_tokens": 5300000,
        "total_output_tokens": 8500000,
        "total_turns": 5171,
        "total_cost": 12.50,
        "last_activity": "2026-04-02T08:26:00Z"
      }
    ],
    "events": [
      {
        "client_event_id": 15230,
        "timestamp": "2026-04-02T08:25:53Z",
        "session_id": "ed3e62f3",
        "event_type": "tool_use",
        "source_layer": "jsonl",
        "data_json": {"name": "Bash", "command": "pytest tests/"}
      }
    ],
    "api_calls": [
      {
        "client_call_id": 36,
        "timestamp": "2026-04-02T08:25:50Z",
        "model": "claude-sonnet-4-6",
        "destination_service": "anthropic_api",
        "input_tokens": 3,
        "output_tokens": 93,
        "estimated_cost_usd": 0.05
      }
    ],
    "alerts": [
      {
        "client_event_id": 15225,
        "timestamp": "2026-04-02T08:20:00Z",
        "session_id": "50a4dd45",
        "severity": "medium",
        "patterns": ["phone_number"],
        "context": "user_prompt",
        "snippet": "sender_id: 7465847486",
        "validated": true,
        "confidence": "low"
      }
    ],
    "watermarks": {
      "events": 15230,
      "sessions": 84,
      "api_calls": 36,
      "browser_sessions": 12
    }
  }
  
  Response (200):
  {
    "stored": {"sessions": 1, "events": 5, "api_calls": 1, "alerts": 1},
    "endpoint_id": "a1b2c3d4-...",
    "next_sync_after": 30
  }
  
  On network failure: retry with exponential backoff (1s, 2s, 4s, 8s, max 60s)
  No data loss — local DB is source of truth, sync resumes from watermarks.

STEP 4: CP ingest processing
─────────────────────────────────────────────
  1. Validate X-API-Key against endpoints table (bcrypt hash)
  2. Auto-register endpoint on first POST:
     INSERT INTO endpoints (hostname, ip_address, os, api_key_hash)
     ON first seen — returns new endpoint_id
  3. Update last_heartbeat on every POST
  4. For each session: UPSERT into fleet_sessions
     (ON CONFLICT(endpoint_id, client_session_id) DO UPDATE)
  5. For each event: INSERT into fleet_events
     (ON CONFLICT(endpoint_id, client_event_id) DO NOTHING — dedup)
  6. For sensitive_data events: denormalize into fleet_alerts
  7. For api_calls: INSERT into fleet_api_calls
  8. Update sync_watermarks table
  9. Rate limit: 60 requests/minute per endpoint

STEP 5: Fleet database (Postgres)
─────────────────────────────────────────────
  Every table has endpoint_id as a foreign key.
  This is the key difference from standalone SQLite:
  
  fleet_sessions:  endpoint_id + client_session_id (unique together)
  fleet_events:    endpoint_id + client_event_id (unique together, dedup)
  fleet_alerts:    endpoint_id + client_event_id (unique together)
  fleet_api_calls: endpoint_id + client_call_id (unique together)
  
  Deduplication: UNIQUE constraints ensure that replayed/retried
  POSTs don't create duplicate records.

STEP 6: Fleet dashboard
─────────────────────────────────────────────
  Served at http://{cp_host}:9090/dashboard
  
  Views:
  ┌─────────────────────────────────────────────────────────────┐
  │ FLEET OVERVIEW                                              │
  │                                                             │
  │ Endpoints: 2  Sessions: 86  Tokens: 171M  Alerts: 47,424   │
  │ Total Cost: $42.50   Fleet Risk: MEDIUM                     │
  ├─────────────────────────────────────────────────────────────┤
  │ ENDPOINT LIST                                               │
  │                                                             │
  │ ● Mac-3155 (192.168.1.50)    macOS    37 agents  Last: 2s  │
  │ ● Docker-Client (172.17.0.3) Linux     5 agents  Last: 28s │
  ├─────────────────────────────────────────────────────────────┤
  │ FLEET SESSIONS (all endpoints, all agents)                  │
  │                                                             │
  │ [Mac-3155] [Claude Code] "Continue from where..."  5.3M tok│
  │ [Mac-3155] [OpenClaw]    "Security audit..."       58 tok   │
  │ [Docker]   [Cursor]      "Fix the auth bug..."     1.2M tok│
  │ [Docker]   [Claude Code] "Write unit tests..."     800K tok │
  ├─────────────────────────────────────────────────────────────┤
  │ FLEET ALERTS (cross-endpoint triage)                        │
  │                                                             │
  │ 🔴 HIGH  [Mac-3155] JWT token in session logs     validated │
  │ 🟡 MED   [Mac-3155] Phone number (Telegram ID)   false pos │
  │ 🟡 MED   [Docker]   AWS key pattern in output    validated  │
  ├─────────────────────────────────────────────────────────────┤
  │ FLEET ANALYTICS                                             │
  │                                                             │
  │ Token usage by endpoint (stacked bar chart)                 │
  │ Cost by endpoint (line chart)                               │
  │ Model distribution across fleet (pie chart)                 │
  │ Tool usage heatmap (endpoint × tool matrix)                 │
  ├─────────────────────────────────────────────────────────────┤
  │ POLICY (future)                                             │
  │                                                             │
  │ Block tool: exec on endpoints without sandbox               │
  │ Require: sandbox mode on all OpenClaw deployments           │
  │ Alert: if any endpoint exposes SSH keys to agent            │
  └─────────────────────────────────────────────────────────────┘
```

## Control Plane Database Schema (Postgres)

```sql
-- Registered endpoints (auto-created on first ingest POST)
CREATE TABLE endpoints (
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
CREATE UNIQUE INDEX idx_endpoints_id ON endpoints(endpoint_id);

-- Fleet sessions (mirrors client sessions + endpoint_id)
CREATE TABLE fleet_sessions (
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
CREATE TABLE fleet_events (
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
CREATE INDEX idx_fleet_events_ts ON fleet_events(timestamp);
CREATE INDEX idx_fleet_events_type ON fleet_events(event_type);
CREATE INDEX idx_fleet_events_endpoint ON fleet_events(endpoint_id);

-- Fleet alerts (denormalized sensitive_data events for fast queries)
CREATE TABLE fleet_alerts (
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
CREATE INDEX idx_fleet_alerts_severity ON fleet_alerts(severity);
CREATE INDEX idx_fleet_alerts_endpoint ON fleet_alerts(endpoint_id);

-- Fleet API calls (mirrors client api_calls + endpoint_id)
CREATE TABLE fleet_api_calls (
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
CREATE TABLE sync_watermarks (
    endpoint_id UUID NOT NULL,
    table_name TEXT NOT NULL,
    last_client_id BIGINT DEFAULT 0,
    last_sync TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY(endpoint_id, table_name)
);
```

## Client Sync Agent Design (sync.py)

```python
# New module: src/claude_monitoring/sync.py

class SyncAgent:
    """Background thread that syncs local monitor.db to the control plane."""
    
    def __init__(self, cp_url, api_key, interval=30):
        self.cp_url = cp_url.rstrip("/")
        self.api_key = api_key
        self.interval = interval
        self.endpoint_id = None  # assigned by CP on first sync
        self._stop = threading.Event()
    
    def start(self):
        """Start sync loop in daemon thread."""
        thread = threading.Thread(target=self._sync_loop, daemon=True)
        thread.start()
    
    def _sync_loop(self):
        """Main loop: read new data, POST to CP, update watermarks."""
        while not self._stop.is_set():
            try:
                self._do_sync()
            except Exception as e:
                logger.warning(f"Sync failed: {e}")
                self._backoff()
            self._stop.wait(self.interval)
    
    def _do_sync(self):
        """Single sync cycle."""
        watermarks = self._read_watermarks()
        
        # Read new data since last sync
        new_sessions = self._read_new("sessions", watermarks.get("sessions", 0))
        new_events = self._read_new("events", watermarks.get("events", 0))
        new_api_calls = self._read_new("api_calls", watermarks.get("api_calls", 0))
        new_alerts = self._extract_alerts(new_events)
        
        if not any([new_sessions, new_events, new_api_calls]):
            return  # nothing new, skip POST
        
        payload = {
            "endpoint": self._get_endpoint_info(),
            "sessions": new_sessions,
            "events": new_events,
            "api_calls": new_api_calls,
            "alerts": new_alerts,
            "watermarks": {
                "events": watermarks.get("events", 0) + len(new_events),
                "sessions": watermarks.get("sessions", 0) + len(new_sessions),
                "api_calls": watermarks.get("api_calls", 0) + len(new_api_calls),
            }
        }
        
        response = requests.post(
            f"{self.cp_url}/api/v1/ingest",
            json=payload,
            headers={"X-API-Key": self.api_key},
            timeout=10,
        )
        response.raise_for_status()
        
        result = response.json()
        self.endpoint_id = result.get("endpoint_id")
        self._update_watermarks(payload["watermarks"])
```

## Config Changes (config.toml)

```toml
[control_plane]
enabled = false
url = "http://localhost:9090"
api_key = ""
sync_interval_seconds = 30
endpoint_name = ""  # auto-detected from hostname if empty
```

CLI usage:
```bash
# Standalone (existing, unchanged)
ai-monitor --start

# With control plane sync
ai-monitor --start --control-plane http://cp-host:9090 --cp-api-key "key123"

# With proxy AND control plane
ai-monitor --start --with-proxy --control-plane http://cp-host:9090 --cp-api-key "key123"
```

## Docker Test Environment

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: fleet_monitor
      POSTGRES_USER: monitor
      POSTGRES_PASSWORD: ${CP_DB_PASSWORD:-changeme}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U monitor"]
      interval: 5s
      timeout: 5s
      retries: 5

  control-plane:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://monitor:${CP_DB_PASSWORD:-changeme}@postgres:5432/fleet_monitor
      CP_API_KEY: ${CP_API_KEY:-test-key-123}
      CP_PORT: "9090"
    ports:
      - "9090:9090"

  test-client:
    image: python:3.12-slim
    depends_on:
      - control-plane
    volumes:
      - ./test-client:/app
    environment:
      CP_URL: http://control-plane:9090
      CP_API_KEY: ${CP_API_KEY:-test-key-123}
    command: python /app/simulate_endpoint.py

volumes:
  pgdata:
```

## Test Setup

```
Your laptop (Client 1 — real data):
  $ ai-monitor --start --with-proxy \
      --control-plane http://localhost:9090 \
      --cp-api-key "test-key-123"

Docker (Client 2 + CP):
  $ cd control-plane/
  $ docker compose up -d
  
  This starts:
    - Postgres (port 5432)
    - Control Plane (port 9090) 
    - Test Client (generates fake sessions every 30s)

Verify:
  $ curl http://localhost:9090/api/v1/endpoints
  → shows 2 endpoints: your laptop + test-client
  
  Open http://localhost:9090/dashboard
  → fleet dashboard with both endpoints
```

## Security Considerations

| Concern | Mitigation |
|---|---|
| API key in transit | HTTPS in production. HTTP acceptable for localhost test only. |
| API key storage | bcrypt hash in Postgres. Never logged. Never in error responses. |
| Sensitive data in payloads | Snippets contain detected secrets. HTTPS required for non-localhost. |
| SQL injection | All queries via SQLAlchemy ORM with parameterized statements. |
| Rate limiting | 60 req/min per endpoint. Prevents abuse from compromised client. |
| Endpoint impersonation | API key is per-endpoint. Rotating keys supported via registry API. |
| CP database access | Postgres credentials via env vars, never in code. |
| Fleet dashboard auth | Future: add authentication. Current: localhost-only access. |

## Future: ACMS Memory Integration

Once the CP is stable, integrate ACMS as an insight layer:

1. Feed fleet events into ACMS memory store
2. ACMS builds cross-session, cross-endpoint knowledge graph
3. Query: "What patterns lead to credential exposures?"
4. Query: "Which developers consistently use agents without sandbox?"
5. Query: "What's the most common tool sequence before a security alert?"
6. Surface insights in the fleet dashboard as an "Insights" tab

This is Phase 5 — design only, implement after CP is validated.
