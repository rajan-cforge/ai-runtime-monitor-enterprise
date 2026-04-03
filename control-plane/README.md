# AI Runtime Monitor — Control Plane

Fleet aggregation server for AI Runtime Monitor. Collects monitoring data from multiple developer endpoints into a single dashboard.

## Architecture

```
  Client 1 (MacBook)          Client 2 (Docker)
  ┌──────────────┐           ┌──────────────┐
  │ ai-monitor   │           │ test-client   │
  │ monitor.db   │           │ (simulated)   │
  └──────┬───────┘           └──────┬───────┘
         │ POST /api/v1/ingest       │
         │ (every 30s)               │
         └───────────┬───────────────┘
                     ▼
         ┌───────────────────┐
         │  Control Plane    │
         │  FastAPI + Postgres│
         │  Fleet Dashboard  │
         └───────────────────┘
```

## Prerequisites

- Docker Desktop
- Python 3.9+ (for client sync agent)

## Quick Start

```bash
cd control-plane
make setup          # Checks ports, generates .env, builds, starts
make health         # Verify all services healthy
```

Open http://localhost:9090/dashboard for the fleet dashboard.

## Connect Your Laptop

```bash
make connect        # Shows command with your API key
```

Then run:
```bash
ai-monitor --start --control-plane http://localhost:9090 --cp-api-key YOUR_KEY
```

## Services

| Container | Purpose | Port |
|---|---|---|
| arm-cp-postgres | Fleet database (Postgres 16) | 5433 (host) |
| arm-cp-server | FastAPI ingest + fleet dashboard | 9090 (host) |
| arm-cp-test-client | Generates fake session data | - |

## API Reference

```bash
# Health check
curl http://localhost:9090/health

# List endpoints (requires API key)
curl http://localhost:9090/api/v1/endpoints -H "X-API-Key: YOUR_KEY"

# Fleet stats
curl http://localhost:9090/api/v1/fleet/stats

# Fleet sessions
curl http://localhost:9090/api/v1/fleet/sessions

# Fleet alerts
curl "http://localhost:9090/api/v1/fleet/alerts?severity=high"

# Ingest (from client)
curl -X POST http://localhost:9090/api/v1/ingest \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"endpoint":{"hostname":"test"},"sessions":[],"events":[],"api_calls":[],"alerts":[],"watermarks":{}}'
```

## Management

```bash
make start          # Start services
make stop           # Stop (preserves data)
make teardown       # Stop + delete all data
make logs           # Tail all logs
make logs-cp        # Tail control plane only
make health         # Health check
make clean          # Remove .env and caches
```

## Port Configuration

Ports are auto-discovered by `scripts/setup.sh`. If you need to change them, edit `.env`:

```bash
POSTGRES_HOST_PORT=5433    # Change if 5433 is taken
CP_HOST_PORT=9090          # Change if 9090 is taken
```

Then restart: `make stop && make start`

## Security

- All services bind to localhost only
- API key required for ingest and endpoints API
- Postgres credentials are randomly generated
- Never expose to public network without proper authentication
- All SQL queries use parameterized statements (SQLAlchemy)
