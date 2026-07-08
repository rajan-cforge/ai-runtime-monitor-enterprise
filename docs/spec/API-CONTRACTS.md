# API Contracts

**Companion to:** [openapi.yaml](./openapi.yaml)
**Last updated:** 2026-05-24
**Status:** v0.2 launch candidate

This document is the human-readable narrative for the AI Runtime Monitor API. The machine-readable OpenAPI 3.0 spec is in `openapi.yaml`. Use the spec for client generation and contract testing; use this document for design rationale and usage patterns.

## 1. API surface overview

The local daemon exposes 22+ HTTP endpoints under `http://localhost:9081` (default). The dashboard's React-less HTML UI consumes these endpoints. External tooling and SIEMs consume them via the `/api/export` endpoint or by polling the structured endpoints directly.

The API is grouped into seven functional areas:

- **Sessions** (4 endpoints) — list, detail, turn-by-turn breakdown, per-session traffic
- **Monitoring** (5 endpoints) — stats, live feed, processes, connections, file events
- **API Traffic** (2 endpoints) — proxy-captured request/response data with stats
- **Security** (1 endpoint) — sensitive data alerts
- **Browser** (3 endpoints) — Chrome history-derived AI activity
- **Activity** (1 endpoint) — unified chronological feed
- **Export** (1 endpoint) — bulk export for SIEM integration

## 2. Authentication

Every endpoint requires a bearer token. Token is generated on first run by the setup wizard and stored at `~/claude_watch_output/.dashboard_token` with permissions 600. Two ways to present the token:

- **Header (preferred for programmatic access):**
  ```
  Authorization: Bearer <token>
  ```
- **Query parameter (convenience for browser bookmarks):**
  ```
  http://localhost:9081/?token=<token>
  ```

The token is compared in constant time using `hmac.compare_digest`. There are no other authentication methods in v0.2. There is no token rotation API — re-running `ai-monitor --setup` generates a new token and invalidates the old one.

## 3. Trust model

- **Bind address:** `127.0.0.1` by default. Remote access requires explicit opt-in via `--bind 0.0.0.0`.
- **CORS:** Not enabled. The dashboard's monkey-patched `fetch` injects the token from `localStorage` automatically. Cross-origin requests are rejected.
- **Rate limiting:** Not implemented in v0.2. The localhost-only default makes rate limiting low-priority. v1.0 fleet dashboard adds rate limiting.
- **HTTPS:** Not implemented in v0.2. Token-over-HTTP is acceptable on localhost. A future v1.0 enterprise control plane (planned, not yet designed) would require HTTPS for any remote bind.

## 4. Response conventions

### 4.1 Success responses

All endpoints return JSON unless `format=ndjson` or `format=csv` is specified on `/api/export`. JSON responses are structured by endpoint type:

- **List endpoints** (`/api/sessions`, `/api/alerts`, etc.) return either a bare array or a paginated envelope:
  ```json
  {
    "items": [...],
    "total": 1247,
    "limit": 100,
    "offset": 0
  }
  ```
- **Detail endpoints** (`/api/session/<id>`) return a single object, sometimes with nested summary data.
- **Stats endpoints** return aggregated numbers and breakdowns:
  ```json
  {
    "process_count": 3,
    "connection_count": 12,
    "active_sessions": 1
  }
  ```

### 4.2 Error responses

Errors return appropriate HTTP status codes with a JSON body:

```json
{
  "error": "session not found",
  "detail": "no session with id '550e8400-e29b-41d4-a716-446655440000'"
}
```

| Code | Meaning | Action |
|------|---------|--------|
| 200 | OK | Use the response body |
| 400 | Bad request (validation error) | Fix the parameters |
| 401 | Unauthorized (missing or wrong token) | Authenticate |
| 404 | Resource not found | Verify the ID |
| 500 | Internal server error | Check daemon logs |

## 5. Pagination

List endpoints accept `limit` and `offset` query parameters. Default limit is 100; maximum is 1000. Some endpoints (like `/api/feed`) return newest-first; others (like `/api/alerts`) return by severity then timestamp.

For very large data sets (such as bulk SIEM ingestion), the `/api/export` endpoint streams data without pagination overhead.

## 6. Endpoint group: Sessions

### 6.1 `GET /api/sessions` — list sessions

The most-used endpoint. Returns all captured sessions across CLI tools (Claude Code, OpenClaw) and browser AI (ChatGPT, Gemini).

Parameters:
- `search` — text search across title, cwd, model
- `sort` — `recent` (default), `cost`, or `tokens`
- `limit` — default 100, max 1000
- `offset` — pagination offset

Response: paginated list of `Session` objects.

### 6.2 `GET /api/session/<id>` — session detail

Returns session metadata plus an event-counts-by-type summary. Useful for building the Session Explorer left sidebar.

### 6.3 `GET /api/session/<id>/turns` — turn-by-turn breakdown

Returns the data the Deep Dive cockpit renders: turn rail with timing, API inspector with request/response shape, context gauge showing token usage trajectory.

### 6.4 `GET /api/session/<id>/traffic` — per-session API calls

Cross-references API calls captured by the mitmproxy addon back to a session ID. Only populated when the proxy is running.

## 7. Endpoint group: Monitoring

### 7.1 `GET /api/stats` — aggregate stats

Returns a snapshot of current state:
- `process_count` — AI processes currently running
- `connection_count` — network connections to AI hosts (last 5 minutes)
- `file_event_count` — file events in the last hour
- `total_cost_24h` — estimated AI cost in the last 24 hours
- `active_sessions` — sessions with activity in the last hour
- `alert_count_24h` — sensitive-data alerts in the last 24 hours

### 7.2 `GET /api/feed` — live event feed

Returns recent events across all source layers (JSONL, network, process, filesystem, browser). The dashboard polls this every few seconds to drive the Live Feed tab.

### 7.3 `GET /api/processes` — AI processes

Lists running and recently-terminated AI processes. Includes PID, name, cmdline, CPU/memory percent, start/end times.

### 7.4 `GET /api/process/<pid>` — process detail

Detailed information about a single process including its connections, file events, and session associations.

### 7.5 `GET /api/connections` — network connections

Recent network connections to AI service hosts. Useful for spotting unexpected destinations.

### 7.6 `GET /api/files` — file events

File system events (create, modify, delete) attributed to AI agents.

## 8. Endpoint group: API Traffic

### 8.1 `GET /api/traffic` — captured API calls

Returns API calls captured by the mitmproxy addon. Includes full token counts, costs, latency, and structured tool calls. Empty if the proxy is not running.

Parameters:
- `service` — filter by destination service (anthropic_api, openai_api, etc.)
- `limit` — default 100
- `offset` — pagination

### 8.2 `GET /api/traffic/stats` — traffic stats

Aggregated stats by service and model. Used to drive the API Traffic tab's overview cards.

## 9. Endpoint group: Security

### 9.1 `GET /api/alerts` — sensitive data alerts

Returns sensitive-data alerts surfaced from the scanning pipeline. Each alert includes:
- `severity` — critical / high / medium / low
- `category` — credential / pii / financial / identity / key_material
- `patterns` — list of pattern names that matched
- `masked_value` — first 4 chars + asterisks + last 4 chars (never the raw value)
- `hash` — SHA-256 first-16 hex chars for deduplication
- `confidence` — validator confidence (high / medium; low confidence is filtered out)
- `validated` — true if a validator (Luhn, Shannon entropy, JWT decode, etc.) ran

Plaintext fragments (`snippet`, `matched_value`, `match_context`) are stripped after 30 days by the auto-purge process; the alert metadata is retained indefinitely.

Parameters:
- `severity` — filter by severity
- `category` — filter by category
- `session_id` — filter to a single session
- `limit` / `offset` — pagination

## 10. Endpoint group: Browser

Browser endpoints derive data from Chrome's history database. They show AI service usage (ChatGPT, Gemini, Claude Web, Copilot, Perplexity, DeepSeek) without requiring a browser extension. The optional browser extension (v0.2.1) adds content-level capture; these endpoints work with or without the extension.

### 10.1 `GET /api/browser` — summary

Returns AI service usage breakdown.

### 10.2 `GET /api/browser/sessions` — list sessions

Returns browser AI sessions with conversation IDs extracted from URLs.

### 10.3 `GET /api/browser/session/<conversation_id>` — session detail

Detail for a specific browser AI conversation.

## 11. Endpoint group: Activity Timeline

### 11.1 `GET /api/activity/timeline` — unified feed

Merges events from all source layers into a single chronological feed. The Activity Timeline tab uses this to give a "what happened" view across CLI tools, browser AI, and system events.

## 12. Endpoint group: Export

### 12.1 `GET /api/export` — bulk export

Exports captured data in JSON, NDJSON, or CSV format. Designed for SIEM ingestion and offline analysis.

Parameters:
- `type` — required: `events`, `alerts`, `connections`, `sessions`, or `traffic`
- `format` — `json` (default), `ndjson` (one JSON object per line), or `csv`
- `session_id` — optional filter

Output stream is unbounded; pagination does not apply.

## 13. Versioning

The local daemon API is currently versioned at v0.2. There is no `/v1/` prefix because the API is treated as one cohesive surface tied to the daemon version. Breaking changes will be communicated via:

- CHANGELOG.md entries
- Deprecation warnings in the daemon log
- A `/api/version` endpoint (planned for v1.0) that clients can query before making other calls

## 13.1 Attack Surface — Permission grants + audit log (P8-D, v0.2.2)

Added in P8-D per LOCKED §4.5.1 + directive §8.4.1. **Dormant in v0.2.2 core** (§8.4.1:1449 — "the prompt NEVER appears in production v0.2.2 core"); goes live in v0.2.2.1 (GitHub integration).

Data model per Rajan JD-2 Option C ratification 2026-07-08:

- **`permission_grants`** (existing, P0.2-shipped) — current-state view. PK=`integration`, columns `(integration, granted_at, granted_scope)`. Last-write-wins UPSERT on grant; DELETE on revoke.
- **`permission_audit`** (NEW in v0.2.2.004 migration) — append-only history. Every grant/revoke event is an immutable row; grant → revoke → re-grant preserves all 3 rows. Schema `(id INTEGER PK AUTOINCREMENT, integration TEXT, event TEXT CHECK (event IN ('granted','revoked')), event_at TIMESTAMP, granted_scope TEXT)`.
- Writes go through `record_permission_event()` which INSERTs to `permission_audit` and UPSERTs/DELETEs `permission_grants` in a single transaction (`with conn:` idiom).

### Endpoints

- **`GET /api/permissions/grants`** — current-state view. Envelope `{"grants": [{integration, granted_at, granted_scope}]}`. Empty list in dormant state.
- **`GET /api/permissions/audit?limit=N`** — reverse-chronological audit history. `limit` clamped [1, 1000], default 100. Envelope `{"events": [{id, integration, event, event_at, granted_scope}]}`. Empty list in dormant state.
- **`GET /api/permissions/debug-enabled`** — reflects `VIGIL_ENABLE_PERMISSION_PROMPT_DEBUG=1` env-var. Judge JD-1 hard pin (Rajan verdict 2026-07-08): frontend query-param `?debug-permission-prompt=1` MUST be AND'd with this daemon-side flag; query-param alone → literally inert. Envelope `{"debug_enabled": boolean}`.

All three routes gated by the same `verify_token` path as every other `/api/*` route (CF-JD1-A hard pin: debug feature is a gate STACKED ON TOP of auth, never a bypass).

Safe-default flip contract (p8-D.a1.verdict.md §4): any of the following → PR flips to security-C4, HALT for Rajan human review — enable a production trigger path; add a token column to either table; store a real API token; add a new host to `scripts/check_privacy_no_telemetry.py` ALLOWED_HOSTNAMES.

## 14. Future API changes

These are explicitly out of scope for v0.2 but anticipated for future versions:

- **`/api/policies`** — read/write prevention policies (v1.5+)
- **`/api/fleet/*`** — fleet aggregation endpoints exposed by a planned v1.0 enterprise control plane (not yet designed)
- **`/api/version`** — daemon version and API compatibility info (v1.0)
- **Websocket endpoints** — real-time push instead of polling for Live Feed (v0.3+)
- **GraphQL endpoint** — for richer client queries (under consideration; not committed)

## 15. Implementation references

The endpoints are implemented in `src/claude_monitoring/monitor.py` (`DashboardHandler` class). Request authentication is in `security.py::verify_token`. Sensitive-data masking is in `security.py::mask_value` and applied at insert time, not at serve time, so plaintext never appears in API responses.

A future enterprise control plane (planned for v1.0, not yet designed) would expose its own ingest API (e.g. `/api/v1/ingest`) on a separate service. The daemon-to-control-plane sync client was removed in `control-plane-feature-removal`; the local daemon no longer ships data off-box.

## 16. Known best-effort spec areas (verify during integration testing)

Per the source-honesty contract that drove the spec corpus, these aspects of `openapi.yaml` are explicitly best-effort and must be verified against the actual `DashboardHandler` implementations during the first integration test that consumes the spec. None of them affect spec validity (the file is `openapi-spec-validator` clean) — they affect spec *fidelity*.

- **Pagination envelope coverage.** `PaginatedResponse` is currently applied only to `/api/sessions` via `allOf`. Other list endpoints (`/api/feed`, `/api/files`, `/api/traffic`, `/api/alerts`, etc.) declare bare arrays even though they accept `limit` / `offset` query params. Either expand the envelope to those endpoints once integration tests confirm `total` is cheap to compute, or document each endpoint that ships bare arrays as intentional (e.g., streaming-friendly `/api/feed`).

- **Untyped response payloads.** Four endpoints — `/api/session/{id}/turns`, `/api/activity/timeline`, `/api/browser/session/{conversation_id}`, `/api/export` — declare `type: object` without property schemas because the spec author wasn't certain of the exact handler output shape. Tighten these to concrete schemas after sampling real responses.

- **`/api/traffic/stats` likely under-specifies the response.** The current schema uses `additionalProperties: integer` but the handler probably returns nested cost / token objects. Inspect and tighten.

- **The 401 response on every authenticated endpoint** was added mechanically in PR 3 since the global `security:` block implies it. If any endpoint is actually unauthenticated (none should be in v0.2, but worth confirming), remove the 401 ref for that endpoint.

These items are tracked here rather than as `TODO` markers inside `openapi.yaml` because mid-spec TODOs confuse client generators. When you fix one, delete the matching bullet here.
