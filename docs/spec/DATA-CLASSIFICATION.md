# Data Classification — AI Runtime Monitor (Vigil) v0.2

**Last updated:** 2026-05-24
**Status:** v0.2 launch candidate
**Audience:** Enterprise procurement, security review, compliance auditors

This document classifies every category of data that Vigil collects, stores, transmits, or displays. Each category includes its sensitivity level, retention policy, where it's stored, what it's used for, and how it's protected.

## 1. Classification scheme

Four sensitivity tiers, modeled on common enterprise data classification:

| Tier | Examples | Default handling |
|------|---------|------------------|
| **Critical** | Credentials, private keys, API tokens, PAN numbers | Masked at capture; plaintext never persisted; auto-purged after 30 days |
| **Sensitive** | User prompts, AI responses, file contents, tool call args | Stored at rest with chmod 600; auto-purged plaintext after 30 days |
| **Internal** | Process names, file paths, model names, token counts, timings | Stored at rest with chmod 600; retained indefinitely |
| **Public** | Open source code, README, OpenAPI spec, version numbers | No special handling |

## 2. Data inventory by table

### 2.1 `sessions` table

| Column | Tier | Purpose | Retention |
|--------|------|---------|-----------|
| session_id | Internal | Identifier | Indefinite |
| start_time, last_activity | Internal | Time bookkeeping | Indefinite |
| cwd | Sensitive | Working directory may include project name | 30 days (then path retained but `data_json` plaintext purged) |
| model | Internal | Model name (e.g., claude-sonnet-4-5) | Indefinite |
| total_cost, tokens, turns | Internal | Usage metrics | Indefinite |
| jsonl_path | Sensitive | File system path; could leak project info | 30 days |
| title | Sensitive | First user message snippet | 30 days |

### 2.2 `events` table — `data_json` column contents

The `data_json` payload varies by `event_type`. Sensitivity also varies:

| Event type | data_json fields | Tier of contents |
|-----------|-----------------|------------------|
| `user_prompt` | text | **Sensitive** (user's words) |
| `assistant_response` | text | **Sensitive** (AI's response) |
| `tool_use` | name, args | **Sensitive** (args may contain code, paths, secrets pre-masking) |
| `token_usage` | input_tokens, output_tokens, cache_read, cache_write | Internal |
| `sensitive_data` | severity, category, patterns, masked_value, hash, snippet, matched_value | **Critical** for `matched_value` and `snippet`; Internal for everything else |
| `file_event` | path, operation, size | Sensitive (path); Internal (size, op) |
| `process_event` | pid, name, cmdline | Sensitive (cmdline can include sensitive args) |
| `network_event` | host, port, service | Internal |

### 2.3 `api_calls` table

| Column | Tier | Purpose | Retention |
|--------|------|---------|-----------|
| timestamp, session_id, turn_id, turn_number | Internal | Identifiers | Indefinite |
| destination_host, destination_service, endpoint_path | Internal | Routing info | Indefinite |
| http_method, http_status, latency_ms, request_id | Internal | HTTP metadata | Indefinite |
| model | Internal | Model name | Indefinite |
| input_tokens, output_tokens, cache_*, estimated_cost_usd | Internal | Usage metrics | Indefinite |
| request_size_bytes, response_size_bytes | Internal | Size only | Indefinite |
| num_messages, system_prompt_chars | Internal | Length info | Indefinite |
| last_user_msg_preview, assistant_msg_preview | **Sensitive** | Truncated content (~200 chars) | 30 days |
| tool_calls, tool_call_count | Sensitive | Tool names and arg shape | 30 days |
| bash_commands | **Sensitive** | Extracted shell commands | 30 days |
| files_read, files_written, urls_fetched | Sensitive | File paths and URLs | 30 days |
| sensitive_patterns, sensitive_pattern_count | Internal | Detection summary (no plaintext) | Indefinite |
| stop_reason | Internal | API metadata | Indefinite |

### 2.4 `processes`, `connections`, `file_events`, `browser_sessions`

All columns are **Internal** tier. They describe process and network activity without including the contents of what's being processed or transferred.

Exception: `browser_sessions.url` and `title` may include conversation IDs and topic hints. Classified as **Sensitive** for retention purposes.

### 2.4a `extension_heartbeats`, `extension_captures` (Chrome extension surface)

`extension_heartbeats` row schema:

| Column | Tier | Notes |
|--------|------|-------|
| `hostname` | Internal | One of the AI browser hosts (claude.ai, chatgpt.com, gemini.google.com). Set membership; not sensitive. |
| `last_seen` | Internal | UTC timestamp of the last heartbeat from the extension. |
| `user_matches` / `assistant_matches` | Internal | Per-heartbeat counts of DOM-matched elements. Aggregate counts, no content. |
| `captures_sent` | Internal | Number of capture events submitted in the heartbeat window. |
| `selector_failure` | Internal | Boolean — true when the extension is alive but the page DOM stopped yielding the expected selectors. |

`extension_captures` (browser AI content emitted by the extension):

| Column | Tier | Notes |
|--------|------|-------|
| `text` (and any DOM-derived content fields) | **Sensitive** | Mirrors `events.data_json.text` classification — user prompts, assistant responses, code blocks. Same masking and retention as Layer 1 JSONL captures. |
| `service`, `event_type`, `url`, `timestamp` | Internal | Routing metadata. |

The extension is the **sole** capture surface for browser AI usage as of PR #51 (proxy `allow_hosts` no longer includes browser UI sites). The Sensitive classification on `extension_captures.text` follows from that — it is the same data class that the JSONL/proxy paths carry for Claude Code and desktop apps.

### 2.5 `package_vulnerabilities`, `agent_dependencies`, `intel_source_status`

All **Internal** tier. Package names, version numbers, CVE IDs, and threat intel records.

### 2.6 Configuration files

| File | Tier | Contents |
|------|------|----------|
| `~/.config/ai-runtime-monitor/config.toml` | Internal | Ports, paths, opt-in flags |
| `~/claude_watch_output/.dashboard_token` | **Critical** | Bearer token for dashboard auth |
| `~/claude_watch_output/.setup_complete` | **Critical** | Includes the dashboard token in JSON |
| `~/claude_watch_output/certs/ai-monitor-ca-key.pem` | **Critical** | CA private key |
| `~/claude_watch_output/certs/ai-monitor-ca.pem` | Public | CA public cert (designed to be installed in trust stores) |

### 2.3. Attack-surface data (v0.2.2 P0.2+)

Added 2026-06-05 with the v0.2.2 P1.2 PR. The discovery feature
(Phases 1-5) reads attacker-controllable config bytes and produces
`Asset` records. Three data types cross the B7 boundary:

| Data type | Tier | Notes |
|---|---|---|
| Raw config bytes read off disk (pre-redaction window) | **Critical** | May contain API tokens, OAuth secrets, env vars with passwords. Held in memory only during parse + redact; downclassifies after `redact_secrets_in_env` completes. |
| Parsed `Asset.current_state` payload (post-redaction) | **Internal** | Process names, file paths, version numbers, redacted env-var maps. Token-shaped values replaced with `[REDACTED — token-shaped variable name]` / `[REDACTED — token-shaped value]` sentinels. **Relies on DB chmod-600 as the backstop for redaction residuals, NOT on redaction being exhaustive** (heuristic 8 value patterns + 5 name suffixes; novel token shapes may escape). |
| `assets` table rows | **Internal** | `current_state` is JSON-serialized via `json.dumps` into the `current_state` TEXT column. Same Internal tier; chmod-600 inherited from `monitor.db`. |
| `discovery_runs` table rows | **Internal** | One row per scan invocation. Records trigger, sources, asset counts, per-source `outcome` (LastRunOutcome.value: `success` / `timeout` / `error` / `capped` / `uncalled`) via the `errors` JSON column. No raw config bytes; no token values. |

The redaction layer is heuristic, env-scoped, source-invoked; residuals
are possible. The chmod-600 DB is the at-rest backstop, not redaction
completeness.

## 3. Data flow with classification

### 3.1 Capture path (Layer 1: JSONL)

```
User writes prompt
    │
    │ Sensitive content
    ▼
AI agent JSONL file (chmod 600 typically; outside Vigil's control)
    │
    │ JSONLSessionWatcher tails
    ▼
scan_sensitive() runs
    │
    │ If matches: mask via security.mask_value, hash via security.hash_value
    │ Plaintext is INCLUDED in data_json for "snippet" and "matched_value"
    │ (purged after 30 days, but present during the window)
    ▼
INSERT into events table (chmod 600 DB)
```

### 3.2 Dashboard display path

```
GET /api/alerts
    │
    │ Bearer token verified (constant-time)
    ▼
SELECT data_json FROM events WHERE event_type = 'sensitive_data'
    │
    │ data_json includes masked_value (safe for display)
    │ data_json may also include matched_value if < 30 days old
    │ The dashboard renders ONLY masked_value
    ▼
JSON response (over HTTP on localhost, no TLS in v0.2)
    │
    ▼
Browser renders Alert row (matched_value not shown in UI)
```

The dashboard's UI never renders `matched_value` or `snippet`. They are returned in the API response (a v0.3 candidate change is to strip them at the API layer too) but the HTML rendering uses only `masked_value`.

### 3.4 Browser session export

```
GET /api/export?type=events&format=csv&session_id=<id>
    │
    │ Bearer token verified
    ▼
SELECT events WHERE session_id = ?
    │
    │ data_json may contain ALL fields (including matched_value if < 30 days)
    ▼
CSV stream returned to browser
    │
    ▼
User downloads CSV
```

The export endpoint is the most permissive output path. It returns the raw `data_json` field contents, including any plaintext that hasn't yet been purged. This is intentional — the user owns their data and may need it for forensic analysis — but customers handling regulated data should configure auto-purge to a shorter window.

## 4. Retention policies

### 4.1 Critical-tier retention

- **Credentials in user prompts/responses** — `matched_value` and `snippet` purged after 30 days; metadata (severity, pattern, hash) retained indefinitely
- **Dashboard token** — until manual rotation via `ai-monitor --setup`
- **CA private key** — until manual purge via `ai-monitor --purge`

The 30-day window for credential plaintext is configurable in v0.3+. The default is chosen to balance forensic value (long enough for investigation) against exposure window (short enough to limit leak impact).

### 4.2 Sensitive-tier retention

- **Message previews, tool args, file paths** — same 30-day plaintext purge as critical tier
- **Session titles, working directories** — retained indefinitely (metadata is internal-tier)

### 4.3 Internal-tier retention

- All counts, IDs, timestamps, model names, hostnames, token counts — retained indefinitely
- Total database size grows roughly linearly with use; expect ~50 MB per developer-month at moderate usage
- v0.3 will add configurable retention windows per data type

## 5. Data subject rights

The product is single-user and locally-hosted. The "data subject" (the developer) has full control over their data through:

- **Right to access:** the entire database is at `~/claude_watch_output/monitor.db` (readable by SQLite tools)
- **Right to delete:** `ai-monitor --purge` deletes all data
- **Right to export:** `/api/export` endpoint or direct SQLite query
- **Right to rectify:** the user can run UPDATE/DELETE against the local DB directly

There is no remote data plane in v0.2. All captured data stays local.

## 6. Cross-border data transfer


For a future v1.0+ managed enterprise control plane (planned, not yet designed):
- Regional deployment (US, EU) to honor data residency
- Customer chooses region at signup
- No cross-region replication without explicit opt-in

## 7. Special handling for regulated data

The product is not designed for use with PHI, PCI-DSS scope data, or government-classified information. Customers in these regulated industries should:

- Configure auto-purge to 7 days (the planned minimum in v0.3)
- Run only the local daemon
- Treat the daemon's database with the same care as other regulated data stores

A future Enterprise tier may add specific certifications (HIPAA-compliant managed plane, PCI-DSS scope segmentation) but these are not in the v0.2 roadmap.

## 8. Logging and metrics

The product's own logs are at `~/claude_watch_output/monitor.log`. Log entries are classified as:

| Log content | Tier | Example |
|-------------|------|---------|
| Module names, function names | Public | `[SyncAgent] Sync failed` |
| Error type names (without values) | Internal | `sanitize failed: ValueError` |
| File paths, hostnames, port numbers | Internal | `Listening on 127.0.0.1:9081` |
| User prompts, credentials, message bodies | **NEVER LOGGED** | (would be a bug if it appeared) |

The sanitization log line explicitly never includes the input value:

```python
logger.warning("sanitize failed: %s", type(e).__name__)
# NOT: logger.warning("sanitize failed for value %s", value)
```

This is verified by per-handler logger configuration; no log line emits a redacted/sensitive value.

## 9. Third-party data transmission

The product transmits data to:

| Destination | Why | Data sent | User control |
|-------------|-----|-----------|--------------|
| Anthropic, OpenAI, Google API endpoints | These are the AI APIs the user's own agents call (we don't initiate) | None from Vigil itself | n/a |
| OSV.dev API | Vulnerability lookup for installed packages | Package names + versions (no credentials, no user data) | Implicit (vulnerability scanning is core functionality) |
| abuse.ch ThreatFox API | Threat intel feed | None (we only pull from them) | Implicit |
| abuse.ch URLhaus API | Threat intel feed | None (we only pull from them) | Implicit |
| GoCloudForge servers | Telemetry (planned v0.3, opt-in) | None in v0.2 | n/a (not active) |

The OSV.dev calls send package names but no credentials. The threat intel feeds are pull-only. There is no analytics, no telemetry, no "phone home" in v0.2.

## 10. Verification

For procurement reviewers who want to verify these claims:

- Open the source code at github.com/rajan-cforge/ai-runtime-monitor-enterprise
- Search for `requests.post`, `urllib.request`, `socket.connect` — these are every outbound network call
- Search for `logger.` and `print(` — these are every log line


For deeper verification, contact security@gocloudforge.com.
