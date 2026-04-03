# AI Runtime Monitor — Architecture & Design

## Overview

AI Runtime Monitor is a three-layer observability system for AI coding agents. It provides CrowdStrike-style visibility into what AI tools are doing on your machine: what they're reading, writing, executing, and sending over the network.

```
                    +---------------------------+
                    |     Web Dashboard :9081    |
                    |  (dashboard.html via HTTP) |
                    +---------------------------+
                             |  REST API
                    +---------------------------+
                    |   DashboardHandler (HTTP)  |
                    |   /api/sessions            |
                    |   /api/stats               |
                    |   /api/events              |
                    |   /api/browser/*           |
                    |   /api/processes           |
                    +---------------------------+
                             |  SQLite queries
                    +---------------------------+
                    |       monitor.db           |
                    |   (SQLite + WAL mode)      |
                    +---------------------------+
                     ^       ^       ^       ^
                     |       |       |       |
              +------+  +---+--+  +-+----+ ++--------+
              |Layer1a| |Layer1b| |Layer2 | |Layer 3  |
              |JSONL  | |Network| |Files  | |Process  |
              |Watcher| |Monitor| |Watch  | |Scanner  |
              +-------+ +------+ +------+ +---------+
                                                ^
                                         +------+------+
                                         | Layer 4     |
                                         | Chrome      |
                                         | History     |
                                         +-------------+
```

## Source Files

| File | Purpose | Lines |
|---|---|---|
| `monitor.py` | Main engine: all layers, dashboard HTTP server, JSONL processing | ~3000 |
| `watch.py` | mitmproxy addon for deep API traffic capture (proxy mode) | ~800 |
| `constants.py` | AI_HOSTS, SENSITIVE_PATTERNS, BROWSER_AI_PATTERNS, process lists | ~350 |
| `config.py` | TOML config loading, CLI overrides, path resolution | ~300 |
| `db.py` | SQLite schema, migrations, thread-safe connections | ~150 |
| `utils.py` | `scan_sensitive()`, `is_ai_process()`, `extract_urls()` | ~120 |
| `validators.py` | Deep validation for sensitive data (Luhn, entropy, JWT decode) | ~450 |
| `report.py` | Markdown/HTML/CSV report generation | ~200 |
| `dashboard.html` | Single-file SPA: session explorer, charts, alerts, live feed | ~1500 |
| `watch_dashboard.html` | Proxy-mode dashboard for API traffic analysis | ~400 |

## Monitoring Layers

### Layer 1a: JSONL Session Watcher (`JSONLSessionWatcher`)

**What it monitors:** Claude Code and OpenClaw JSONL transcript files.

**How it works:**
1. Uses `watchdog` (filesystem event library) to watch two directories:
   - `~/.claude/projects/` — Claude Code session transcripts
   - `~/.openclaw/agents/main/sessions/` — OpenClaw session transcripts
2. When a `.jsonl` file is created or modified, reads new lines from the last-known file position
3. Each JSON line is parsed and dispatched by `type` field:
   - Claude Code: `type:"user"` / `type:"assistant"` / `type:"system"` / `type:"progress"`
   - OpenClaw: `type:"session"` / `type:"model_change"` / `type:"message"` (with `role` in `message.role`)
4. OpenClaw records are normalized to Claude Code format via `_normalize_openclaw_record()`:
   - `toolCall` -> `tool_use`, `arguments` -> `input`
   - `stopReason` -> `stop_reason`
   - `usage.input` -> `usage.input_tokens`, `cacheRead` -> `cache_read_input_tokens`
5. Events are stored in the `events` table; session metadata updated in `sessions` table
6. Text content is scanned for sensitive data patterns via `_check_sensitive()`

**Data flow:**
```
JSONL file change -> watchdog event -> process_jsonl_file()
  -> read new lines -> json.loads() -> _process_record()
    -> _process_user_message() / _process_assistant_message()
      -> _store_event() -> INSERT INTO events
      -> _check_sensitive() -> scan_sensitive() + validators
      -> _update_session_stats() -> UPDATE sessions
```

**Deduplication:** Records are deduped by UUID (`_seen_uuids` set). File positions are tracked per-path (`file_positions` dict) so only new lines are processed.

**Backfill:** On startup, `backfill_existing_sessions()` scans all existing JSONL files to populate the database with historical data.

### Layer 1b: Network Monitor (`NetworkMonitor`)

**What it monitors:** Active TCP connections from AI processes.

**How it works:**
1. Runs every 5 seconds in a background thread
2. Uses `psutil` to enumerate all processes and their network connections
3. For each connection, checks if the remote host matches `AI_HOSTS` (from constants.py)
4. Also does reverse DNS lookups and IP prefix matching for Anthropic's GCP-hosted API
5. Stores connections in the `connections` table

**Known AI hosts tracked:** Anthropic, OpenAI, Google/Gemini, AWS Bedrock, Mistral, Cohere, Groq, Together AI, Perplexity, DeepSeek, xAI/Grok, HuggingFace, Replicate, Fireworks, Ollama (local), LM Studio (local), OpenClaw (local), OpenRouter, Azure OpenAI, plus telemetry services (Sentry, Statsig, Segment, Amplitude).

### Layer 2: File Activity Monitor (`FileActivityHandler`)

**What it monitors:** File system operations in project directories.

**How it works:**
1. Uses `watchdog` to observe the current working directory
2. Dynamically adds new directories from active session CWDs
3. Records file creates, modifications, and deletes in the `file_events` table
4. Filters out noise: `.git/`, `__pycache__/`, `node_modules/`, `.pyc` files

### Layer 3: Process Scanner (`ProcessScanner`)

**What it monitors:** Running AI-related processes.

**How it works:**
1. Runs every 2 seconds in a background thread
2. Uses `psutil.process_iter()` to scan all processes
3. Two-tier matching via `is_ai_process()`:
   - **Exact match:** Process name in `AI_PROCESS_EXACT` (e.g., "claude", "ChatGPT", "openclaw-gateway")
   - **Pattern match:** Substring in `AI_PROCESS_PATTERNS` with exclusion lists (e.g., "cursor" but not "CursorUIViewService")
4. Tracks process lifecycle: start, running, terminated
5. Records CPU%, memory%, cmdline in `processes` table
6. Skips macOS system services (`/System/Library/`, `/usr/libexec/`)

### Layer 4: Chrome History Watcher (`ChromeHistoryWatcher`)

**What it monitors:** Browser visits to AI services (ChatGPT, Gemini, Claude Web, etc.).

**How it works:**
1. Runs every 60 seconds in a background thread
2. Finds Chrome History SQLite databases across all profiles:
   - `~/Library/Application Support/Google/Chrome/Default/History`
   - `~/Library/Application Support/Google/Chrome/Profile */History`
3. **Cannot read Chrome's DB directly** (it's locked by Chrome), so:
   - Copies the History file to a temp location (`tempfile.mkstemp`)
   - Opens the copy with `sqlite3`
   - Queries the `visits` + `urls` tables
   - Deletes the temp copy
4. Filters URLs against `BROWSER_AI_PATTERNS` dictionary:
   - `chatgpt.com` / `chat.openai.com` -> "ChatGPT"
   - `gemini.google.com` -> "Gemini"
   - `claude.ai` -> "Claude Web"
   - `perplexity.ai` -> "Perplexity"
   - `copilot.microsoft.com` -> "Copilot"
   - `aistudio.google.com` -> "AI Studio"
   - `deepseek.com` -> "DeepSeek"
5. Extracts conversation IDs from URL paths:
   - ChatGPT: `/c/{id}` -> conversation ID
   - Gemini: `/app/{id}` -> conversation ID
   - Claude Web: `/chat/{id}` -> conversation ID
6. Chrome timestamps are microseconds since 1601-01-01 (WebKit epoch), converted via: `unix_ts = chrome_ts / 1_000_000 - 11644473600`
7. Visit duration comes from Chrome's `visits.visit_duration` field (microseconds)
8. Incremental: tracks `last_check_times` per profile to only query new visits
9. First run looks back 7 days

**Data stored per visit:**
- Service name, URL, page title
- Conversation ID (extracted from URL)
- Visit timestamp (ISO format)
- Visit duration (seconds)

**Limitations:**
- macOS only (hardcoded Chrome path)
- Chrome only (no Firefox, Safari, Arc, Brave)
- Cannot detect incognito sessions
- Duration is Chrome's estimate, not actual active tab time
- No content capture — only URLs and titles
- Conversation grouping depends on URL pattern; services that don't put IDs in URLs show as individual visits

## Database Schema

```sql
-- Agent sessions (Claude Code, OpenClaw, etc.)
sessions (session_id PK, start_time, cwd, model, total_cost,
          total_input_tokens, total_output_tokens, total_turns,
          jsonl_path, last_activity, title)

-- All events from all layers
events (id PK, timestamp, session_id, event_type, source_layer, data_json)

-- Network connections from AI processes
connections (id PK, timestamp, pid, process_name, remote_host,
             remote_port, status, service)

-- Running AI processes
processes (id PK, pid, name, cmdline, start_time, end_time,
           cpu_percent, memory_percent, status)

-- File operations in project directories
file_events (id PK, timestamp, path, operation, session_id, size)

-- Browser visits to AI services
browser_sessions (id PK, service, url, title, conversation_id,
                  visit_time, duration_seconds, foreground_seconds,
                  tab_id, window_id)

-- Deep API traffic capture (proxy mode only)
api_calls (id PK, timestamp, session_id, turn_id, turn_number,
           destination_host, destination_service, endpoint_path,
           http_method, http_status, model, stream, input_tokens,
           output_tokens, cache_read_tokens, cache_write_tokens, ...)
```

## Dashboard Architecture

The dashboard is a single HTML file (`dashboard.html`) that serves as a self-contained SPA:

- **No build step** — vanilla JS, no framework
- **Chart.js** for graphs (loaded from CDN)
- **Polling** — fetches `/api/stats` and `/api/sessions` periodically
- **Live feed** — in-memory deque (`live_feed`, 500 items) pushed via polling

### Dashboard Tabs
1. **Overview** — stat cards (sessions, events, tokens, alerts, processes, browser visits), token timeline chart, tool usage chart, browser AI usage chart
2. **Session Explorer** — unified list of CLI sessions + browser sessions, searchable, sortable; click to see full event timeline
3. **Processes** — live AI process list with CPU/memory
4. **Network** — active connections to AI hosts
5. **Alerts** — sensitive data detections with severity filtering
6. **Live Feed** — real-time event stream

### Browser Sessions in Dashboard
Browser sessions appear in the Session Explorer alongside CLI sessions:
- Purple left border and "service badge" (e.g., "ChatGPT", "Gemini")
- Shows visit count instead of turn count
- Shows duration instead of token count
- Click opens a detail view with:
  - All visits to that conversation
  - Temporally correlated network connections (within +/- 5 minutes)

### API Endpoints
| Endpoint | Purpose |
|---|---|
| `GET /api/stats` | Overview stats: totals, timelines, browser daily breakdown |
| `GET /api/sessions` | Session list (CLI + browser when `include_browser=true`) |
| `GET /api/session/{id}` | Session detail with events |
| `GET /api/browser` | Raw browser visit list |
| `GET /api/browser/sessions` | Browser visits grouped by conversation |
| `GET /api/browser/session/{conv_id}` | Browser conversation detail + correlated connections |
| `GET /api/processes` | Running AI processes |
| `GET /api/connections` | Active network connections |
| `GET /api/events` | Event stream for a session |
| `GET /api/alerts` | Sensitive data alerts |
| `GET /api/feed` | Live event feed |

## Sensitive Data Detection Pipeline

```
Text input
  |
  v
scan_sensitive() [utils.py]
  |-- Regex match against SENSITIVE_PATTERNS (constants.py)
  |-- Validator check (validators.py) - Luhn, entropy, JWT decode, etc.
  |-- Only "high" / "medium" confidence matches pass
  |
  v
_check_sensitive() [monitor.py]
  |-- Filter KNOWN_EXAMPLE_SECRETS
  |-- Filter phone_number when near "sender_id" (Telegram IDs)
  |-- Filter credit_card when near API metadata keywords
  |-- _adjust_alert_severity() — context-aware downgrade
  |     |-- tool_result in /tests/ -> "low"
  |     |-- assistant discussing security -> "medium"
  |     |-- tool writes to test files -> "low"
  |
  v
Store sensitive_data event in DB
```

## Startup Sequence

```
start_monitoring()
  |-- init_db() — create tables + migrations
  |-- detect_plan_info() — check subscription tier
  |-- Create JSONLSessionWatcher + watchdog observer
  |     |-- Watch ~/.claude/projects/ (Claude Code)
  |     |-- Watch ~/.openclaw/agents/main/sessions/ (OpenClaw)
  |-- backfill_existing_sessions() — process all existing JSONL files (background thread)
  |-- Create FileActivityHandler + watchdog observer
  |-- Create ProcessScanner (2s loop, background thread)
  |-- Create NetworkMonitor (5s loop, background thread)
  |-- Create ChromeHistoryWatcher (60s loop, background thread)
  |-- Start ReusableHTTPServer on port 9081
  |-- Initial process scan + print found AI processes
  |-- Block main thread (Ctrl+C to stop)
```

## Test Coverage

682 tests across 15 test files:
- `test_jsonl_watcher.py` — 113 tests (JSONL processing, OpenClaw normalization, sensitive data filtering)
- `test_monitor_main.py` — 51 tests (Chrome history, process scanning, dashboard APIs)
- `test_validators.py` — 85 tests (Luhn, entropy, all 12 validators, integration)
- `test_config.py` — 57 tests
- `test_watch_parsing.py` — 80 tests (API response parsing)
- `test_sensitive.py` — 20 tests
- `test_chrome.py` — 9 tests (timestamp conversion, URL parsing)
- And more...
