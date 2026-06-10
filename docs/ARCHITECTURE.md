# Architecture

**Last updated:** 2026-05-24
**Status:** v0.2 launch candidate
**Companion specs:** [PRD](./spec/PRD.md), [THREAT-MODEL](./spec/THREAT-MODEL.md), [SECURITY-MANIFEST](./spec/SECURITY-MANIFEST.md), [API-CONTRACTS](./spec/API-CONTRACTS.md)

This document is the technical architecture reference for AI Runtime Monitor (Vigil). The repo root `README.md` is the user entry point; this document describes how the system actually works.

## 1. System overview

```
┌──────────────────┐   JSONL transcripts    ┌─────────────────┐    SQLite     ┌────────────────┐
│  Claude Code     │ ─────────────────────→ │   monitor.py    │ ───────────→ │   Dashboard    │
│  Cursor, Aider   │   ~/.claude/projects/  │   (scanners)    │  monitor.db  │   :9081        │
│  (AI agents)     │                        └─────────────────┘              │   9 tabs       │
└────────┬─────────┘                               │                        └────────────────┘
         │                                         │ psutil                         ↑
         │                                         ▼                               │
         │                                  ┌─────────────┐                        │
         │                                  │ Processes    │─── processes table ────┤
         │                                  │ Connections  │─── connections table ──┤
         │                                  │ File events  │─── file_events table ──┤
         │                                  │ Chrome hist  │─── browser_sessions ───┘
         │                                  └─────────────┘
         │
         │  HTTPS_PROXY                    ┌─────────────────┐   dual-write
         └───────────────────────────────→ │   watch.py      │ ──────┐
            (optional deep capture)        │   (mitmproxy    │       │
                                           │    addon)       │       ▼
                                           └────────┬────────┘  ┌──────────┐
                                                    │           │monitor.db│──→ api_calls table
                                                    ▼           └──────────┘
                                              CSV session
                                              files (primary)
```

All captured data stays local. There is no daemon-side outbound sync surface.

## 2. Trust boundaries

The system crosses four trust boundaries today, with a fifth (B5: Agent Identity) planned for v0.3 — see `docs/spec/THREAT-MODEL.md` §7 and `docs/design/agent-detection.md`. The threat model document analyzes each in detail; this section is the diagram.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Developer's machine (single OS user)                                        │
│                                                                             │
│   ┌─────────────────┐         ┌─────────────────┐        ┌─────────────┐    │
│   │  AI agents      │   B1    │  Vigil daemon   │   B2   │  SQLite DB  │    │
│   │  (UNTRUSTED:    │ ──────→ │  (TRUSTED:      │ ─────→ │  (TRUSTED:  │    │
│   │   could be      │  JSONL  │   our code)     │  WAL   │   chmod 600)│    │
│   │   prompt-       │  files  │                 │        │             │    │
│   │   injected)     │         │                 │        │             │    │
│   └─────────────────┘         └────┬────────────┘        └─────────────┘    │
│                                    │                                        │
│   ┌─────────────────┐         B4   │   B1            ┌─────────────────┐    │
│   │  Browser ext    │  ──────→     ▼  ←─────────     │  Dashboard UI   │    │
│   │  (UNTRUSTED)    │         ┌─────────────────┐    │  (UNTRUSTED:    │    │
│   └─────────────────┘         │ DashboardHandler│ ←──│   could be      │    │
│                               │ (HTTP + token)  │    │   spoofed)      │    │
│                               └─────────────────┘    └─────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘

                          B3: Proxy ↔ AI APIs
                          ──────────────────────────
                          Cryptographically constrained via X.509 NameConstraints
                          Can only sign leaf certs for ~10 AI domains
```

- **B1 — User/Agents ↔ Daemon (HTTP API):** Token-authenticated, constant-time compared, bound to 127.0.0.1 by default
- **B2 — Daemon ↔ Database (file system):** Chmod 600/700 enforcement, WAL mode, planned SQLCipher in v0.3
- **B3 — Proxy ↔ AI APIs (TLS termination):** Cryptographic enforcement via X.509 NameConstraints, addon-level host filter
- **B4 — Browser Extension ↔ Daemon (HTTP):** Same bearer token model as B1, treats extension data as untrusted

Each boundary's STRIDE analysis is in [spec/THREAT-MODEL.md](./spec/THREAT-MODEL.md).

## 3. Data flows

### 3.1 Capture flow: JSONL → DB → Dashboard

```
AI agent             JSONLSessionWatcher         monitor.db          Dashboard
──────────           ──────────────────         ──────────          ─────────
Writes JSONL  ───→   Tail file        ───→     INSERT into
event                Parse line                events, sessions
                     Scan sensitive  ───→      INSERT into
                     patterns                  events (sensitive_data)
                                                                    Browser polls
                                                                    /api/feed
                                                                    Returns JSON
                                                                    rows
```

Volume: each Claude Code turn produces ~5-15 JSONL events. A heavy session produces ~500 events. Total events per developer per day: 5,000-50,000.

The "Scan sensitive patterns" step in this flow is detailed in §3.5 (filter chain: regex → validators → confidence filter → context-aware downgrade).

### 3.2 Proxy capture flow: HTTPS → CSV + DB

```
AI agent             mitmproxy              ClaudeWatchAddon         monitor.db
──────────           ────────               ────────────────         ──────────
HTTP request  ───→   TLS terminate ───→     Filter host
through proxy        with CA cert           Capture body
                                            Scan sensitive
                                            Write CSV       ───→    INSERT into
                                            (primary)               api_calls
                                                                    (dual-write,
                                                                     best-effort)
```

The CSV is the source of truth. The DB write is best-effort and used by the dashboard for fast queries. If the DB write fails, the data is still in the CSV and recoverable.

### 3.3 Dashboard request flow

```
Browser              DashboardHandler         security.py            monitor.db
───────              ────────────────         ──────────             ──────────
GET /api/sessions
?token=xxx
                     verify_token() ───→      hmac.compare_digest
                                              (constant-time)
                     parse query params
                                                                     SELECT ... ORDER BY
                     execute query  ─────────────────────────────→   ... LIMIT ?
                     ←─────────────────────────────────────────────  rows
                     Serialize to JSON
                     Write response
Receive JSON
Render in tab
```

Hot path: every dashboard refresh hits 3-5 endpoints. Round-trip latency < 50ms on a developer machine.

### 3.4 Sensitive Data Detection Pipeline

The data-flow walkthrough for sensitive-pattern matching as text moves from a captured event into the database. Preserved from the prior architecture revision because the per-stage filter chain doesn't appear elsewhere and reviewers ask about it.

```
Text input
  |
  v
scan_sensitive() [utils.py]
  |-- Regex match against SENSITIVE_PATTERNS (constants.py)
  |-- Validator check (validators.py) — Luhn, entropy, JWT decode, etc.
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

**Validator-level detail** (`validators.py`). Each pattern type has a validator
that returns `{valid, confidence, details, live}`:

| Validator | Key Check | Rejects |
|---|---|---|
| `validate_credit_card` | Luhn checksum + digit count | Numbers near JSON metadata keys, all-same-digit, failed Luhn |
| `validate_phone_number` | Proximity to ID keywords | Numbers within 50 chars of `sender_id`, `message_id`, `chat_id`, `telegram` |
| `validate_ssn` | Area/group/serial rules | `000-xx-xxxx`, `666-xx-xxxx`, `9xx-xx-xxxx`, `xxx-00-xxxx`, `xxx-xx-0000`, known test SSNs |
| `validate_password` | Shannon entropy | Placeholders (`changeme`, `password`), entropy < 2.0, comments |
| `validate_jwt` | Header/payload base64 decode | Invalid base64, missing `alg` in header, non-JSON payload |
| `validate_aws_key` | Prefix + length + charset | Wrong prefix, not 20 chars, lowercase chars |
| `validate_db_connection` | URI parse + password entropy | No password, placeholder password, low entropy |

**Shannon entropy** measures randomness: `H = -sum(p * log2(p))`. Real passwords
score > 3.0; placeholders like "changeme" score ~2.5.

**Luhn algorithm** validates credit-card check digits. Catches token counts and
request IDs that happen to match the card regex pattern.

## 4. Module dependency graph

```
                         ┌──────────┐
                         │ config   │ ◀────── (everyone depends on this)
                         └──────────┘
                              ▲
              ┌───────────────┼───────────────┐
              │               │               │
        ┌──────────┐    ┌──────────┐    ┌──────────┐
        │constants │    │  utils   │    │ security │
        └──────────┘    └──────────┘    └──────────┘
              ▲               ▲               ▲
              │               │               │
              └───────┬───────┴───────┬───────┘
                      │               │
                ┌──────────┐    ┌──────────┐
                │   db     │    │validators│
                └──────────┘    └──────────┘
                      ▲               ▲
                      │               │
        ┌─────────────┼───────────────┼─────────────┐
        │             │               │             │
   ┌──────────┐  ┌──────────┐                 ┌──────────┐
   │  watch   │  │ monitor  │                 │  status  │
   └──────────┘  └──────────┘                 └──────────┘
                      ▲                              ▲
                      │                              │
              ┌──────────┐                     ┌──────────┐
              │  wizard  │                     │lifecycle │
              └──────────┘                     └──────────┘

   Specialized scanners (called from monitor.py):
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │supply_chain  │  │threat_intel  │  │vuln_scanner  │
   └──────────────┘  └──────────────┘  └──────────────┘
   ┌──────────────┐
   │   report     │
   └──────────────┘
```

Layer rules (enforced via planned import-linter):

- **Foundation layer** (`config`, `constants`, `utils`) — no project imports
- **Primitives layer** (`security`, `db`, `validators`) — depends only on foundation
- **Scanners layer** (`supply_chain`, `threat_intel`, `vuln_scanner`, `report`) — depends on foundation + primitives
- **Application layer** (`monitor`, `watch`, `status`, `wizard`, `lifecycle`) — depends on everything below

Forbidden imports (enforced post-Phase-3F):

- Primitives layer importing from application layer (would create a cycle)
- Foundation layer importing from anywhere else
- Scanners importing from each other (each scanner is self-contained)

## 5. Module structure

```
src/claude_monitoring/
├── __init__.py           Package init
├── config.py             TOML config loading, defaults, accessors
├── constants.py          AI_HOSTS, SENSITIVE_PATTERNS, MODEL_PRICING, CSV_COLUMNS
├── utils.py              estimate_cost, scan_sensitive, extract_file_paths, now_iso
├── db.py                 init_db (7 tables + indexes), insert_api_call, get_thread_db
├── security.py           CA generation, token mgmt, masking, purge, perm enforcement
├── validators.py         Per-pattern validators (Luhn, JWT, entropy, etc.)
├── lifecycle.py          Heartbeat, crash tracking, LaunchAgent integration
├── monitor.py            Main entry point: scanners, dashboard HTTP server, API
├── watch.py              mitmproxy addon, CLI analysis tools, proxy setup/verify
├── status.py             ai-monitor --status diagnostic
├── wizard.py             First-run setup + secure uninstall
├── supply_chain.py       Package inventory across 19 managers
├── threat_intel.py       ThreatFox, URLhaus, IOC ingestion
├── vuln_scanner.py       pip-audit + OSV.dev integration
├── report.py             Markdown / HTML / CSV report generation
├── dashboard.html        Self-contained HTML/CSS/JS dashboard (embedded)
└── watch_dashboard.html  Standalone watch session dashboard

src/claude_monitoring/protocols/   (Phase 3F target)
├── __init__.py
├── scanner.py            Scanner Protocol + Finding + ScannerHealth
├── collector.py          Collector Protocol (planned)
└── detector.py           Detector Protocol (planned)

src/claude_monitoring/scanners/    (Phase 3F target, M6 split)
├── jsonl_session.py      Currently in monitor.py
├── process.py            Currently in monitor.py
├── network.py            Currently in monitor.py
├── filesystem.py         Currently in monitor.py
└── browser_history.py    Currently in monitor.py
```

## 6. Deployment model

### 6.1 v0.2 — single-process daemon

Everything runs in one Python process on the developer's machine:

- Main thread: HTTP dashboard server
- Scanner threads: one per scanner (JSONL, process, network, filesystem, browser history)
- Watchdog thread: heartbeat updater
- Optional mitmproxy subprocess: HTTPS interception (when `--with-proxy`)

The process is started by the user (`ai-monitor --start`) or by a macOS LaunchAgent on login.

### 6.2 v0.3+ — packaged distributions

- Homebrew formula: `brew install vigil`
- macOS .dmg with signed installer
- Linux: Debian and RPM packages (best-effort; macOS is primary)
- Windows: planned v0.3 (process and network monitoring); proxy in v0.4

### 6.3 Startup Sequence

The `start_monitoring()` entry point in `monitor.py` wires the daemon together. All scanner classes referenced below live in `monitor.py` — see Section 5 for the module inventory. Preserved from the prior architecture revision because the dependency order between watchers, scanners, and the HTTP server matters for operators debugging stuck startups.

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

## 7. Data sources

### Layer 1: JSONL Transcript Tailing (passive, no proxy needed)

`JSONLSessionWatcher` tails `~/.claude/projects/*/` and `~/.openclaw/sessions/*/` for `.jsonl` files written by AI agents. Each line is a structured event (user message, assistant response, tool call, result). Extracted data:

- Session metadata (model, cwd, start time, title)
- Turn-by-turn token usage and cost
- Tool calls (Bash, Read, Write, Edit, Glob, Grep, etc.)
- Sensitive pattern detection in message content
- File paths read/written

Stored in: `sessions`, `events` tables.

### Layer 2: System Monitoring (psutil + watchdog)

- **ProcessScanner**: polls `psutil.process_iter()` every 30s for known AI process names (claude, cursor, copilot, aider, etc.)
- **NetworkMonitor**: polls `psutil.net_connections()` for connections to known AI API hosts
- **FileSystemWatcher**: uses `watchdog` FSEvents to detect file modifications
- **ChromeHistoryWatcher**: reads Chrome's `History` SQLite DB for visits to AI service URLs

Stored in: `processes`, `connections`, `file_events`, `browser_sessions` tables.

### Layer 3: HTTPS Proxy Interception (optional, requires setup)

`ClaudeWatchAddon` is a mitmproxy addon that intercepts HTTPS traffic when agents are configured with `HTTPS_PROXY`. Captures full request/response payloads:

- Exact input/output/cache token counts from API response headers
- System prompt character count
- Message previews (user + assistant)
- Tool call names and arguments
- Sensitive pattern detection in payloads
- Latency, HTTP status, stop reason, request ID

Stored in: CSV files (primary) + `api_calls` table (dual-write, best-effort).

**v0.2.1 capture-coverage ceiling on macOS desktop AI apps.** Layer 3 captures whatever traffic actually reaches the proxy. On macOS the proxy is configured at a single IPv4 host via `networksetup -setsecurewebproxy`, and Electron-based desktop AI apps split networking across child processes: the network-service helper (`network.mojom.NetworkService`) honors that proxy for routine traffic, but the main process may maintain persistent IPv6 channels (e.g., long-lived HTTP/2 streams to `api.anthropic.com`) that bypass it. PAC (proxy auto-config) was empirically tested in the v0.2.1 sprint and routes a subset of Electron traffic for the network-service helper but cannot redirect already-established main-process channels. Cursor's plugin/extension-host subprocesses bypass at the vendor level. `chatgpt.com` is intentionally excluded from `allow_hosts` per the PR #51 API-only invariant (Boundary B4 in `docs/spec/THREAT-MODEL.md`), so ChatGPT Desktop's `chatgpt.com/backend-api` traffic reaches the proxy but is not decrypted. The honest live verdict per surface is surfaced by `ai-monitor --status` (PR #72). The architectural fix is v0.3 — Apple Network Extension framework intercepts at the OS network stack regardless of subprocess or address family. See `docs/spec/functional/security.md` §13 for the v0.3 plan.

### 7.5 Monitoring Layer Implementation Detail

Per-scanner implementation reference. The high-altitude flow lives in Sections 3 and 7 above; this section is the concrete "how" each scanner is wired, what library it depends on, and where its data lands. Preserved from the prior architecture revision because the per-scanner subsections are the canonical answer to "how does Vigil actually see this?" — and they don't exist elsewhere in the spec corpus.

Section 7 above uses "Layer 1/2/3" for the data-source taxonomy (JSONL / system-monitoring / proxy). The subsections below use the scanner class names directly — `JSONLSessionWatcher`, `NetworkMonitor`, `FileActivityHandler`, `ProcessScanner`, `ChromeHistoryWatcher` — to avoid colliding with Section 7's numbering.

#### JSONL Session Watcher (`JSONLSessionWatcher`)

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
6. Text content is scanned for sensitive data patterns via `_check_sensitive()` (see Section 3.5)

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

#### Network Monitor (`NetworkMonitor`)

**What it monitors:** Active TCP connections from AI processes.

**How it works:**
1. Runs every 5 seconds in a background thread
2. Uses `psutil` to enumerate all processes and their network connections
3. For each connection, checks if the remote host matches `AI_HOSTS` (from constants.py)
4. Also does reverse DNS lookups and IP prefix matching for Anthropic's GCP-hosted API
5. Stores connections in the `connections` table

**Known AI hosts tracked:** Anthropic, OpenAI, Google/Gemini, AWS Bedrock, Mistral, Cohere, Groq, Together AI, Perplexity, DeepSeek, xAI/Grok, HuggingFace, Replicate, Fireworks, Ollama (local), LM Studio (local), OpenClaw (local), OpenRouter, Azure OpenAI, plus telemetry services (Sentry, Statsig, Segment, Amplitude).

#### File Activity Monitor (`FileActivityHandler`)

**What it monitors:** File system operations in project directories.

**How it works:**
1. Uses `watchdog` to observe the current working directory
2. Dynamically adds new directories from active session CWDs
3. Records file creates, modifications, and deletes in the `file_events` table
4. Filters out noise: `.git/`, `__pycache__/`, `node_modules/`, `.pyc` files

#### Process Scanner (`ProcessScanner`)

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

#### Chrome History Watcher (`ChromeHistoryWatcher`)

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

## 8. Database schema

All tables live in `~/claude_watch_output/monitor.db` (SQLite, WAL mode).

### sessions
| Column | Type | Description |
|--------|------|-------------|
| session_id | TEXT PK | Claude session UUID |
| start_time | TEXT | ISO 8601 timestamp |
| cwd | TEXT | Working directory |
| model | TEXT | Model name (claude-sonnet-4, etc.) |
| total_cost | REAL | Cumulative estimated cost USD |
| total_input_tokens | INTEGER | Cumulative input tokens |
| total_output_tokens | INTEGER | Cumulative output tokens |
| total_turns | INTEGER | Number of conversation turns |
| jsonl_path | TEXT | Path to source JSONL file |
| last_activity | TEXT | Most recent event timestamp |
| title | TEXT | Session title / first user message |

### events
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 |
| session_id | TEXT | FK to sessions |
| event_type | TEXT | user_prompt, assistant_response, tool_use, token_usage, sensitive_data |
| source_layer | TEXT | jsonl, network, process, filesystem |
| data_json | TEXT | JSON payload with event-specific fields |

### api_calls
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 |
| session_id | TEXT | Claude session ID |
| turn_id | TEXT | Turn identifier |
| turn_number | INTEGER | Sequential turn number |
| destination_host | TEXT | API hostname |
| destination_service | TEXT | Service classifier (anthropic_api, openai_api, etc.) |
| endpoint_path | TEXT | /v1/messages, /v1/chat/completions, etc. |
| http_method | TEXT | POST, GET |
| http_status | INTEGER | 200, 429, 500, etc. |
| model | TEXT | Model name |
| stream | TEXT | true/false |
| input_tokens | INTEGER | Input token count |
| output_tokens | INTEGER | Output token count |
| cache_read_tokens | INTEGER | Cache read token count |
| cache_write_tokens | INTEGER | Cache write token count |
| estimated_cost_usd | REAL | Estimated cost |
| request_size_bytes | INTEGER | HTTP request body size |
| response_size_bytes | INTEGER | HTTP response body size |
| latency_ms | INTEGER | Request latency |
| num_messages | INTEGER | Messages in conversation |
| system_prompt_chars | INTEGER | System prompt length |
| last_user_msg_preview | TEXT | Truncated last user message |
| assistant_msg_preview | TEXT | Truncated assistant response |
| tool_calls | TEXT | JSON list of tool call names |
| tool_call_count | INTEGER | Number of tool calls |
| bash_commands | TEXT | Bash commands extracted |
| files_read | TEXT | Files read in this turn |
| files_written | TEXT | Files written in this turn |
| urls_fetched | TEXT | URLs fetched |
| sensitive_patterns | TEXT | Detected sensitive patterns |
| sensitive_pattern_count | INTEGER | Count of sensitive patterns |
| stop_reason | TEXT | end_turn, tool_use, max_tokens |
| request_id | TEXT | API request ID header |

### processes
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| pid | INTEGER | OS process ID |
| name | TEXT | Process name |
| cmdline | TEXT | Full command line |
| start_time | TEXT | Process start time |
| end_time | TEXT | Process end time (if terminated) |
| cpu_percent | REAL | CPU usage percentage |
| memory_percent | REAL | Memory usage percentage |
| status | TEXT | running / terminated |

### connections
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | When connection was observed |
| pid | INTEGER | Process ID |
| process_name | TEXT | Process name |
| remote_host | TEXT | Remote IP/hostname |
| remote_port | INTEGER | Remote port |
| status | TEXT | ESTABLISHED, etc. |
| service | TEXT | Classified service name |

### file_events
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| timestamp | TEXT | ISO 8601 |
| path | TEXT | File path |
| operation | TEXT | created, modified, deleted |
| session_id | TEXT | Associated session |
| size | INTEGER | File size in bytes |

### browser_sessions
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| service | TEXT | ChatGPT, Gemini, Claude Web, etc. |
| url | TEXT | Full URL |
| title | TEXT | Page title |
| conversation_id | TEXT | Extracted conversation/chat ID |
| visit_time | TEXT | ISO 8601 |
| duration_seconds | REAL | Time on page |
| foreground_seconds | REAL | Active tab time |
| tab_id | INTEGER | Chrome tab ID |
| window_id | INTEGER | Chrome window ID |

### Indexes

- `idx_events_ts` — events(timestamp)
- `idx_events_session` — events(session_id)
- `idx_events_type` — events(event_type)
- `idx_sessions_last` — sessions(last_activity)
- `idx_file_events_ts` — file_events(timestamp)
- `idx_processes_pid` — processes(pid)
- `idx_browser_conv` — browser_sessions(conversation_id)
- `idx_browser_visit` — browser_sessions(visit_time)
- `idx_connections_pid` — connections(pid)
- `idx_connections_ts` — connections(timestamp)
- `idx_api_calls_ts` — api_calls(timestamp)
- `idx_api_calls_session` — api_calls(session_id)
- `idx_api_calls_service` — api_calls(destination_service)

## 9. API reference

All endpoints are served by the built-in HTTP server on the dashboard port (default 9081). Responses are JSON unless noted.

Full machine-readable spec: [spec/openapi.yaml](./spec/openapi.yaml). Human narrative: [spec/API-CONTRACTS.md](./spec/API-CONTRACTS.md).

### Sessions
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sessions` | List sessions. Params: `search`, `sort` (recent/cost/tokens), `limit`, `offset` |
| GET | `/api/session/<id>` | Session detail with metadata + event summary |
| GET | `/api/session/<id>/turns` | Turn-by-turn breakdown for Deep Dive |
| GET | `/api/session/<id>/traffic` | API calls for a specific session |

### Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Aggregate stats (process count, connections, files, cost) |
| GET | `/api/feed` | Live event feed. Params: `limit`, `offset` |
| GET | `/api/processes` | Running/recent AI processes |
| GET | `/api/process/<pid>` | Process detail |
| GET | `/api/connections` | Network connections |
| GET | `/api/files` | File events. Params: `limit`, `offset` |

### API Traffic (from proxy)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/traffic` | Paginated API call list. Params: `service`, `limit`, `offset` |
| GET | `/api/traffic/stats` | Aggregated traffic stats (total calls, cost, tokens by service/model) |

### Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | Sensitive data alerts. Params: `severity`, `category`, `session_id`, `limit`, `offset` |

### Browser
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/browser` | Browser AI activity summary |
| GET | `/api/browser/sessions` | List browser AI sessions |
| GET | `/api/browser/session/<conversation_id>` | Browser session detail |

### Timeline & Export
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/activity/timeline` | Unified chronological feed across all sources |
| GET | `/api/export` | Export data. Params: `type` (events/alerts/connections/sessions), `format` (json/ndjson/csv), `session_id` |

## 10. Configuration

Config file: `~/.config/ai-runtime-monitor/config.toml` (XDG), fallback `~/claude_watch_output/config.toml`.

Generate a default config:
```bash
ai-monitor --init-config
```

Priority: CLI flags > config file > built-in defaults.

See [config.py](src/claude_monitoring/config.py) for the full default config template.

### Key settings

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| server | dashboard_port | 9081 | Dashboard HTTP port |
| server | proxy_port | 9080 | mitmproxy HTTPS proxy port |
| server | bind_address | 127.0.0.1 | Bind address (localhost only by default) |
| paths | output_dir | ~/claude_watch_output | Data directory |
| paths | db_name | monitor.db | SQLite database filename |
| proxy | enabled | false | Start proxy with dashboard |
| proxy | cert_path | ~/.mitmproxy/mitmproxy-ca-cert.pem | CA cert location |

## 11. Security model

- Dashboard and proxy bind to `127.0.0.1` by default (localhost only)
- Remote access requires explicit `--bind 0.0.0.0` opt-in
- mitmproxy CA cert is scoped to AI domains via X.509 NameConstraints (cryptographic enforcement)
- No secrets stored in config file
- Config file permissions are checked (warns if world-readable)
- `proxy_env.sh` is generated with `chmod 600`
- All SQL queries use parameterized statements (no string interpolation with user input)
- Dashboard authentication via per-install bearer token (constant-time compared)
- Sensitive data masked at capture, auto-purged after 30 days
- Sync agent sanitizes payloads as defense-in-depth before transmission

Full security control inventory: [spec/SECURITY-MANIFEST.md](./spec/SECURITY-MANIFEST.md). STRIDE threat analysis: [spec/THREAT-MODEL.md](./spec/THREAT-MODEL.md).

## 12. Extensibility points

The product is designed for these extension paths:

### 12.1 Adding a new AI service to detect

- Add the hostname to `constants.AI_HOSTS` and `constants.AI_PROXY_DOMAINS`
- Add a service classifier rule in `constants.SERVICE_CLASSIFICATION`
- No code changes elsewhere; the scanners and proxy auto-pick up the new entries
- Update `docs/spec/PRD.md` capability list (caught by spec-requirements CI)

### 12.2 Adding a new scanner (e.g., container monitoring)

Post-Phase-3F (M6 split), this becomes a clean path:

- Create a class in `scanners/` implementing the `Scanner` Protocol from `protocols/scanner.py`
- Add to `monitor.py::run` scanner list
- Add conformance test to `tests/architecture/`
- Update `docs/spec/functional/<scanner_name>.md`

### 12.3 Adding a new sensitive data pattern

- Add to `constants.SENSITIVE_PATTERNS` with name, regex, severity, category
- Optionally add a validator to `validators.py` to reduce false positives
- Add unit test with positive and negative examples

### 12.4 Adding a new API endpoint

- Add the route handler method to `DashboardHandler`
- Dispatch from `do_GET`
- Add to `docs/spec/openapi.yaml` (CI enforces this)
- Add to `docs/spec/API-CONTRACTS.md` if the contract has design rationale

### 12.5 Supporting a new AI agent for configuration

- Add an entry to the per-agent config table in `watch.py::cli_configure`
- Document the proxy injection method (shell_rc, app_config, env_file)
- Add unit test with mocked shell profile

### 12.6 Adding a new validator

- Add a function to `validators.py` that takes `(matched_text, full_text)` and returns `{"valid": bool, "confidence": "high"|"medium"|"low"}`
- Register in `VALIDATORS` dict keyed by pattern name
- Add unit tests with positive cases (real-format values) and negative cases (lookalikes)

## 13. CLI commands

### ai-monitor (main dashboard)
```
ai-monitor --start              # Start monitoring + dashboard
ai-monitor --start --with-proxy # Start with HTTPS proxy
ai-monitor --port 9082          # Custom port
ai-monitor --status             # Diagnostic report
ai-monitor --status-json        # Machine-readable status
ai-monitor --install-agent      # macOS LaunchAgent (auto-start)
ai-monitor --uninstall-agent    # Remove LaunchAgent
ai-monitor --init-config        # Generate config.toml
ai-monitor --setup              # Run first-run wizard (force)
ai-monitor --purge              # Secure uninstall
```

### claude-watch (proxy + analysis)
```
claude-watch --setup             # First-time: install mitmproxy, trust cert
claude-watch --start             # Start mitmproxy interceptor
claude-watch --verify            # Health check proxy setup
claude-watch --configure <agent> # Configure HTTPS_PROXY for an agent
claude-watch --unconfigure       # Remove proxy config from shell
claude-watch --analyze           # Terminal analysis of latest session
claude-watch --plot              # Generate PNG charts
claude-watch --dashboard         # Standalone web dashboard
claude-watch --scan              # Detect running AI agents
claude-watch --generate-test     # Create synthetic test data
```

## 14. Testing posture

Test coverage is tracked via per-file ratchet (see PR #27) and reported in the CI workflow output. Per-module testing detail lives in the corresponding `docs/spec/functional/<module>.md`.

> The prior architecture revision included a "Test Coverage" section enumerating test counts and per-file inventories. That section was dropped here because the counts went stale within a sprint and the ratchet + per-module specs are the canonical homes.

## 15. Related documents

- [README.md](./README.md) — product entry point for users
- [spec/PRD.md](./spec/PRD.md) — product requirements, target users, roadmap
- [spec/openapi.yaml](./spec/openapi.yaml) — machine-readable API spec
- [spec/API-CONTRACTS.md](./spec/API-CONTRACTS.md) — API design narrative
- [spec/THREAT-MODEL.md](./spec/THREAT-MODEL.md) — STRIDE analysis
- [spec/SECURITY-MANIFEST.md](./spec/SECURITY-MANIFEST.md) — controls mapped to OWASP ASVS / NIST SSDF
- [spec/functional/](./spec/functional/) — per-module functional specs
- [SSDLC_ENFORCEMENT.md](./SSDLC_ENFORCEMENT.md) — engineering process and CI controls
