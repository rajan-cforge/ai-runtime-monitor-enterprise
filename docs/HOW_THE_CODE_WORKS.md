# How the Code Works — Developer Guide

This document explains how each component of AI Runtime Monitor works at the code level. Generated with the aid of the codebase knowledge graph (1125 nodes, 3186 edges).

## Code Graph Summary

The knowledge graph reveals the codebase structure:
- **180 functions/classes** in the `claude_monitoring` package
- **Top hotspots** (most-called functions): `load_config` (56 callers), `_ensure_session` (55), `parse_request_body` (36), `get_thread_db` (26), `_process_record` (25)
- **Entry points**: `start_monitoring()`, `main()`, all `_api_*` handlers, `scan_once()` methods
- **Clusters**: JSONL processing cluster, watch/parsing cluster, config cluster, dashboard API cluster, Chrome history cluster

## monitor.py — The Main Engine (~3000 lines)

### Initialization & Thread Model

```python
start_monitoring()
  -> init_db()              # Create SQLite DB with WAL mode
  -> detect_plan_info()     # Read ~/.claude/settings.json for subscription tier
  -> JSONLSessionWatcher()  # Layer 1a — JSONL processing
  -> Observer().schedule()  # watchdog filesystem observer for JSONL dirs
  -> backfill_existing_sessions()  # Background thread: scan all *.jsonl files
  -> FileActivityHandler()  # Layer 2 — file change observer
  -> ProcessScanner()       # Layer 3 — 2s polling loop, background thread
  -> NetworkMonitor()       # Layer 1b — 5s polling loop, background thread
  -> ChromeHistoryWatcher() # Layer 4 — 60s polling loop, background thread
  -> ReusableHTTPServer()   # Dashboard on port 9081, background thread
```

All monitoring runs in daemon threads. The main thread blocks on `threading.Event().wait()` until Ctrl+C.

### JSONLSessionWatcher — The Core Data Pipeline

This is the most complex component. The call graph from the knowledge graph shows:

```
process_jsonl_file()
  -> read new bytes from file (tracked by file_positions dict)
  -> json.loads() each line
  -> _process_record()
       |
       |-- Dedup check: skip if uuid in _seen_uuids set
       |-- Resolve session_id:
       |     sessionId field (Claude Code)
       |     OR record.id for type:"session" (OpenClaw)
       |     OR filename UUID (OpenClaw messages)
       |
       |-- type:"session" -> _ensure_session() and return
       |-- type:"model_change" -> _update_session_stats(model=...) and return
       |
       |-- type:"message" (OpenClaw):
       |     role from message.role
       |     -> _normalize_openclaw_record()
       |     -> dispatch to user/assistant/toolResult handler
       |
       |-- type:"user" (Claude Code):
       |     -> _process_user_message()
       |
       |-- type:"assistant" (Claude Code):
       |     -> _process_assistant_message()
```

**`_process_user_message()`** handles two content formats:
- String content (simple text prompt)
- List content with `{type:"text"}` and `{type:"tool_result"}` blocks

For each text block: stores `user_prompt` event, runs `_check_sensitive()`, increments turn count, sets session title.

**`_process_assistant_message()`** iterates content blocks:
- `{type:"thinking"}` -> stores `thinking` event
- `{type:"text"}` -> stores `assistant_response` event
- `{type:"tool_use"}` -> stores `tool_use` event with input preview:
  - Bash: shows command
  - Read/Write/Edit: shows file path
  - Glob/Grep: shows pattern
  - WebFetch: shows URL
  - MCP tools (`mcp__server__method`): triggers `mcp_call` event + unknown server alert

After content blocks: stores `token_usage` event and updates session stats.

**`_normalize_openclaw_record()`** translates OpenClaw field names:
```python
toolCall     -> tool_use       (content block type)
arguments    -> input          (tool call arguments)
toolResult   -> tool_result    (content block type)
toolUseId    -> tool_use_id    (tool result reference)
stopReason   -> stop_reason    (on message object)
usage.input  -> input_tokens   (token counts)
usage.output -> output_tokens
cacheRead    -> cache_read_input_tokens
cacheWrite   -> cache_creation_input_tokens
```

**`_normalize_openclaw_tool_result()`** reshapes top-level `role:"toolResult"` messages into the nested content-block format that `_process_user_message()` expects.

### Session Title Extraction

`_set_session_title()` runs on the first user message of each session:
- For OpenClaw sessions (cwd contains `.openclaw`): strips Telegram metadata wrappers and prefixes with "OpenClaw . Telegram:"
- `_extract_openclaw_user_text()` splits on triple-backtick fences to find the actual user message after metadata blocks
- Truncates at ~120 chars on a word boundary

### Sensitive Data Pipeline

`_check_sensitive()` is called on every text block (user prompts, assistant responses, tool inputs, tool results):

```python
_check_sensitive(text, session_id, timestamp, context)
  -> scan_sensitive(text)           # regex + validator pipeline
  -> filter KNOWN_EXAMPLE_SECRETS   # known test values (AKIAIOSFODNN7EXAMPLE etc.)
  -> filter phone_number when sender_id/message_id in text
  -> filter credit_card when API metadata keywords in text
  -> _adjust_alert_severity()       # context-aware downgrade
  -> _store_event(type="sensitive_data")
```

**`_adjust_alert_severity()`** reduces false positives via context rules:
- `tool_result` with `/tests/` or `test_` path -> "low"
- `tool_result` with "EXAMPLE" keyword -> "low"
- `assistant_response` discussing security (contains "detected", "credential", etc.) -> cap at "medium"
- `tool:*` with `/tests/` path -> "low"

### _ensure_session — UPSERT Pattern

The most-called function (55 callers). Uses SQLite's `INSERT...ON CONFLICT DO UPDATE`:
```sql
INSERT INTO sessions (session_id, start_time, cwd, jsonl_path, last_activity)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
  last_activity = excluded.last_activity,
  cwd = COALESCE(excluded.cwd, sessions.cwd),
  jsonl_path = COALESCE(excluded.jsonl_path, sessions.jsonl_path)
```

Passes `cwd or None` (not empty string) to preserve existing cwd via COALESCE.

### ChromeHistoryWatcher — Browser Analysis

```python
scan_once()
  -> _find_history_files()  # iterate Chrome/Default, Chrome/Profile*
  -> for each profile:
       tempfile.mkstemp() + shutil.copy2()  # copy locked DB
       sqlite3.connect(tmp_path)
       -> SELECT urls.url, urls.title, visits.visit_time, visits.visit_duration
          FROM visits JOIN urls ON visits.url = urls.id
          WHERE (url LIKE '%chatgpt.com%' OR url LIKE '%claude.ai%' OR ...)
            AND visit_time > ?  -- incremental cutoff
       -> for each row:
            match URL against BROWSER_AI_PATTERNS dict
            _chrome_ts_to_iso(visit_time)  # WebKit epoch -> ISO
            _extract_conversation_id(url, service)  # parse /c/, /app/, /chat/
            INSERT INTO browser_sessions
            push_live_event()
       os.unlink(tmp_path)  # cleanup
```

**Chrome timestamp math:** Chrome stores timestamps as microseconds since January 1, 1601 (WebKit/Windows FILETIME epoch). To convert: `unix_seconds = chrome_microseconds / 1,000,000 - 11,644,473,600`

**Conversation ID extraction** parses service-specific URL patterns:
- ChatGPT: `chatgpt.com/c/{conversation_id}` 
- Gemini: `gemini.google.com/app/{conversation_id}`
- Claude Web: `claude.ai/chat/{conversation_id}`

### DashboardHandler — HTTP API Server

Routes are registered in `do_GET()` as a dict mapping path -> handler method. Key endpoints:

**`_api_sessions()`** — The session list is a union of:
1. CLI sessions from `sessions` table (source="cli")
2. Browser sessions from `browser_sessions` table grouped by conversation_id (source="browser")
   - Browser sessions are synthesized into the same shape: `session_id="browser_{conv_id}"`, `model=service_name`, `total_turns=visit_count`, `total_duration=sum(duration_seconds)`
3. Alert counts are batch-fetched and joined

**`_api_stats()`** — Dashboard overview data:
- Token usage timeline (last 24h, grouped by hour, using `json_extract`)
- Tool usage breakdown (top 20)
- Model usage distribution
- Browser stats: today's visit count, 7-day daily breakdown by service

**`_api_browser_session_detail()`** — For a conversation, returns all visits plus temporally correlated network connections (connections to the service's known hosts within +/- 5 minutes of the visit window).

### BrokenPipeError Handling

The HTTP server catches `BrokenPipeError` at two levels:
1. In `do_GET()`: catches it around both the handler call and the error-response fallback
2. In `ReusableHTTPServer.handle_error()`: suppresses the socketserver traceback

This prevents log spam when the browser cancels polling requests.

## validators.py — Deep Pattern Validation

The validation pipeline sits between regex matching and alert storage. Each pattern type has a validator that returns `{valid, confidence, details, live}`.

**Key validators and their logic:**

| Validator | Key Check | Rejects |
|---|---|---|
| `validate_credit_card` | Luhn checksum + digit count | Numbers near JSON metadata keys, all-same-digit, failed Luhn |
| `validate_phone_number` | Proximity to ID keywords | Numbers within 50 chars of `sender_id`, `message_id`, `chat_id`, `telegram` |
| `validate_ssn` | Area/group/serial rules | `000-xx-xxxx`, `666-xx-xxxx`, `9xx-xx-xxxx`, `xxx-00-xxxx`, `xxx-xx-0000`, known test SSNs |
| `validate_password` | Shannon entropy | Placeholders ("changeme", "password"), entropy < 2.0, comments |
| `validate_jwt` | Header/payload base64 decode | Invalid base64, missing `alg` in header, non-JSON payload |
| `validate_aws_key` | Prefix + length + charset | Wrong prefix, not 20 chars, lowercase chars |
| `validate_db_connection` | URI parse + password entropy | No password, placeholder password, low entropy |

**Shannon entropy** measures randomness: `H = -sum(p * log2(p))`. Real passwords score > 3.0; placeholders like "changeme" score ~2.5.

**Luhn algorithm** validates credit card check digits. Catches token counts and request IDs that happen to match the card regex pattern.

## watch.py — Proxy-Mode Deep Capture

Runs as a mitmproxy addon for full request/response capture:

```
Claude Code -> HTTPS_PROXY=http://127.0.0.1:9080 -> mitmproxy
  -> WatchAddon.request() / .response()
    -> parse_request_body()  — extract messages, tools, model
    -> parse_response_body() — extract response content, usage
    -> parse_sse_response()  — handle streaming responses
    -> Write to CSV + store in api_calls table
```

Supports parsing for: Anthropic Messages API, OpenAI Chat Completions API, Google Gemini API.

## config.py — Configuration

TOML-based config at `~/.config/claude-monitoring/config.toml`:
- Dashboard port, bind address
- Proxy port, certificates
- MCP known servers list
- Output directory, database path

`load_config()` is the most-called function (56 callers) — it caches the parsed config at module level and supports `set_cli_overrides()` for command-line flag overrides.

## db.py — Database Layer

- Uses SQLite WAL mode for concurrent reads
- `get_thread_db()` returns a per-thread connection (thread-local storage)
- Schema migrations via `ALTER TABLE ... ADD COLUMN` with try/except (idempotent)
- Indexes on `events(session_id, event_type)`, `browser_sessions(conversation_id)`, etc.

## Data Flow Summary

```
[Claude Code]  -> JSONL files -> JSONLSessionWatcher -> events table
[OpenClaw]     -> JSONL files -> JSONLSessionWatcher -> events table (normalized)
[Chrome]       -> History DB  -> ChromeHistoryWatcher -> browser_sessions table
[Processes]    -> psutil      -> ProcessScanner -> processes table
[Network]      -> psutil      -> NetworkMonitor -> connections table
[Files]        -> watchdog    -> FileActivityHandler -> file_events table
[Proxy]        -> mitmproxy   -> WatchAddon -> api_calls table + CSV

All tables -> DashboardHandler (HTTP API) -> dashboard.html (SPA)
```
