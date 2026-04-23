# AI Runtime Monitor — Architecture v2

> Grounded in code and production database as of April 2026. 1,300 tests,
> 14,088 lines of Python, 3,034-line dashboard SPA, 20 database tables.

## What This System Does

AI Runtime Monitor provides CrowdStrike-style visibility into AI coding
agents running on developer machines. It answers: What are AI agents
reading, writing, executing, installing, and sending over the network —
and is any of it malicious?

```
                    +------------------------------------+
                    |     Web Dashboard :9081             |
                    |     3,034-line single-file SPA      |
                    |     10 tabs, 40+ API endpoints      |
                    +--------------+---------------------+
                                   | REST API (HTTP)
                    +--------------+---------------------+
                    |    DashboardHandler (monitor.py)     |
                    |    5,351 lines -- core engine         |
                    +--------------+---------------------+
                                   | SQLite (WAL mode)
                    +--------------+---------------------+
                    |         monitor.db (20 tables)       |
                    +--+---+---+---+---+---+---+---+---+-+
                       |   |   |   |   |   |   |   |   |
   +---------+ +------++ +-+---+ +-+-+ +-+--+ +-+------+ +-+---------+
   | Layer 1 | |L 2   | |L 3  | |L 4| |L 5 | |Supply  | |Threat    |
   | JSONL + | |File  | |Proc | |Chr.| |Ext.| |Chain   | |Intel     |
   | Proxy   | |Watch | |Scan | |Hist| |DOM | |792 ln  | |556 ln    |
   +---------+ +------+ +-----+ +---+ +----+ +--------+ +----------+
        |                                         |            |
   +----+-----+                              +----+----+  +----+---+
   | Claude   |                              |pip-audit|  |Threat |
   | Code     |                              |OSV.dev  |  |Fox    |
   | OpenClaw |                              |PyPI/npm |  |URLhaus|
   | Desktop  |                              |Registry |  |       |
   | Browser  |                              +---------+  +-------+
   +---------+
```

## Source Files

| File | Lines | Purpose |
|---|---|---|
| `monitor.py` | 5,351 | Core engine: monitoring layers, dashboard HTTP server, JSONL processing, 40+ API handlers, watchdog |
| `dashboard.html` | 3,034 | Single-file SPA: 10 tabs, Chart.js charts, session explorer, deep dive, activity summary |
| `watch.py` | 1,993 | mitmproxy addon for HTTPS proxy (port 9080), selective SSL inspection, service-specific parsers |
| `lifecycle.py` | 1,038 | PID management, heartbeat, crash telemetry, ProxyManager, orphan cleanup, LaunchAgent service |
| `supply_chain.py` | 792 | Package install parser (9 managers), risk scoring, environment inventory (pip+brew), SBOM export |
| `validators.py` | 598 | Deep validation: Luhn checksum, Shannon entropy, JWT decode, SSN rules |
| `threat_intel.py` | 556 | Registry metadata (PyPI/npm), ThreatFox/URLhaus CSV feeds, IOC matching, attack chain correlation |
| `security.py` | 416 | Custom CA generation (Name-Constrained), Keychain trust, file permissions, dashboard token |
| `vuln_scanner.py` | 398 | 6-phase scan pipeline: environment, pip-audit, OSV.dev, ThreatFox, URLhaus, registry |
| `status.py` | 394 | `--status` command: probe all layers, report health, JSON output |
| `config.py` | 267 | TOML config loading, CLI overrides, path resolution |
| `wizard.py` | 344 | First-run setup: CA generation, Keychain trust, system proxy opt-in, DB init |
| `constants.py` | 408 | AI_HOSTS (60+ hosts), SENSITIVE_PATTERNS (16), domain lists, process lists |
| `db.py` | 381 | SQLite schema (20 tables), migrations, thread-safe connections |
| `report.py` | 322 | Markdown/HTML/CSV report generation |
| `sync.py` | 226 | Background sync agent to fleet control plane |
| `utils.py` | 142 | scan_sensitive(), is_ai_process(), extract_urls() |

## How Each AI App Is Monitored

The honest truth table, verified against the production database:

```
                    JSONL    Proxy     Extension   Process
                   (content) (network) (DOM)       (detect)
Claude Code          ***       **        -           *
OpenClaw             ***       **        -           *
Claude Desktop        -        **        -          **
ChatGPT Desktop       -        **        -          **
Cursor                -         -        -          **
Chrome claude.ai      -        **       ***          -
Chrome chatgpt.com    -        **       ***          -
Chrome gemini.com     -        **       ***          -
Ollama                -         -        -          **

*** = full content   ** = metadata/detection   * = basic   - = none
```

**Key facts from the production DB (8,000+ api_calls rows):**

- Claude Desktop routes 100% of conversation traffic through `claude.ai`
  (web backend, SSE). The proxy captures metadata (host, path, status,
  sizes, latency) but NOT conversation content.
- ChatGPT Desktop routes through `chatgpt.com` — same: metadata only.
- Cursor bypasses the macOS system proxy entirely — zero captured rows.
- Claude Code's primary monitoring channel is JSONL file parsing (full
  content: prompts, responses, tool calls, tokens). The proxy adds
  network-level detail when configured but is not required.
- Browser AI (Chrome) content comes from the DOM-scraping extension, not
  the proxy. The proxy adds metadata for the same sessions.

## SSL Inspection

> Full details in `docs/SSL_INSPECTION.md`.

We run mitmproxy as a local HTTPS proxy on port 9080. It intercepts TLS
connections ONLY to 19 AI domains (controlled by `--allow-hosts`). All
other traffic tunnels through untouched.

**Why it works despite TLS protections:**

1. A per-machine CA with X.509 Name Constraints (restricts signing to
   AI domains only) is added to the macOS System Keychain.
2. Chrome exempts locally-installed root CAs from HSTS pin enforcement
   (same mechanism used by Zscaler/Netskope/CrowdStrike).
3. Node.js apps (Claude Code) need `NODE_EXTRA_CA_CERTS` env var because
   Node ignores the OS trust store.
4. `--set upstream_cert=false` prevents leaf cert SANs from violating the
   CA's Name Constraints (the *.chatgpt.com wildcard SAN bug).

**Two parsing tiers:**

| Tier | Domains | What we parse |
|------|---------|---------------|
| API (full) | `api.anthropic.com`, `api.openai.com`, + 12 more | Request/response JSON: model, tokens, prompts, tool calls, cost |
| Browser (metadata) | `claude.ai`, `chatgpt.com`, `gemini.google.com`, + 2 more | HTTP envelope only: host, path, status, sizes, latency. Bodies are SSE/protobuf — not parseable. |

## Monitoring Layers

### Layer 1a: JSONL Session Watcher

Watches Claude Code (`~/.claude/projects/`) and OpenClaw
(`~/.openclaw/agents/main/sessions/`) JSONL transcript files using
watchdog filesystem events.

```
JSONL file change -> watchdog event -> process_jsonl_file()
  -> read new bytes from persisted file position (survives restarts)
  -> json.loads() each line -> _process_record()
    -> dedup by UUID (_seen_uuids set)
    -> _process_user_message() / _process_assistant_message()
      -> _store_event() with SHA256 dedup hash (INSERT OR IGNORE)
      -> _check_sensitive() -> confidence scoring -> severity capping
      -> _check_supply_chain() -> parse install commands -> risk scoring
      -> _update_session_stats()
```

File positions persisted in `file_positions` table. Every event gets a
`dedup_hash` = SHA256(timestamp|session|type|data)[:16]. UNIQUE index
prevents duplicates at DB level.

### Layer 1b: Network Monitor

Scans TCP connections every 5 seconds via psutil. Matches against 60+
AI service hosts in `AI_HOSTS`. Stores in `connections` table.

### Layer 2: File Activity Monitor

Watchdog observer on project directories. Records creates, modifications,
deletes. Filters `.git/`, `__pycache__/`, `node_modules/`, `.tmp` files.

### Layer 3: Process Scanner

Scans all processes every 2 seconds. Two-tier matching: exact name
(`AI_PROCESS_EXACT`) then pattern with exclusions
(`AI_PROCESS_PATTERNS`). Creates synthetic desktop sessions for Electron
AI apps (Claude Desktop, ChatGPT Desktop, Cursor) via
`_ensure_desktop_session()`.

### Layer 4: Chrome History Watcher

Copies Chrome's locked History SQLite DB every 60 seconds. Extracts AI
site visits (ChatGPT, Claude, Gemini, Perplexity, Copilot). Converts
WebKit timestamps.

### Layer 5: Browser Extension

Chrome extension (Manifest V3) captures actual conversation content from
AI web interfaces via DOM observation (MutationObserver).

```
AI Web Page (DOM)
    | content script reads .textContent
Content Scripts (claude.js, chatgpt.js, gemini.js)
    | chrome.runtime.sendMessage()
Background Service Worker (background.js)
    | batch every 5s, max 100 events
POST http://127.0.0.1:9081/api/browser/ingest
    | stores content_text + event_type in browser_sessions
SQLite -> Dashboard Session Explorer
```

### Layer 6: HTTPS Proxy (watch.py)

mitmproxy addon on port 9080. Selective SSL inspection of 19 AI domains.
Two parsing tiers (API = full content, browser = metadata only).
Requires either `HTTPS_PROXY` env var (CLI tools) or macOS system proxy
(desktop Electron apps).

## Service Management

The monitor runs as a macOS LaunchAgent (`com.gocloudforge.ai-runtime-monitor`)
managed by `lifecycle.py`. Key components:

- **ProxyManager** — owns the mitmdump subprocess lifecycle (start, stop,
  restart with exponential backoff). Before spawning, scans `lsof -i :9080`
  for orphan mitmproxy processes and kills them (prevents EADDRINUSE crash
  loops).
- **Watchdog thread** — polls ProxyManager every 30s. If mitmdump died,
  disables system proxy (prevents orphaned MITM) and restarts with backoff.
  Restart counter only resets after 3 consecutive healthy polls.
- **Stale state detector** — on startup, checks for orphan PIDs, stuck
  system proxy, stale heartbeat files. Cleans up and logs to `crashes` table.
- **Install/restart/uninstall** — idempotent. `--install-service` detects
  existing installs, unloads, waits for PIDs, kills orphan mitmdump, loads
  fresh plist. `--restart` uses `launchctl kickstart -k` with orphan cleanup.

## Sensitive Data Detection Pipeline

```
Text input (any layer)
    |
scan_sensitive() [utils.py]
    -> regex match against 16 SENSITIVE_PATTERNS (constants.py)
    -> validator check (Luhn, entropy, JWT, SSN rules) [validators.py]
    -> returns: name, severity, category, matched_value, match_start
    |
_check_sensitive() [monitor.py]
    -> filter KNOWN_EXAMPLE_SECRETS
    -> filter phone_number when sender_id present (Telegram IDs)
    -> filter credit_card when API metadata keywords present
    -> _calculate_confidence():
        user_prompt -> "high"
        tool_result -> "high" (but "low" if /tests/ path)
        assistant_response -> always "low"
        tool:Bash -> "high" for aws/ssh/curl, "low" for git commit
    -> _cap_severity_by_confidence():
        low confidence -> severity capped at "low"
        medium -> capped at "medium"
        high -> passes through
    -> alert dedup: same (session, pattern, value[:20]) -> repeat_count++
```

## Supply Chain Monitoring

```
AI agent runs: pip install fastapi uvicorn
    |
Layer 1a captures tool_use event with command text
    |
_check_supply_chain() in monitor.py
    |
parse_install_command() [supply_chain.py]
    -> isolate install segment (split on |, &&, ;)
    -> strip redirects (2>&1, 2>/dev/null)
    -> handle docker-compose prefix
    -> parse tokens per manager (npm/pip/cargo/go/yarn/pnpm/brew/apt/npx/gem)
    -> validate: _is_valid_package_name() rejects shell noise
    -> categorize: "package" / "tool_exec" / "build_tool" / "metadata"
    |
assess_risk() -> score 0-10 with reasons
    +5 typosquat (30 known variants)
    +5 active critical CVE
    +3 high-risk package (mitmproxy, cryptography, paramiko, etc.)
    +3 npx remote execution
    +2 financial API (alpaca-trade-api, stripe, plaid)
    +1 unpinned (no version specified)
    |
store_dependency() -> INSERT OR IGNORE into agent_dependencies
    |
Alerts: typosquat -> CRITICAL, high-risk unpinned -> HIGH
```

## Vulnerability Intelligence

6-phase scan pipeline (`vuln_scanner.py::run_full_scan`):

| Phase | Source | What it does |
|-------|--------|--------------|
| 0 | environment | `pip list` + `brew list` -> `environment_packages` (183 rows) |
| 1 | pip-audit | `pip-audit --format=json` -> `package_vulnerabilities` |
| 2 | osv | Query `api.osv.dev/v1/query` per agent-installed package. Detects MAL- prefix as malicious. 6h cache, 0.5s rate limit. |
| 3 | threatfox | GET `threatfox.abuse.ch/export/csv/recent/` -> `threat_iocs` (IP + domain IOCs) |
| 4 | urlhaus | GET `urlhaus.abuse.ch/downloads/csv_recent/` -> `threat_iocs` (malicious URL hostnames) |
| 5 | registry | Count cached PyPI/npm metadata rows |

Runs async in a daemon thread. Dashboard polls progress every 1s.
Environment enumerators use `sys.executable -m pip` and absolute brew
paths for launchd safety.

**Intel source health:** 4-state dots (green/yellow/red/gray) driven by
`intel_source_status` table. Green = success within 24h. Red = last
fetch failed. Gray = never fetched.

## Threat Intelligence

```
threat_intel.py:
    +-- Registry metadata enrichment
    |   fetch_pypi_metadata() / fetch_npm_metadata()
    |   -> package age, author, install scripts, maintainer changes
    |   -> assess_registry_risk(): age <24h (+4), postinstall (+2), etc.
    |   -> cached in package_registry_cache
    |
    +-- ThreatFox IOC feed (public CSV export, no API key)
    |   GET https://threatfox.abuse.ch/export/csv/recent/
    |   -> IP:port pairs + domains + malware family
    |   -> stored in threat_iocs table
    |
    +-- URLhaus malicious domains (public CSV export, no API key)
    |   GET https://urlhaus.abuse.ch/downloads/csv_recent/
    |   -> active malicious URL hostnames, cap 500/pull
    |   -> stored in threat_iocs table
    |
    +-- IOC matching
    |   check_connection_against_iocs(remote_host, db)
    |   -> exact IP -> exact domain -> subdomain walk
    |
    +-- Attack chain correlation
        correlate_install_to_connection(session_id, timestamp, host, db)
        -> package install within 60s before IOC-matched connection
        -> same session required
        -> kill chain: install -> execute -> exfiltrate
```

## Database Schema (20 tables)

| Table | Rows | Purpose |
|-------|------|---------|
| `events` | 145K | All events from all layers, dedup_hash UNIQUE |
| `sessions` | 55 | Agent sessions with title, model, tokens, risk |
| `api_calls` | 8K | Proxy-captured API traffic + JSONL-derived token rows |
| `agent_dependencies` | 106 | Parsed package installs with risk scoring |
| `environment_packages` | 183 | Full pip+brew inventory from environment scan |
| `package_vulnerabilities` | 103 | CVE data from pip-audit + OSV |
| `threat_iocs` | 3.5K | ThreatFox + URLhaus indicators |
| `intel_source_status` | 6 | Per-source health (environment, pip-audit, osv, threatfox, urlhaus, registry) |
| `scan_history` | 13 | Vulnerability scan metadata |
| `package_registry_cache` | 4 | PyPI/npm metadata cache |
| `package_watchlist` | 33 | Auto-populated monitoring priorities |
| `package_maintainer_history` | 0 | npm publisher change tracking |
| `browser_sessions` | 188 | Chrome history + extension captures |
| `extension_heartbeats` | 3 | Chrome extension liveness |
| `connections` | 24K | Network connections to AI hosts |
| `processes` | 1.3K | AI process lifecycle |
| `file_events` | 572K | File creates/modifies/deletes |
| `file_positions` | 1K | Persisted byte offsets for JSONL files |
| `alert_dismissals` | 0 | Dismissed alerts with reason codes |
| `crashes` | 25 | Crash telemetry (stale PIDs, orphans, stuck proxy) |

## Dashboard (10 tabs)

| Tab | Purpose | Key Features |
|---|---|---|
| **Overview** | KPI cards + charts | Sessions (active count), agents (breakdown), tokens, burn rate ($/day), alerts (critical count) |
| **Session Explorer** | Browse + deep dive | Risk borders, active section, Deep Dive cockpit with turn navigation, desktop activity summary with daily charts |
| **Live Feed** | Real-time event stream | Newest-first, click-to-Deep Dive, type filter, connection batching |
| **Analytics** | Charts + MCP stats | Token timeline, tool donut, model names, burn rate with runway |
| **Insights** | Project analytics | Most-read files, project breakdown, efficiency metrics |
| **System** | Process + network + files | Grouped by app, version-to-name resolution, EC2-to-region |
| **API Traffic** | Proxy-captured calls | Deduped, sensitive filter, cache/cost/stop in detail, sort |
| **Activity Timeline** | Cross-source timeline | Date separators, alert styling, source filter |
| **Supply Chain** | Dependency monitoring | 5 views (grouped, environment, tools), CVE panel, registry intel, risk scoring, 6-source intel bar, async scan with progress |
| **Alerts** | Security findings | Confidence badges, investigation cards for supply-chain alerts, Copy Report, View Package/Session deep links, dismiss with reasons |

## API Endpoints (40+)

**GET:**
`/api/stats` `/api/sessions` `/api/session/{id}` `/api/session/{id}/turns`
`/api/feed` `/api/processes` `/api/connections` `/api/files` `/api/alerts`
`/api/browser` `/api/browser/sessions` `/api/browser/session/{id}`
`/api/activity/timeline` `/api/traffic` `/api/traffic/stats`
`/api/mcp/stats` `/api/mcp/servers` `/api/insights`
`/api/insights/projects` `/api/insights/efficiency` `/api/export`
`/api/report` `/api/supply-chain` `/api/supply-chain/detail`
`/api/supply-chain/environment` `/api/supply-chain/scan-status`
`/api/supply-chain/scan-progress` `/api/supply-chain/intel-status`
`/api/supply-chain/registry` `/api/supply-chain/sbom`
`/api/supply-chain/watchlist`

**POST:**
`/api/alerts/dismiss` `/api/browser/ingest` `/api/supply-chain/scan`
`/api/supply-chain/intel-refresh`

## Fleet Control Plane (Docker)

```
+----------------------------------------------------------+
|                 CONTROL PLANE (Docker)                     |
|   +----------------+    +----------------+               |
|   | FastAPI :9090   |--->| Fleet Dashboard |               |
|   | (cp/app.py)     |    | fleet_dashboard |               |
|   +-------+--------+    | .html           |               |
|           |              +----------------+               |
|   +-------v--------+                                     |
|   | Postgres 16     |                                     |
|   | 6 fleet tables  |                                     |
|   +----------------+                                     |
+----------------------------------------------------------+
        ^                              ^
        | POST /api/v1/ingest          |
  +-----+----------+        +---------+----------+
  | Mac agent      |        | Docker TestClient   |
  | sync.py        |        | simulate_endpoint   |
  | every 30s      |        | .py                 |
  +----------------+        +--------------------+
```

## Test Coverage

1,300 tests across 39 test files:
- `test_jsonl_watcher.py` — JSONL processing, OpenClaw, sensitive data, dedup
- `test_api.py` — all dashboard API endpoints
- `test_watch_parsing.py` — API response parsing (Anthropic, OpenAI SSE)
- `test_validators.py` — Luhn, entropy, all 12 validators
- `test_supply_chain.py` — parsing, risk, categorization, backfill, environment enumerators
- `test_threat_intel.py` — registry metadata, IOC feeds, correlation
- `test_vuln_scanner.py` — pip-audit, OSV, CVSS, environment phase
- `test_lifecycle.py` — PID files, heartbeat, ProxyManager, orphan cleanup
- `test_security_hardening.py` — auth, token validation, file permissions
- `test_supply_chain_ux.py` — intel state machine, async scan, alert enrichment
- `test_desktop_deep_dive.py` — desktop activity summary, traffic_captured flag
- `test_abuse_ch_csv.py` — ThreatFox/URLhaus CSV parsers
- `test_status.py` — status probe, cert trust, permissions
- And 26 more test files covering config, utils, monitor, report, chrome, watch, etc.

## CLI Usage

```bash
# First-time setup (generates CA, trusts it, initializes DB)
ai-monitor --setup

# Install as LaunchAgent (starts on login, auto-restarts on crash)
ai-monitor --install-service --with-system-proxy

# Restart (kills orphan mitmdump, clean relaunch)
ai-monitor --restart

# Status (probes all layers, reports health)
ai-monitor --status
ai-monitor --status --json

# Uninstall (stops service, disables proxy, removes plist)
ai-monitor --uninstall-service

# Standalone (no LaunchAgent)
ai-monitor --start --with-proxy
```

## What Makes This Different

No existing security tool (CrowdStrike, Datadog, Wiz) monitors AI agents
at this level:

1. **Session-level tracing** — every prompt, response, tool call, and
   token usage linked to a session with a Deep Dive cockpit
2. **Supply chain monitoring** — every package an AI agent installs,
   parsed from 9 package managers, with typosquat detection and risk
   scoring
3. **Vulnerability intelligence** — 6-phase scan pipeline (environment
   inventory + pip-audit + OSV.dev + ThreatFox + URLhaus + registry)
   with per-source health indicators
4. **SSL inspection with Name Constraints** — per-machine CA restricted
   to 19 AI domains at the X.509 level, not application level
5. **Attack chain correlation** — package install + malicious connection
   within 60 seconds = supply chain attack detected
6. **Desktop app activity monitoring** — Claude Desktop, ChatGPT Desktop
   process detection + proxy metadata + daily activity summaries
7. **Browser AI capture** — DOM-based content capture via Chrome extension
   for ChatGPT, Claude, Gemini web interfaces
8. **Crash-resilient service** — LaunchAgent with watchdog, orphan cleanup,
   auto-disable system proxy on crash, stale state detection on startup
9. **Confidence-scored alerts** — every alert has high/medium/low
   confidence with false positive tagging
