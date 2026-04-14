# AI Runtime Monitor — Architecture v2

> Grounded in actual implementation as of April 2026. 962 tests, 9,234 lines of Python, 2,310-line dashboard SPA, 17 database tables.

## What This System Does

AI Runtime Monitor provides CrowdStrike-style visibility into AI coding agents running on developer machines. It answers: What are AI agents reading, writing, executing, installing, and sending over the network — and is any of it malicious?

```
                    ┌────────────────────────────────────┐
                    │     Web Dashboard :9081             │
                    │     2,310-line single-file SPA      │
                    │     10 tabs, 30+ API endpoints      │
                    └──────────────┬─────────────────────┘
                                   │ REST API (HTTP)
                    ┌──────────────┴─────────────────────┐
                    │    DashboardHandler (monitor.py)     │
                    │    4,008 lines — core engine          │
                    └──────────────┬─────────────────────┘
                                   │ SQLite (WAL mode)
                    ┌──────────────┴─────────────────────┐
                    │         monitor.db (17 tables)       │
                    └───┬───┬───┬───┬───┬───┬───┬───┬───┘
                        │   │   │   │   │   │   │   │
    ┌───────────┐ ┌─────┴┐ ┌┴────┐ ┌┴───┐ ┌┴────┐ ┌┴────────┐ ┌┴──────────┐
    │ Layer 1a  │ │L 1b  │ │L 2  │ │L 3 │ │L 4  │ │Supply   │ │Threat     │
    │ JSONL     │ │Net   │ │File │ │Proc│ │Chrome│ │Chain    │ │Intel      │
    │ Watcher   │ │Mon   │ │Watch│ │Scan│ │Hist  │ │466 lines│ │287 lines  │
    └───────────┘ └──────┘ └─────┘ └────┘ └─────┘ └─────────┘ └───────────┘
         │                                              │            │
    ┌────┴────┐                                    ┌────┴────┐  ┌───┴───┐
    │ Claude  │                                    │pip-audit│  │Threat │
    │ Code    │                                    │OSV.dev  │  │Fox    │
    │ OpenClaw│                                    │PyPI/npm │  │URLhaus│
    │ JSONL   │                                    │Registry │  │       │
    └─────────┘                                    └─────────┘  └───────┘
```

## Source Files

| File | Lines | Purpose |
|---|---|---|
| `monitor.py` | 4,008 | Core engine: all monitoring layers, dashboard HTTP server, JSONL processing, all API handlers |
| `dashboard.html` | 2,310 | Single-file SPA: 10 tabs, Chart.js charts, session explorer, deep dive cockpit |
| `watch.py` | 1,859 | mitmproxy addon for HTTPS proxy capture (optional, port 9080) |
| `validators.py` | 596 | Deep validation: Luhn checksum, Shannon entropy, JWT decode, SSN rules |
| `supply_chain.py` | 466 | Package install parser (9 managers), risk scoring, environment inventory |
| `constants.py` | 408 | AI_HOSTS, SENSITIVE_PATTERNS, BROWSER_AI_PATTERNS, process lists |
| `db.py` | 381 | SQLite schema (17 tables), migrations, thread-safe connections |
| `report.py` | 320 | Markdown/HTML/CSV report generation |
| `threat_intel.py` | 287 | Registry metadata (PyPI/npm), ThreatFox/URLhaus IOC feeds, IOC matching, attack chain correlation |
| `vuln_scanner.py` | 272 | pip-audit integration, OSV.dev API queries, CVSS parsing, vulnerability storage |
| `config.py` | 267 | TOML config loading, CLI overrides, path resolution |
| `sync.py` | 224 | Background sync agent to fleet control plane |
| `utils.py` | 140 | scan_sensitive(), is_ai_process(), extract_urls() |

## Monitoring Layers

### Layer 1a: JSONL Session Watcher (`JSONLSessionWatcher`)

Watches Claude Code (`~/.claude/projects/`) and OpenClaw (`~/.openclaw/agents/main/sessions/`) JSONL transcript files using watchdog filesystem events.

**Data flow:**
```
JSONL file change → watchdog event → process_jsonl_file()
  → read new bytes from persisted file position (survives restarts)
  → json.loads() each line → _process_record()
    → dedup by UUID (_seen_uuids set)
    → _process_user_message() / _process_assistant_message()
      → _store_event() with SHA256 dedup hash (INSERT OR IGNORE)
      → _check_sensitive() → confidence scoring → severity capping
      → _check_supply_chain() → parse install commands → risk scoring
      → _update_session_stats()
```

**Key implementation details:**
- File positions persisted in `file_positions` table (solved the 36x duplication bug)
- Every event gets a `dedup_hash` = SHA256(timestamp|session|type|data)[:16]
- UNIQUE index on `dedup_hash` prevents duplicates at DB level
- `_clean_title()` strips markdown, HTML tags, metadata prefixes from 11 known patterns

### Layer 1b: Network Monitor (`NetworkMonitor`)

Scans TCP connections every 5 seconds via psutil. Matches against 25+ AI service hosts in `AI_HOSTS`.

### Layer 2: File Activity Monitor (`FileActivityHandler`)

Watchdog observer on project directories. Records creates, modifications, deletes. Filters `.git/`, `__pycache__/`, `node_modules/`, `.tmp` files.

### Layer 3: Process Scanner (`ProcessScanner`)

Scans all processes every 2 seconds. Two-tier matching: exact name (`AI_PROCESS_EXACT`) then pattern with exclusions (`AI_PROCESS_PATTERNS`). Tracks lifecycle, CPU%, memory%.

### Layer 4: Chrome History Watcher (`ChromeHistoryWatcher`)

Copies Chrome's locked History SQLite DB every 60 seconds. Extracts AI site visits (ChatGPT, Claude, Gemini, Perplexity, Copilot). Converts WebKit timestamps.

### Layer 5: Browser Extension

Chrome extension (Manifest V3) captures actual conversation content from AI web interfaces via DOM observation (MutationObserver). NOT network interception.

```
AI Web Page (DOM)
    ↓ content script reads .textContent
Content Scripts (claude.js, chatgpt.js, gemini.js)
    ↓ chrome.runtime.sendMessage()
Background Service Worker (background.js)
    ↓ batch every 5s, max 100 events
POST http://127.0.0.1:9081/api/browser/ingest
    ↓ stores content_text + event_type in browser_sessions
SQLite → Dashboard Session Explorer
```

### Layer 6: HTTPS Proxy (Optional)

mitmproxy addon (`watch.py`) on port 9080. Full request/response capture for Anthropic, OpenAI, Google, and other AI APIs. Requires `HTTPS_PROXY=http://127.0.0.1:9080`.

## Sensitive Data Detection Pipeline

```
Text input (any layer)
    ↓
scan_sensitive() [utils.py]
    → regex match against 16 SENSITIVE_PATTERNS (constants.py)
    → validator check (Luhn, entropy, JWT, SSN rules) [validators.py]
    → returns: name, severity, category, matched_value, match_start
    ↓
_check_sensitive() [monitor.py]
    → filter KNOWN_EXAMPLE_SECRETS
    → filter phone_number when sender_id present (Telegram IDs)
    → filter credit_card when API metadata keywords present
    → _calculate_confidence():
        user_prompt → "high"
        tool_result → "high" (but "low" if /tests/ path)
        assistant_response → always "low"
        tool:Bash → "high" for aws/ssh/curl, "low" for git commit/sql cleanup
    → _cap_severity_by_confidence():
        low confidence → severity capped at "low"
        medium → capped at "medium"
        high → passes through
    → alert dedup: same (session, pattern, matched_value[:20]) → increment repeat_count
    → store: patterns, severity, confidence, matched_value, match_context, likely_false_positive
```

**Result:** 38% reduction in CRITICAL alerts, 575 false positives identified and flagged.

## Supply Chain Monitoring

```
AI agent runs: pip install fastapi uvicorn
    ↓
Layer 1a captures tool_use event with command text
    ↓
_check_supply_chain() in monitor.py
    ↓
parse_install_command() [supply_chain.py]
    → isolate install segment (split on |, &&, ;)
    → strip redirects (2>&1, 2>/dev/null)
    → handle docker-compose prefix
    → parse tokens per manager (npm/pip/cargo/go/yarn/pnpm/brew/apt/npx/gem)
    → validate: _is_valid_package_name() rejects shell noise, short words, punctuation
    → categorize: "package" / "tool_exec" / "build_tool" / "metadata"
    ↓
assess_risk() → score 0-10 with reasons
    +5 typosquat (30 known variants)
    +3 high-risk package (mitmproxy, cryptography, paramiko, selenium, etc.)
    +3 npx remote execution
    +2 financial API (alpaca-trade-api, stripe, plaid)
    +1 unpinned (no version specified)
    ↓
store_dependency() → INSERT OR IGNORE into agent_dependencies
    ↓
Alerts: typosquat → CRITICAL, high-risk unpinned → HIGH
```

**Current data:** 333 entries (115 packages, 167 tool executions, 27 build tools, 23 metadata)

## Vulnerability Intelligence

```
POST /api/supply-chain/scan
    ↓
run_full_scan() [vuln_scanner.py]
    ├── pip-audit (local, no network for Python)
    │   → parses JSON output → vuln_id, fix_version, description
    │
    └── OSV.dev API (per-package, all ecosystems)
        → POST https://api.osv.dev/v1/query
        → extracts: CVSS from database_specific.severity
        → flags MAL- prefix as severity "malicious" (OpenSSF 15K+ packages)
        → rate limited: 0.5s/req, cached 6 hours
    ↓
store_vuln() → INSERT OR IGNORE into package_vulnerabilities (UNIQUE on pkg+ver+vuln)
    ↓
API enrichment: /api/supply-chain grouped view includes vulnerabilities per package
Dashboard: CVE badge (red "8 CVEs"), expandable detail with osv.dev links, fix versions
```

**Current data:** 119 vulnerabilities across 19 packages (14 critical, 37 high, 19 medium, 6 low)

## Threat Intelligence

```
threat_intel.py:
    ├── Registry metadata enrichment
    │   fetch_pypi_metadata() / fetch_npm_metadata()
    │   → package age, downloads, author, description, repo, install scripts, license
    │   → assess_registry_risk(): age <24h (+4), <7d (+2), no desc+repo (+2), postinstall (+2)
    │   → cached in package_registry_cache (24h TTL)
    │
    ├── ThreatFox IOC feed (public CSV export, no API key)
    │   GET https://threatfox.abuse.ch/export/csv/recent/
    │   → recent IOCs: IP:port pairs + domains + malware family
    │   → stored in threat_iocs table
    │
    ├── URLhaus malicious domains (public CSV export, no API key)
    │   GET https://urlhaus.abuse.ch/downloads/csv_recent/
    │   → active malicious URL hostnames
    │   → stored in threat_iocs table
    │
    ├── IOC matching
    │   check_connection_against_iocs(remote_host, db)
    │   → exact IP match → exact domain match → subdomain match
    │
    └── Attack chain correlation
        correlate_install_to_connection(session_id, timestamp, host, db)
        → finds package install within 60 seconds before IOC-matched connection
        → same session required
        → produces kill chain: install → execute → exfiltrate
```

## Database Schema (17 tables)

```sql
events (329K rows)        — all events from all layers, dedup_hash UNIQUE
sessions (85 rows)        — agent sessions with title, model, tokens, risk
agent_dependencies (333)  — parsed package installs with risk scoring
environment_packages (183)— full pip+brew inventory
package_vulnerabilities (119) — CVE data from pip-audit + OSV
scan_history (4)          — vulnerability scan metadata
threat_iocs (0)           — ThreatFox + URLhaus indicators
package_registry_cache    — PyPI/npm metadata cache
browser_sessions (760)    — Chrome history + extension captures
api_calls (480)           — proxy-captured API traffic
connections               — network connections to AI hosts
processes                 — AI process lifecycle
file_events               — file creates/modifies/deletes
file_positions (1063)     — persisted byte offsets for JSONL files
alert_dismissals (3)      — dismissed alerts with reason codes
sync_state                — control plane sync watermarks
```

## Dashboard (10 tabs)

| Tab | Purpose | Key Features |
|---|---|---|
| **Overview** | KPI cards + charts | Sessions (active count), agents (breakdown), tokens, burn rate ($/day), alerts (critical count), browser services |
| **Session Explorer** | Browse + deep dive | Risk borders, clean titles, active section, Deep Dive cockpit with turn navigation, secret masking, context window gauge |
| **Live Feed** | Real-time event stream | Newest-first, click→Deep Dive, sessions-only default, type filter, severity coloring, connection batching |
| **Analytics** | Charts + MCP stats | Token timeline (midnight labels), tool donut (Top 8+Other), model names human-readable, burn rate with runway |
| **Insights** | Project analytics | Most-read files, project breakdown, efficiency metrics |
| **System** | Process + network + files | Grouped by app (expand/collapse), aggregates, version→name resolution, EC2→region, temp filter |
| **API Traffic** | Proxy-captured calls | Deduped, sensitive filter toggle, cache/cost/stop in detail, sort, Log/Live source labels |
| **Activity Timeline** | Cross-source timeline | Date separators, alert styling, filter count, source filter |
| **Supply Chain** | Dependency monitoring | 5 category views, grouped+expand, CVE panel, registry intel panel, risk scoring, threat intel bar |
| **Alerts** | Security findings | Confidence badges, human summaries, matched value with Reveal, dismiss with reasons, false positive filter |

## API Endpoints (30+)

**GET:**
`/api/stats` `/api/sessions` `/api/session/{id}` `/api/session/{id}/turns` `/api/feed` `/api/processes` `/api/connections` `/api/files` `/api/alerts` `/api/browser` `/api/browser/sessions` `/api/browser/session/{id}` `/api/activity/timeline` `/api/traffic` `/api/traffic/stats` `/api/mcp/stats` `/api/mcp/servers` `/api/insights` `/api/insights/projects` `/api/insights/efficiency` `/api/export` `/api/report` `/api/supply-chain` `/api/supply-chain/detail` `/api/supply-chain/scan-status` `/api/supply-chain/environment` `/api/supply-chain/intel-status` `/api/supply-chain/registry`

**POST:**
`/api/alerts/dismiss` `/api/browser/ingest` `/api/supply-chain/scan`

## Fleet Control Plane (Docker)

```
┌──────────────────────────────────────────────────────────┐
│                 CONTROL PLANE (Docker)                     │
│   ┌────────────────┐    ┌────────────────┐               │
│   │ FastAPI :9090   │───▶│ Fleet Dashboard │               │
│   │ (cp/app.py)     │    │ fleet_dashboard │               │
│   └───────┬────────┘    │ .html           │               │
│           │              └────────────────┘               │
│   ┌───────▼────────┐                                     │
│   │ Postgres 16     │                                     │
│   │ 6 fleet tables  │                                     │
│   └────────────────┘                                     │
└──────────────────────────────────────────────────────────┘
        ▲                              ▲
        │ POST /api/v1/ingest          │
  ┌─────┴──────────┐        ┌─────────┴──────────┐
  │ Mac-3333       │        │ Docker-TestClient   │
  │ sync.py agent  │        │ simulate_endpoint   │
  │ every 30s      │        │ .py                 │
  └────────────────┘        └────────────────────┘
```

## Test Coverage

962 tests across 21 test files:
- `test_jsonl_watcher.py` — 136 tests (JSONL processing, OpenClaw, sensitive data, dedup)
- `test_api.py` — 84 tests (all dashboard API endpoints)
- `test_watch_parsing.py` — 80 tests (API response parsing)
- `test_validators.py` — 85 tests (Luhn, entropy, all 12 validators)
- `test_supply_chain.py` — 58 tests (parsing, risk, categorization, backfill)
- `test_threat_intel.py` — 21 tests (registry, IOC feeds, correlation)
- `test_vuln_scanner.py` — 16 tests (pip-audit, OSV, CVSS)
- `test_detection_pipeline.py` — 15 tests (confidence, severity capping, dedup)
- `test_bug_fixes.py` — 12 tests (CVSS parsing, confidence filter, titles)
- `test_environment.py` — 7 tests (pip/brew inventory, cross-ref)
- And 11 more test files covering config, utils, monitor, report, chrome, etc.

## CLI Usage

```bash
# Standalone monitoring + dashboard
ai-monitor --start

# With HTTPS proxy for deep API capture
ai-monitor --start --with-proxy

# With fleet control plane sync
ai-monitor --start --with-proxy \
  --control-plane http://localhost:9090 \
  --cp-api-key <key>

# One-shot process scan
ai-monitor --scan
```

## What Makes This Different

No existing security tool (CrowdStrike, Datadog, Wiz) monitors AI agents at this level:

1. **Session-level tracing** — every user prompt, assistant response, tool call, and token usage linked to a session with a Deep Dive cockpit
2. **Supply chain monitoring** — every package an AI agent installs, parsed from 9 package managers, with typosquat detection and risk scoring
3. **Vulnerability intelligence** — pip-audit + OSV.dev scanning with CVSS scores, CVE detail panels, and remediation commands
4. **Attack chain correlation** — package install + malicious connection within 60 seconds in the same session = supply chain attack detected
5. **Context window gauge** — token saturation monitoring with overflow warnings (no competitor has this)
6. **MCP server discovery** — detects Model Context Protocol servers used by agents
7. **Browser AI capture** — DOM-based content capture from ChatGPT, Claude, Gemini web interfaces
8. **Confidence-scored alerts** — every alert has high/medium/low confidence with false positive tagging, reducing noise by 38%
