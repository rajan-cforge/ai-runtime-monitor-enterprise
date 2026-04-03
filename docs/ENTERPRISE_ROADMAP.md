# AI Runtime Monitor — Enterprise Roadmap

> Plan-only document. No implementation yet. Each item includes files, approach, effort, tests, and security considerations.

---

## Phase 1: Fix and Polish

### Item 1: API Traffic Gap — OpenClaw Calls Missing from Proxy

**Priority:** P1
**Effort:** M (2-4 hrs)
**Files to create/modify:**
- `docs/PROXY_OPENCLAW_SETUP.md` (create) — setup guide
- `src/claude_monitoring/monitor.py` — Option C: extract API metadata from JSONL
- `src/claude_monitoring/constants.py` — add OpenClaw JSONL API extraction patterns
- `tests/test_jsonl_watcher.py` — tests for API metadata extraction from OpenClaw records

**Dependencies:** None (first item)

**Root Cause Analysis:**
The OpenClaw gateway runs as a macOS LaunchAgent (`~/Library/LaunchAgents/ai.openclaw.gateway.plist`). Its `EnvironmentVariables` block does not include `HTTPS_PROXY`. The process is started by `launchd`, not from the user's shell, so it never inherits the shell's `HTTPS_PROXY=http://127.0.0.1:9080`. Confirmed: only 35 api_calls exist (all from March 5 when Claude Code was using the proxy from a shell session), zero from OpenClaw.

**Fix Options (implement all three, document trade-offs):**

Option A — Inject `HTTPS_PROXY` into the LaunchAgent plist:
```bash
# Add to EnvironmentVariables in ai.openclaw.gateway.plist:
#   "HTTPS_PROXY" => "http://127.0.0.1:9080"
# Then: launchctl unload/load the plist
```
Pros: Full API traffic capture (request/response bodies, streaming). Cons: Requires the user to modify the plist and reload the daemon. Breaks if proxy isn't running. Needs CA cert trust for HTTPS interception (`NODE_EXTRA_CA_CERTS` is already set in the plist, but to system certs, not mitmproxy's CA).

Option B — Configure Node.js proxy at the OpenClaw level:
Check if OpenClaw or its underlying Anthropic SDK respects `ANTHROPIC_PROXY` or `HTTP_PROXY` at the application config level. The gateway uses the Anthropic Node SDK which reads `ANTHROPIC_BASE_URL` but does not natively support `HTTPS_PROXY`. Would require OpenClaw to add proxy support.
Pros: Clean. Cons: Depends on OpenClaw upstream.

Option C — Extract API call metadata from OpenClaw JSONL (recommended first step):
OpenClaw JSONL already contains rich API metadata in assistant message records:
```json
"usage": {"input":3, "output":93, "cacheRead":0, "cacheWrite":13257, "totalTokens":13353,
          "cost":{"input":0.000009, "output":0.001395, "total":0.05111775}},
"model": "claude-sonnet-4-6",
"api": "anthropic-messages",
"provider": "anthropic",
"responseId": "msg_011ZhHTxqvHCvcMeNUNbidg3"
```
In `_process_assistant_message()` (OpenClaw path), extract these fields and INSERT into `api_calls` table with: `destination_host="api.anthropic.com"`, `destination_service="anthropic_api"`, `model`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `estimated_cost_usd=cost.total`, `response_id=responseId`. This gives us token-level API visibility without proxy interception.

**Approach:** Implement Option C first (no proxy dependency), document Options A and B in the setup guide.

**Test Plan:**
- Unit test: process a real OpenClaw assistant JSONL record, verify api_calls row created with correct fields
- Unit test: verify Claude Code JSONL path does NOT create api_calls (that still comes from proxy)
- Integration test: backfill the real OpenClaw JSONL file, verify api_calls count matches assistant message count
- Verify: `SELECT COUNT(*), destination_host FROM api_calls GROUP BY destination_host` shows OpenClaw entries

**Security Considerations:**
- Option A (proxy): mitmproxy MITM requires CA trust. If CA is compromised, all HTTPS traffic is interceptable. Document that the mitmproxy CA cert should be restricted and never committed to git.
- Option C (JSONL): No new attack surface — same JSONL files already processed. Cost data in JSONL is calculated by OpenClaw, not verified by us.

**Demo Impact:** API Traffic tab goes from showing stale March 5 data to showing live OpenClaw API calls with model, tokens, and cost. Major credibility improvement.

---

### Item 2: Dashboard Agent Badges

**Priority:** P1
**Effort:** M (3-5 hrs)
**Files to create/modify:**
- `src/claude_monitoring/constants.py` — add `AGENT_TYPE_MAP` dict
- `src/claude_monitoring/monitor.py` — add `_detect_agent_type()` method, set agent_type on session
- `src/claude_monitoring/db.py` — add `agent_type TEXT` column migration to sessions table
- `src/claude_monitoring/dashboard.html` — badge CSS, badge rendering, agent type filter dropdown
- `tests/test_jsonl_watcher.py` — agent type detection tests
- `tests/test_monitor_main.py` — dashboard API returns agent_type field

**Dependencies:** None

**Approach:**

1. Agent type detection in `constants.py`:
```python
AGENT_TYPE_MAP = {
    # cwd pattern -> (agent_type, color, label)
    ".openclaw": ("openclaw", "#238636", "OpenClaw"),
    ".claude": ("claude_code", "#2563eb", "Claude Code"),
    ".cursor": ("cursor", "#7c3aed", "Cursor"),
    ".codex": ("codex", "#ea580c", "Codex"),
}
AGENT_TYPE_COLORS = {
    "openclaw": "#238636",      # green
    "claude_code": "#2563eb",   # blue
    "cursor": "#7c3aed",        # purple
    "chatgpt": "#ea580c",       # orange
    "copilot": "#0891b2",       # teal
    "unknown": "#6b7280",       # gray
}
```

2. In `_ensure_session()` or `_process_record()`, detect agent type from:
   - `cwd` path (contains `.openclaw` -> openclaw, `.claude` -> claude_code)
   - `jsonl_path` (under `~/.openclaw/` vs `~/.claude/`)
   - `model` field (contains service hint)
   Store in new `agent_type` column on sessions table.

3. In `dashboard.html`:
   - Add badge CSS per agent type (colored pill badges)
   - Replace the existing simple `openclaw-badge` with the generalized system
   - Add agent type filter dropdown in Session Explorer header (next to source filter)
   - Strip Telegram metadata from displayed titles (already done in `_set_session_title`, but need to also handle the API response where raw text might still appear)

4. For browser sessions, set agent_type based on service: ChatGPT -> "chatgpt", Claude Web -> "claude_web", etc.

**Test Plan:**
- Unit: `_detect_agent_type("/Users/x/.openclaw/workspace")` returns "openclaw"
- Unit: `_detect_agent_type("/Users/x/Projects/myapp")` returns "claude_code" (if JSONL is under .claude)
- Unit: sessions API response includes `agent_type` field
- Snapshot: badge HTML renders correctly for each agent type
- E2E (future): dashboard shows colored badges

**Security Considerations:**
- Agent type is derived from filesystem paths. Path traversal is not a concern since we only read the path, never use it for file access in this context.
- New DB column with migration — ensure migration is idempotent.

**Demo Impact:** Session Explorer immediately communicates what tool generated each session. Color coding makes it scannable at a glance. Filter lets users focus on one tool.

---

### Item 3: Alerts Tab Overhaul

**Priority:** P2
**Effort:** L (6-8 hrs)
**Files to create/modify:**
- `src/claude_monitoring/db.py` — add `alert_dismissals` table, `alerts` view
- `src/claude_monitoring/monitor.py` — new API endpoints: `POST /api/alerts/dismiss`, `GET /api/alerts` (enhanced), `_check_sensitive` adds `validated` flag
- `src/claude_monitoring/dashboard.html` — alerts tab redesign: grouping, confidence badges, dismiss button, severity counts in tab header
- `tests/test_jsonl_watcher.py` — dismiss persistence tests
- `tests/test_api.py` — alerts endpoint tests

**Dependencies:** Item 1 (validators are already in place from validators.py)

**Approach:**

1. New `alert_dismissals` table:
```sql
CREATE TABLE alert_dismissals (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL,
    dismissed_at TEXT NOT NULL,
    reason TEXT,
    UNIQUE(event_id)
);
```

2. Enhanced alerts API (`GET /api/alerts`):
   - Group alerts by session_id
   - Include `validated` boolean and `confidence` from validators.py
   - Include dismissal status (LEFT JOIN with alert_dismissals)
   - Return severity counts in response envelope: `{"counts": {"critical": 0, "high": 2, ...}, "alerts": [...]}`

3. `POST /api/alerts/dismiss` endpoint:
   - Accepts `{event_id: N, reason: "false_positive"}`
   - Inserts into alert_dismissals
   - Validates event_id exists and is a sensitive_data event
   - Returns 200 or 404

4. Dashboard changes:
   - Tab header shows: `Alerts (2 high, 5 medium)` with colored counts
   - Each alert card shows: confidence badge (green=high, yellow=medium), validated indicator
   - "Dismiss" button per alert -> POST to dismiss endpoint -> grey out the card
   - Group by session with collapsible sections
   - Filter: severity dropdown, show/hide dismissed

5. Already-fixed credit card false positives in API traffic: ensure the `_check_sensitive` pipeline includes `validated: true/false` in stored event data_json for display.

**Test Plan:**
- Unit: POST /api/alerts/dismiss creates dismissal record
- Unit: GET /api/alerts excludes dismissed alerts by default
- Unit: GET /api/alerts?include_dismissed=true includes them
- Unit: dismiss of non-existent event returns 404
- Unit: alerts response includes severity counts
- Integration: create sensitive_data event, dismiss it, verify API reflects state
- Coverage: alert_dismissals table CRUD

**Security Considerations:**
- POST endpoint must validate Content-Type is application/json
- event_id must be parameterized in SQL (no injection)
- Dismiss action is local-only (dashboard is localhost), but still validate input
- Reason field should be truncated to prevent large payloads

**Demo Impact:** Alerts tab goes from a raw list to a triaged, actionable view. Dismiss functionality shows the product is designed for real workflow. Confidence badges demonstrate the validation pipeline.

---

### Item 4: OpenClaw Session Details

**Priority:** P2
**Effort:** M (4-6 hrs)
**Files to create/modify:**
- `src/claude_monitoring/monitor.py` — enrich `_api_session_detail()` for OpenClaw sessions, add `_detect_openclaw_channel()`, tool risk mapping
- `src/claude_monitoring/constants.py` — add `TOOL_RISK_MAP` dict
- `src/claude_monitoring/dashboard.html` — session detail view: channel info, skill badges, cost display, tool risk colors, cross-agent correlation section
- `tests/test_jsonl_watcher.py` — channel detection, tool risk mapping tests

**Dependencies:** Item 2 (agent type detection)

**Approach:**

1. Tool risk mapping in `constants.py`:
```python
TOOL_RISK_MAP = {
    "exec": ("critical", "Can run any shell command"),
    "Bash": ("critical", "Shell execution"),
    "write": ("high", "File creation/overwrite"),
    "Write": ("high", "File creation/overwrite"),
    "edit": ("high", "File modification"),
    "Edit": ("high", "File modification"),
    "read": ("medium", "File read access"),
    "Read": ("medium", "File read access"),
    "web_fetch": ("medium", "External URL fetch"),
    "WebFetch": ("medium", "External URL fetch"),
    "web_search": ("low", "Search query"),
    "WebSearch": ("low", "Search query"),
    "memory_search": ("low", "Agent memory"),
    "sessions_spawn": ("high", "Sub-agent spawning"),
    "Agent": ("high", "Sub-agent spawning"),
}
```

2. Channel detection: Parse OpenClaw user message metadata to detect channel (Telegram, WebChat, API). The metadata block contains `sender_id` (Telegram), or may have other channel indicators. Store as part of session metadata.

3. Cost display: OpenClaw JSONL includes `cost.total` per message. Accumulate and show session total cost in the detail view.

4. Cross-agent correlation: When an OpenClaw session spawns a Claude Code or Codex agent, it typically does so via `sessions_spawn` or `Agent` tool calls. The spawned session would appear in a different JSONL directory but with overlapping timestamps and CWD. Match by: tool_use event with name="sessions_spawn" or "Agent" -> look for sessions starting within 5 seconds with matching CWD.

5. Dashboard detail view additions:
   - Channel badge: "Telegram" / "Web" / "API" with icon
   - Cost summary: "$0.12 (across 5 API calls)"
   - Tool usage section: each tool call gets a risk-colored badge
   - "Linked Sessions" section showing correlated child sessions

**Test Plan:**
- Unit: `_detect_openclaw_channel()` returns "Telegram" for metadata-wrapped messages
- Unit: tool risk mapping returns correct severity for each tool
- Unit: session detail API includes `channel`, `total_cost`, `tool_risks` fields
- Unit: cross-agent correlation finds linked sessions by timestamp+cwd
- Integration: real OpenClaw JSONL produces enriched session detail

**Security Considerations:**
- Cost data comes from OpenClaw's self-reported JSONL. We cannot verify it independently. Document this as "estimated cost" not "actual cost."
- Cross-agent correlation uses timestamp proximity — could theoretically match unrelated sessions. Use tight windows (5s) and require CWD match.

**Demo Impact:** OpenClaw sessions go from basic "unknown model, 0 tokens" to rich views with channel, cost, tool risk assessment, and linked sub-agent sessions. Shows multi-agent observability.

---

## Phase 2: Browser Extension

### Item 5: Chrome Extension — AI Session Monitor

**Priority:** P1
**Effort:** XL (multi-day, 3-5 days)
**Files to create/modify:**

Create:
```
browser-extension/
├── manifest.json
├── background.js
├── content_scripts/
│   ├── claude.js
│   ├── chatgpt.js
│   ├── gemini.js
│   └── shared.js
├── popup/
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── icons/
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png
├── tests/
│   ├── background.test.js
│   ├── content.test.js
│   ├── popup.test.js
│   └── e2e/
│       ├── playwright.config.js
│       └── extension.spec.js
└── README.md
```

Modify:
- `src/claude_monitoring/monitor.py` — add `POST /api/browser/ingest` endpoint
- `src/claude_monitoring/db.py` — add `source TEXT DEFAULT 'history'` column to browser_sessions
- `tests/test_api.py` — ingest endpoint tests

**Dependencies:** None (can start in parallel with Phase 1)

**Approach:**

**a) manifest.json (Manifest V3):**
```json
{
  "manifest_version": 3,
  "name": "AI Runtime Monitor",
  "version": "0.1.0",
  "permissions": ["activeTab", "storage", "tabs"],
  "host_permissions": ["http://127.0.0.1:9081/*", "http://localhost:9081/*"],
  "content_scripts": [{
    "matches": ["*://claude.ai/*", "*://chatgpt.com/*",
                "*://gemini.google.com/*", "*://perplexity.ai/*"],
    "js": ["content_scripts/shared.js", "content_scripts/claude.js"],
    "run_at": "document_idle"
  }],
  "background": {"service_worker": "background.js"},
  "action": {"default_popup": "popup/popup.html"}
}
```

**b) content_scripts/shared.js — Common capture framework:**
- `MutationObserver` on the message container to detect new messages
- `captureUserPrompt()` — hook the submit button/Enter key, capture textarea value
- `captureAssistantResponse()` — observe DOM for new assistant message elements, extract text
- `extractConversationId()` — parse URL for conversation ID
- `sendToBackground(event)` — `chrome.runtime.sendMessage()` to background worker
- All text truncated to 5000 chars
- Rate limit: max 1 event per second

**c) content_scripts/claude.js, chatgpt.js, gemini.js — Site-specific selectors:**
Each file defines the DOM selectors for that site:
- Claude: `div[data-testid="user-message"]`, `div[data-testid="assistant-message"]`
- ChatGPT: `div.markdown`, `textarea#prompt-textarea`
- Gemini: `message-content`, `rich-textarea`
These selectors are fragile and will need maintenance as sites update their UIs.

**d) background.js — Event batching and delivery:**
```javascript
let eventBuffer = [];
setInterval(async () => {
  if (eventBuffer.length === 0) return;
  const batch = eventBuffer.splice(0, 100);
  try {
    await fetch('http://127.0.0.1:9081/api/browser/ingest', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({events: batch})
    });
  } catch (e) {
    // Monitor offline — store in chrome.storage.local
    // FIFO eviction at 1000 events
  }
}, 5000);
```

**e) Monitor API endpoint (`POST /api/browser/ingest`):**
- Validate JSON body: array of events, each with `{service, url, timestamp, type, text}`
- Rate limit: max 100 events per request, 429 if exceeded
- Check request origin is localhost (127.0.0.1 or ::1)
- Insert into browser_sessions with `source='extension'`
- Run `scan_sensitive()` on captured text (user prompts and assistant responses)
- Return `{"stored": N, "alerts": N}`

**f) popup.html — Status dashboard:**
- Connection indicator (green/red) — ping `/api/stats`
- Today's capture count from `chrome.storage.local`
- Per-site toggle (enable/disable capture)
- "Open Dashboard" link
- Last 5 events summary

**Test Plan:**
- Unit (JS, Jest): background.js batching, retry logic, FIFO eviction
- Unit (JS, Jest): content script DOM parsing with mock DOM elements
- Unit (JS, Jest): popup.js status rendering
- Unit (Python, pytest): `/api/browser/ingest` endpoint — valid input, missing fields, oversized payload, non-localhost origin rejected, rate limiting
- Integration: content script captures mock message -> background batches -> POST to ingest -> verify in DB
- E2E (Playwright): load extension in Chrome, navigate to claude.ai mock, verify capture flow
- Coverage target: 90% for background.js and shared.js

**Security Considerations:**
- **Content script isolation:** Runs in Chrome's isolated world. Cannot access page JS variables. This is a security feature — the content script can only read the DOM, not intercept network requests or JS state.
- **No external network calls:** The extension only sends to `127.0.0.1:9081`. `host_permissions` enforces this at the browser level.
- **No eval/Function/innerHTML with user data:** All DOM reads use `textContent`, never `innerHTML`.
- **No page modification:** Content script is read-only. Does not inject UI or modify the page.
- **Input validation on ingest endpoint:** Parameterized SQL, field length limits, type checking.
- **Privacy:** All data stays on the user's machine. No telemetry, no analytics, no external services. Document this in extension description and README.
- **DOM selector fragility:** Site-specific selectors will break when sites redesign. This is a maintenance burden, not a security issue. Include version-specific selector sets with fallbacks.
- **CSP compliance:** No inline scripts, no eval. Manifest V3 enforces this.

**Demo Impact:** Transforms browser AI monitoring from "we know you visited chatgpt.com for 30 seconds" to "we captured the full conversation: user asked X, assistant responded Y, detected credential in response." This is the killer feature for enterprise audit.

---

## Phase 3: Testing & CI/CD Framework

### Item 6: Testing Requirements

**Priority:** P1
**Effort:** L (8-10 hrs)
**Files to create/modify:**

Create:
- `tests/e2e/conftest.py` — E2E fixtures (start monitor, create test DB)
- `tests/e2e/test_dashboard.py` — Playwright tests for dashboard UI
- `tests/e2e/playwright.config.py` — Playwright configuration
- `tests/test_security.py` — SQL injection, XSS, input validation tests

Modify:
- `pyproject.toml` — add Playwright, pytest-cov config, coverage thresholds
- `Makefile` — add `coverage`, `e2e`, `security` targets
- `tests/conftest.py` — shared fixtures for test DB, mock JSONL, mock Chrome DB

**Dependencies:** None (can start immediately)

**Approach:**

**a) Coverage enforcement:**
Add to `pyproject.toml`:
```toml
[tool.pytest.ini_options]
addopts = "--cov=claude_monitoring --cov-fail-under=90 --cov-report=term-missing"
```
Current coverage is untested — run `pytest --cov` to baseline, then add tests to reach 90%.

**b) Integration tests (add to existing test files):**
- JSONL pipeline: write JSONL -> process -> verify events + sessions + alerts in DB
- Dashboard API: start DashboardHandler with test DB -> GET all endpoints -> verify shapes
- Sensitive data end-to-end: text with real patterns -> scan_sensitive -> _check_sensitive -> event stored -> API returns it -> dashboard would render it

**c) E2E tests (Playwright):**
```python
# tests/e2e/test_dashboard.py
def test_dashboard_loads(page, monitor_url):
    page.goto(monitor_url)
    assert page.locator("#st-sessions").text_content() != "-"

def test_session_explorer_lists_sessions(page, monitor_url):
    page.goto(monitor_url)
    page.click("text=Explorer")
    assert page.locator(".session-item").count() > 0

def test_alerts_tab_shows_severity(page, monitor_url):
    page.goto(monitor_url)
    page.click("text=Alerts")
    # Should show severity breakdown
```

**d) Security tests:**
```python
# tests/test_security.py
def test_sql_injection_in_session_search(client):
    resp = client.get("/api/sessions?q=' OR 1=1 --")
    assert resp.status_code == 200  # Should not error
    # Should return 0 results, not all sessions

def test_xss_in_session_title(client, db):
    # Insert session with script tag in title
    db.execute("INSERT INTO sessions (session_id, title) VALUES (?, ?)",
               ("xss-test", '<script>alert(1)</script>'))
    resp = client.get("/api/sessions")
    # Title should be escaped in JSON (it is, since json.dumps escapes </>)
```

**Test Plan:**
- Baseline: run `pytest --cov` and document current coverage %
- Gap analysis: identify uncovered functions via coverage HTML report
- Write tests for uncovered code paths until 90% is reached
- E2E: 10+ Playwright tests covering dashboard load, navigation, session detail, alerts, live feed
- Security: 10+ tests for injection, XSS, input validation, localhost binding

**Security Considerations:**
- E2E tests start a real HTTP server — must bind to localhost only, use random port
- Test DB should use temp files, cleaned up after tests
- No real secrets in test fixtures

**Demo Impact:** "682 tests, 90% coverage" is a strong enterprise signal. Playwright screenshots in CI can be used for documentation.

---

### Item 7: CI/CD Pipeline

**Priority:** P1
**Effort:** M (3-4 hrs)
**Files to create/modify:**

Modify:
- `.github/workflows/ci.yml` — add coverage threshold enforcement, upload coverage artifact
- `.github/workflows/release.yml` — verify it handles PyPI publishing correctly

Create:
- `.github/workflows/e2e.yml` — Playwright E2E tests on main branch
- `.github/workflows/security.yml` — weekly security scans (pip-audit, bandit)
- `.pre-commit-config.yaml` — pre-commit hooks for ruff, detect-secrets

**Dependencies:** Item 6 (tests must exist before CI enforces them)

**Approach:**

**a) ci.yml enhancements:**
```yaml
- run: pytest --cov=claude_monitoring --cov-report=xml --cov-fail-under=90
```
Add `--cov-fail-under=90` to fail CI if coverage drops below threshold. Current CI already runs coverage and uploads to Codecov — just enforce the minimum.

**b) e2e.yml (new):**
```yaml
name: E2E
on:
  push:
    branches: [main]
jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install -e ".[dev]"
      - run: playwright install chromium
      - run: |
          python -m claude_monitoring.monitor --start &
          sleep 3
          pytest tests/e2e/ --browser chromium
      - uses: actions/upload-artifact@v4
        if: failure()
        with: {name: screenshots, path: tests/e2e/screenshots/}
```

**c) security.yml (new, weekly):**
```yaml
name: Security
on:
  schedule:
    - cron: "0 6 * * 1"  # Monday 6am UTC
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install pip-audit bandit
      - run: pip-audit
      - run: bandit -r src/ -ll
```

**d) pre-commit hooks:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.0
    hooks:
      - id: ruff
      - id: ruff-format
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

**e) Makefile additions:**
```makefile
coverage:  ## Run tests with HTML coverage report
	$(PYTHON) -m pytest --cov=claude_monitoring --cov-report=html --cov-fail-under=90
	@echo "Coverage report: htmlcov/index.html"

e2e:  ## Run Playwright E2E tests
	$(PYTHON) -m pytest tests/e2e/ -v

security:  ## Run security scans
	$(PYTHON) -m pip_audit
	$(PYTHON) -m bandit -r src/ -ll

ci:  ## Run full CI pipeline locally
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) security
```

**Test Plan:**
- CI: push a branch, verify all workflow jobs pass
- Coverage: verify CI fails when test is removed (coverage drops below 90%)
- Pre-commit: `pre-commit run --all-files` passes
- Security: `make security` runs without critical findings

**Security Considerations:**
- `detect-secrets` prevents accidental secret commits (Stripe keys, API keys, etc.)
- `pip-audit` catches known CVEs in dependencies
- `bandit` catches Python security anti-patterns (eval, exec, SQL injection)
- E2E workflow starts a server — must not expose it beyond the CI runner

**Demo Impact:** Badges in README: "CI passing", "Coverage 90%+", "Security scanned weekly". Standard enterprise expectations.

---

### Item 8: Secure SDLC Enforcement

**Priority:** P2
**Effort:** M (3-4 hrs)
**Files to create/modify:**

Modify:
- `pyproject.toml` — consolidate dev dependencies, add tool configs
- `SECURITY.md` — expand threat model, testing procedures, disclosure process

Create:
- `CONTRIBUTING.md` — code-level security rules, PR checklist
- `.secrets.baseline` — detect-secrets baseline file

**Dependencies:** Item 7 (CI must be in place to enforce)

**Approach:**

**a) pyproject.toml updates:**
```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0", "pytest-cov>=5.0", "ruff>=0.8",
    "bandit>=1.7", "pip-audit>=2.7", "detect-secrets>=1.5",
    "playwright>=1.40", "mypy>=1.8",
]

[tool.ruff]
line-length = 120
target-version = "py39"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "S", "B"]  # includes bandit rules via S

[tool.mypy]
python_version = "3.9"
warn_return_any = true
warn_unused_configs = true
```

**b) SECURITY.md threat model:**
Document:
- Dashboard is localhost-only (no remote access by default). If `gateway.bind` is changed to `lan` or `0.0.0.0`, the dashboard is network-accessible with no authentication.
- Browser extension only talks to localhost. The `host_permissions` in manifest.json enforces this.
- SQLite DB contains sensitive session data (user prompts, tool outputs, detected secrets). DB file permissions should be 0600.
- Proxy mode (watch.py) performs MITM on HTTPS traffic. The mitmproxy CA certificate must be trusted by the client. If the CA private key is compromised, all intercepted traffic is at risk.
- JSONL files from Claude Code and OpenClaw contain full conversation transcripts including any secrets the user typed or the AI generated.

**c) CONTRIBUTING.md code rules:**
- All SQL: parameterized queries only (`?` placeholders). No f-strings in SQL.
- All user input: validate type, length, and format before use.
- No `eval()`, `exec()`, `pickle.loads()` with untrusted data.
- No hardcoded paths (use `Path.home()` / config).
- HTTP server: check Content-Type on POST, validate JSON schema.
- External data (JSONL, Chrome DB, proxy traffic): treat as untrusted.
- File paths: use `pathlib`, no string concatenation.
- Secrets: never log, never include in error responses, always mask in output.

**Test Plan:**
- Verify `make ci` passes (lint + test + security)
- Verify `pre-commit run --all-files` passes
- Verify SECURITY.md is accurate by manually testing each threat
- Review: all existing SQL queries use parameterized statements (they do — `nosec B608` comments are already on the legitimate f-string queries)

**Security Considerations:** This item IS the security framework. Key risk: rules are documented but not machine-enforced. Mitigation: ruff's `S` rules (bandit integration) catch the most common issues automatically in CI.

**Demo Impact:** Enterprise buyers check for SECURITY.md, CONTRIBUTING.md, and CI badges. This is table stakes for procurement.

---

## Implementation Sequence

### Recommended Order

```
Week 1 (Phase 1 — Fix and Polish):
  Day 1-2:  Item 1 (API Traffic Gap) — unblocks API Traffic tab
  Day 2-3:  Item 2 (Agent Badges) — visual polish, quick win
  Day 3-4:  Item 3 (Alerts Overhaul) — depends on validators (done)
  Day 4-5:  Item 4 (OpenClaw Session Details) — depends on Item 2

Week 2 (Phase 2 — Browser Extension):
  Day 1-3:  Item 5a-d (Extension core: manifest, content scripts, 
            background worker, popup)
  Day 3-4:  Item 5e (Monitor ingest endpoint)
  Day 4-5:  Item 5f-g (Extension tests, security review)

Week 2-3 (Phase 3 — Testing & CI, in parallel with extension):
  Day 1-2:  Item 6a (Coverage baseline + gap analysis)
  Day 2-3:  Item 6b-c (Integration + E2E tests)
  Day 3-4:  Item 7 (CI/CD pipelines)
  Day 4-5:  Item 8 (SDLC documentation)
            Item 6d (Security tests)
```

### Dependency Graph

```
Item 1 (API Traffic) ──────────────────────> [API Traffic tab works]
     |
Item 2 (Agent Badges) ────────────────────> [Visual identity per agent]
     |
     +──> Item 4 (OpenClaw Details) ──────> [Rich multi-agent view]
     
Item 3 (Alerts Overhaul) ────────────────> [Actionable alert triage]
     |
     |    (validators.py already done)
     
Item 5 (Browser Extension) ──────────────> [Content capture from browser]
     |
     +──> Item 5e (Ingest endpoint) ──────> [Data flows into monitor]

Item 6 (Testing) ────> Item 7 (CI/CD) ──> Item 8 (SDLC)
     |                      |
     +── 90% coverage ──────+── Enforced in CI
```

### Items That Can Run in Parallel
- Items 1 + 2 (different files, no overlap)
- Items 5 + 6 (extension development + test infrastructure)
- Items 3 + 4 (alerts tab + session details, different dashboard sections)
- Item 7 happens after Item 6 (CI enforces what tests define)

### Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| DOM selectors in extension break when AI sites redesign | Extension stops capturing | Version-specific selector sets, fallback patterns, automated E2E tests that detect breakage |
| Coverage drops below 90% after rapid feature addition | CI blocks merges | Write tests BEFORE implementation (TDD), coverage report in PR comments |
| OpenClaw JSONL format changes in future versions | JSONL processing breaks | Defensive parsing (try/except), version detection from type:"session" record |
| mitmproxy CA compromise | All HTTPS traffic interceptable | Document CA handling, restrict CA file permissions, consider short-lived CAs |
| Browser extension rejected by Chrome Web Store | Can't distribute via store | Distribute as unpacked extension for enterprise (sideload via policy), document installation |
