# Functional Spec — monitor.py

**Module:** `src/claude_monitoring/monitor.py`
**Size:** ~4800 lines (M6 split scheduled post-launch)
**Status:** v0.2 launch candidate

## 1. Purpose

`monitor.py` is the main entry point for the AI Runtime Monitor daemon. It owns four concerns that collectively form the runtime observation core of the product:

1. **CLI dispatch** — parses `ai-monitor` command-line flags and routes to subcommands (`--start`, `--setup`, `--status`, `--purge`, etc.)
2. **Scanners** — orchestrates `ProcessScanner`, `NetworkMonitor`, `FileSystemWatcher`, `ChromeHistoryWatcher`, and `JSONLSessionWatcher` (the five capture layers)
3. **HTTP dashboard server** — `DashboardHandler` serves all `/api/*` endpoints documented in `openapi.yaml`
4. **Lifecycle orchestration** — heartbeat, crash tracking, graceful shutdown, LaunchAgent integration

This module is the largest in the codebase. M6 (the planned split) will extract scanners, dashboard, and lifecycle into separate modules. Until M6 lands, `monitor.py` remains the de facto orchestrator.

## 2. Public contract

### 2.1 Entry point

```python
def main(argv: list[str] | None = None) -> int
```

The module's `main()` function is the CLI entry point. It parses `argv`, dispatches to the requested subcommand, and returns a Unix exit code. Called by both the `ai-monitor` console script and module invocation (`python -m claude_monitoring.monitor`).

### 2.2 Scanner protocol

Each scanner class follows an informal scanner pattern (formalized by the planned `Scanner` Protocol from `protocols/scanner.py` in Phase 3F):

```python
class XxxScanner:
    name: str               # unique identifier
    
    def __init__(self, db, **config) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def scan_once(self) -> list[dict]: ...  # returns events captured this cycle
    def run_loop(self) -> None: ...         # for continuous scanners
```

Note: `ProcessScanner` predates the formal Scanner Protocol. The conformance test exempts it in `KNOWN_PROTOCOL_EXEMPT` because its `run_loop` lifecycle is different from the one-shot `scan()` envisioned for the Protocol. Phase 3F unifies these.

### 2.3 Dashboard handler

```python
class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None: ...
    def do_POST(self) -> None: ...  # only for /api/v1/* control plane endpoints
```

Dispatches on `self.path` to specific handler methods. Each handler:
1. Validates the bearer token via `security.verify_token`
2. Parses query parameters from `self.path`
3. Queries the database
4. Returns JSON via `self.wfile.write`

## 3. Inputs

`monitor.py` depends on the following sources:

- **Config** — `config.py` accessors (`get_db_path`, `get_dashboard_port`, etc.)
- **Database** — initialized via `db.py::init_db`; queried directly via `sqlite3`
- **JSONL session files** — `~/.claude/projects/**/*.jsonl` (Claude Code) and `~/.openclaw/sessions/**/*.jsonl` (OpenClaw)
- **OS process tables** — via `psutil.process_iter()` and `psutil.net_connections()`
- **File system events** — via `watchdog.observers.Observer` with FSEvents on macOS
- **Chrome history** — `~/Library/Application Support/Google/Chrome/Default/History` (a copy-on-read SQLite DB)

## 4. Outputs

- **Database writes** — every captured event is persisted to the appropriate table (`sessions`, `events`, `processes`, `connections`, `file_events`, `browser_sessions`, `api_calls`)
- **HTTP responses** — JSON for `/api/*`, HTML for `/`, redirect for `/dashboard`
- **Log file** — `~/claude_watch_output/monitor.log` (rotating, max 10MB per file, 5 files retained)
- **Heartbeat file** — `~/claude_watch_output/.heartbeat` (touched every 30s by the watchdog thread)
- **Crash log** — `~/claude_watch_output/crashes.log` (append-only on unclean shutdown)

## 5. Side effects

- **Process creation** — none in v0.2 (the daemon is single-process; scanners are threads)
- **File system mutation** — only within `~/claude_watch_output/`
- **Network I/O** — listens on `127.0.0.1:9081` (dashboard); no outbound network unless control plane sync is enabled
- **Database mutation** — frequent INSERT and occasional UPDATE; never DELETE (auto-purge in `security.py` handles deletion separately)

## 6. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| Database file missing | Daemon exits at startup with error | Run `ai-monitor --setup` |
| Database file corrupted | Daemon logs corruption error, exits | Manual recovery; backup restored from auto-snapshot (planned v0.3) |
| Dashboard port in use | Daemon logs error, exits | Use `--port` flag or kill the conflicting process |
| JSONL directory missing | Scanner logs warning, retries on schedule | Auto-recovers when directory appears |
| Permission denied on JSONL | Scanner logs warning, skips file | Fix file permissions; scanner picks it up on next cycle |
| Chrome history locked | Scanner waits and retries (Chrome closed = lock released) | Auto-recovers |
| Watchdog thread crash | Heartbeat file goes stale | `status.py::heartbeat_age_seconds` surfaces the staleness; planned LaunchAgent auto-restart |
| Memory pressure | Python may be OOM-killed by macOS | LaunchAgent auto-restart; crash logged |

All failure modes prefer to log and continue rather than crash. The watchdog thread is the exception: if it crashes, the daemon detects this on next heartbeat check and exits cleanly so the LaunchAgent can restart.

## 7. Extension points

The module is currently extended via:

- **Adding a new scanner** — create a class in `scanners/` (planned post-M6 split), add to the main scanner list in `monitor.py::run`, register heartbeat hook
- **Adding a new API endpoint** — add a route handler method to `DashboardHandler`, dispatch from `do_GET`, add to `openapi.yaml`
- **Adding a new CLI command** — add to `argparse` setup in `main()`, dispatch in the subcommand switch

Post-Phase-3F, the architect-reviewer agent's rubric explicitly checks that new scanners satisfy the Scanner Protocol from `protocols/scanner.py`.

## 8. Hot-path notes

`DashboardHandler.do_GET` is on the hot path — every dashboard refresh hits multiple endpoints. Patterns to preserve:

- Regex compilation is module-level, never inside the handler
- DB queries use indexed lookups (every WHERE clause has an index per `db.py::init_db`)
- JSON responses are built with `json.dumps` once per request; no incremental string concatenation
- Token verification is constant-time; the additional cost is negligible compared to DB query latency

`JSONLSessionWatcher.run_loop` is also on the hot path — high-frequency JSONL writes during active Claude Code sessions. Patterns to preserve:

- File tail is done with line offset tracking (not re-reading the whole file)
- Sensitive-data scan runs on each captured line; the validator pipeline filters out low-confidence matches
- Database INSERTs are batched per cycle, not per event

## 9. Known issues and audit history

| Audit | Issue | Resolution |
|-------|-------|-----------|
| C1 (Phase 3A) | `verify_endpoint_key` used `==` instead of constant-time comparison | Switched to `hmac.compare_digest`; PR #13 |
| C2 (Phase 3A) | Bare `esc()` in dashboard.html allowed context confusion | Four context-aware helpers; PR #15 |
| C3 (Phase 3A) | `_sanitize_string` was fail-open on malformed input | Fail-closed with sentinel; PR #14 |
| C4 (Phase 3A) | Subprocess shell injection via osascript | argv list + AppleScript escape; PR #12 |
| Audit highs (Phase 3F target) | DashboardHandler does too much (auth, routing, rendering, API) | M6 split scheduled |

## 10. Dependencies

This module depends on:

- Standard library: `http.server`, `socket`, `socketserver`, `threading`, `argparse`, `json`, `sqlite3`, `os`, `sys`, `subprocess`, `re`, `time`, `datetime`, `pathlib`, `logging`
- Project modules: `config`, `constants`, `utils`, `db`, `security`, `lifecycle`, `status`, `wizard`, `report`, `supply_chain`, `threat_intel`, `vuln_scanner`, `validators`
- Third-party: `psutil`, `watchdog`, `cryptography`

Optional (only if proxy is enabled):
- `mitmproxy` (via `watch.py`)
- `matplotlib` (for `claude-watch --plot`)

## 11. Testing

- **Unit tests:** `tests/test_monitor.py`, `tests/test_dashboard_api.py`, `tests/test_dashboard_xss_helpers.py`
- **Integration tests:** `tests/test_smoke.py` (full daemon boot, dashboard request, daemon shutdown)
- **E2E tests:** the `e2e-boot` CI workflow exercises the full path: boot, hit `/api/stats`, validate response, shut down
- **Coverage:** > 75% per per-file ratchet (PR #27)

## 12. Future direction

- **M6 split (Phase 3F):** extract scanners to `scanners/`, dashboard to `dashboard/`, lifecycle stays in `lifecycle.py`. Target post-launch.
- **WebSocket push (v0.3):** replace dashboard polling with WebSocket for `/api/feed`. Reduces latency and bandwidth.
- **Scanner registration (v0.3):** make scanners pluggable via entry points so third-party scanners can be installed without touching `monitor.py`.
- **Async refactor (v1.0):** move scanners and dashboard to asyncio. Eliminates the thread management complexity.
