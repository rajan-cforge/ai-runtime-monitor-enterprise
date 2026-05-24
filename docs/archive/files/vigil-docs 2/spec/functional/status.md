# Functional Spec — status.py

**Module:** `src/claude_monitoring/status.py`
**Status:** v0.2 launch candidate

## 1. Purpose

`status.py` implements the `ai-monitor --status` command. It inspects every layer of the stack — core processes, proxy state, certificate trust, security posture, capture matrix, reliability metrics — and prints a human-readable status report. A `--status-json` variant emits the same data as machine-readable JSON for CI and shell prompts.

Status inspection is a diagnostic tool, not a control surface. It does not modify any state. Every check is best-effort: any error returns False (the "checked but failed" state) and never raises. The function should never crash the CLI.

## 2. Public contract

```python
def show_status() -> int:
    """Print a human-readable status report. Returns 0 for success."""

def show_status_json() -> int:
    """Emit machine-readable status. Useful for CI and shell prompts."""
```

Plus a set of private check helpers (prefixed with `_`) for each individual diagnostic.

## 3. What status reports

The status output is grouped into sections, each surfacing a different aspect of the running system:

### 3.1 Service section (only if LaunchAgent is installed)

- LaunchAgent installed? (yes/no with label)
- State: loaded, running with PID, or not loaded
- Last exit code (if non-zero, surfaces the previous crash)

### 3.2 Core section

- Monitor running? (HTTP probe to `http://127.0.0.1:9081/`)
- Dashboard URL
- Database status (encrypted with SQLCipher, or active with chmod 600)

### 3.3 Proxy section

- mitmproxy running? (`lsof` check on port 9080)
- System proxy configured? (`networksetup -getsecurewebproxy Wi-Fi`)
- CA certificate trusted? (`security find-certificate` on system keychain)
- SSL inspection capability (API only, or API + Browser)

### 3.4 Capture matrix

A grid showing which capture methods are active for each AI agent:

| Agent | JSONL | Proxy | Status |
|-------|-------|-------|--------|
| Claude Code | ✅ | ✅ if proxy running | Both layers |
| OpenClaw | ✅ | n/a | JSONL only |
| Claude Desktop | n/a | ✅ if proxy + system proxy | Proxy or process only |
| ChatGPT Desktop | n/a | ✅ if proxy + system proxy | Proxy or process only |
| Cursor | n/a | ✅ if proxy + system proxy | Proxy or process only |
| Chrome claude.ai | n/a | ✅ if cert trusted | Proxy metadata + extension content |
| Chrome chatgpt | n/a | ✅ if cert trusted | Proxy metadata + extension content |
| Chrome gemini | n/a | ✅ if cert trusted | Proxy metadata + extension content |
| Ollama | ✅ | n/a | Process + network |

### 3.5 Security section

- CA type (Custom or Default mitmproxy)
- CA constraints (number of permitted AI domains)
- CA expiry (date)
- Database encryption (SQLCipher AES-256 if installed; chmod 600 otherwise)
- File permissions enforced (yes/needs fixing)
- Dashboard auth (token required)
- Data retention (30 days auto-purge)

### 3.6 Reliability section

- Heartbeat age (seconds since last update; staleness warning thresholds)
- Recent crashes (count in the last 7 days)
- Log file path and size

### 3.7 Extension section (only if browser extension has reported a heartbeat)

- Host
- Last heartbeat timestamp
- Selector match status (user matches, assistant matches, or failure)

## 4. The "stale state detected" warning

If `_is_mitmproxy_running()` returns True but `_is_monitor_running()` returns False, the status output displays a prominent warning at the top:

```
⚠ STALE STATE DETECTED
  mitmproxy is running but the monitor is not.
  Your network may be routing through an orphaned proxy.
  Fix: ai-monitor --stop && ai-monitor --start --with-proxy
```

This is the exact failure mode that motivated the lifecycle work in Phase 1. An orphaned mitmproxy with no monitor consuming its output means the user's traffic is being intercepted but nothing is recording it — silent MITM. The warning is prominent because the user needs to act, not just notice.

## 5. The dashboard-probe socket trick

`_is_monitor_running()` uses `http.client.HTTPConnection` directly, not `urllib.request`. Reason documented in the code:

> Uses a raw socket connection to bypass any proxy config that Python
> might inherit from the macOS system proxy settings. When
> `--with-system-proxy` is enabled, urllib.request on macOS will route
> `http://127.0.0.1:9081/` through mitmproxy at 127.0.0.1:9080, which
> then rejects the loopback destination — making the probe return
> False even though the server is actually healthy.

This is a real bug we hit in development. The fix preserves the diagnostic's usefulness when the system proxy is active.

## 6. Inputs

- **OS state:** processes, network ports, keychain entries
- **File system state:** existence and permissions of config files, the database, the token file
- **Database state:** the `extension_heartbeats` table for browser-extension status
- **Configuration:** paths and ports from `config.py`
- **Lifecycle state:** heartbeat age and crash count via `lifecycle.py`

## 7. Outputs

- **stdout:** ANSI-colored status report
- **Exit code:** 0 (always; status is a read operation)

For `show_status_json`:
- **stdout:** JSON object with all the same data fields

## 8. Side effects

None. Every check is read-only.

## 9. Failure modes

Every check is wrapped in try/except. Failures degrade gracefully:

- `lsof` not available: proxy/monitor running checks return False
- `networksetup` not available: system proxy check returns False
- `security` command not available: keychain checks return False
- Database missing: extension heartbeat check returns None (section is hidden)
- Cert file missing: CA info returns None ("Default mitmproxy" displayed)

The output adapts: sections that have no data are hidden. The user sees what's relevant for their current setup.

## 10. Hot-path notes

`show_status` runs only when the user types `ai-monitor --status`. It is interactive and cold-path. The various `_is_*` checks shell out to `lsof`, `networksetup`, `security`, and `http.client`. The full status display takes ~1-2 seconds.

`show_status_json` is used in shell prompts and CI. For shell prompts, the latency matters. The JSON version skips the cosmetic formatting but does the same underlying checks. Future versions could cache check results for ~1 second to reduce repeated subprocess overhead.

## 11. Extension points

- **Add a new check:** create a `_is_*` helper and add it to the appropriate section in `show_status`
- **Add a new section:** add the section's print block to `show_status` (and the equivalent key to `show_status_json`)
- **Override the dashboard URL:** runtime config can change `dashboard_port`; status reflects it

## 12. Testing

- **Unit tests:** `tests/test_status.py` mocks subprocess calls and verifies output formatting
- **JSON parity:** test that every field in `show_status_json` corresponds to a section in `show_status`
- **Stale-state detection:** integration test with running mitmproxy and stopped monitor verifies the warning fires

## 13. Dependencies

- Standard library: `http.client`, `subprocess`, `sqlite3`, `json`, `pathlib`
- Project modules: `config`, `security`, `lifecycle`, `db`

## 14. Future direction

- **Health endpoint (v0.3):** expose `/api/health` for external monitoring (Datadog, Prometheus)
- **Periodic background self-check (v0.3):** the daemon checks itself every 5 minutes and logs any degraded state
- **Status webhook (v1.0 Enterprise):** push status changes to a configurable webhook for fleet monitoring
- **Diagnostic bundle export (v0.3):** `ai-monitor --diagnostics` produces a redacted ZIP of relevant logs and config for support
