# Functional Spec — watch.py

**Module:** `src/claude_monitoring/watch.py`
**Status:** v0.2 launch candidate
**Audit history:** None directly; depends on `security.py` audit history

## 1. Purpose

`watch.py` implements Layer 3 of the monitoring stack — HTTPS proxy interception via mitmproxy. It captures full API request/response payloads from AI services when AI agents are configured with `HTTPS_PROXY`. This is the deepest visibility level the product offers; Layer 1 (JSONL) and Layer 2 (process/network) work without it, but the API Traffic tab and exact token counts depend on this module.

The module owns three responsibilities:

1. **mitmproxy addon** — `ClaudeWatchAddon` class implementing the `request` and `response` hooks
2. **CLI tools** — the `claude-watch` console script with subcommands for setup, start, configure, analyze
3. **Per-agent proxy configuration** — adds `HTTPS_PROXY` to supported AI agents' shell profiles or app configs

## 2. Public contract

### 2.1 mitmproxy addon

```python
class ClaudeWatchAddon:
    def __init__(self) -> None: ...
    def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Called for every intercepted HTTPS request."""
    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """Called for every intercepted HTTPS response. Stores capture."""
```

Loaded by mitmproxy via `mitmdump -s watch.py` or `--scripts watch.py`.

### 2.2 CLI subcommands

```python
def cli_setup() -> int:
    """First-time setup: install mitmproxy, generate CA, prompt for trust."""

def cli_start() -> int:
    """Start mitmproxy with the addon loaded."""

def cli_verify() -> int:
    """Health-check the proxy setup. Reports trusted CA, running proxy, config."""

def cli_configure(agent: str) -> int:
    """Configure HTTPS_PROXY for a specific AI agent."""

def cli_unconfigure() -> int:
    """Remove HTTPS_PROXY configuration from all agents."""

def cli_analyze() -> int:
    """Terminal analysis of the latest captured session."""

def cli_plot() -> int:
    """Generate PNG charts from captured data."""

def cli_dashboard() -> int:
    """Launch the standalone watch dashboard (separate from main dashboard)."""

def cli_scan() -> int:
    """Detect running AI agents to inform configuration."""

def cli_generate_test() -> int:
    """Create synthetic test data for development."""
```

## 3. Inputs

- **Configuration:** proxy port, CA cert path from `config.py`
- **mitmproxy process state:** PID, port binding (checked via `lsof`)
- **HTTPS_PROXY environment variable:** read for verification
- **AI agent process names:** detected via `psutil` for configuration suggestions
- **HTTPS flows:** the actual API requests and responses (when active)

## 4. Outputs

- **CSV session files:** dual-written to `~/claude_watch_output/sessions/` (primary capture format)
- **Database rows:** `api_calls` table in `monitor.db` (dual-write, best-effort)
- **Shell profile modifications:** `~/.zshrc` or `~/.bashrc` for configured agents
- **App config modifications:** for agents with app-config-based proxy support (Cursor's settings.json)
- **stdout/stderr:** CLI subcommand output (status, errors, hints)

## 5. Side effects

- **File system mutation:** within `~/claude_watch_output/sessions/`, plus shell profile / app config files
- **Network I/O:** mitmproxy binds to localhost:9080
- **Process spawning:** when `cli_start` runs, it execs `mitmdump`
- **Environment modification:** affects shell sessions opened after configuration

## 6. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| mitmproxy not installed | `cli_setup` installs it via pip | Auto-recovers |
| Proxy port in use | `cli_start` exits with error | Use different port or kill the conflicting process |
| CA cert not trusted | TLS errors on intercepted requests | Run `cli_verify` to diagnose; instructions provided |
| Shell profile not writable | `cli_configure` reports failure | Manual configuration documented |
| AI agent uses non-standard proxy env | Proxy doesn't intercept that agent | Per-agent configuration table needs an entry |
| Captured payload too large | Truncated in CSV; full request size still logged | Default capture limit is 1MB; configurable |
| CSV file lock during dual-write | DB write proceeds; CSV write retried | Eventually consistent |

## 7. Trust model

The proxy is the most sensitive component of the product because it can technically observe any TLS traffic. The product's trust story rests on two mechanisms:

1. **NameConstraints in the CA** (see `security.py` spec) — cryptographically prevents the CA from signing leaf certs for non-AI domains
2. **Selective MITM in the addon** — `ClaudeWatchAddon` explicitly filters which hosts it intercepts. Even if NameConstraints were bypassed, the addon code chooses to ignore non-AI hosts

Host filtering happens at **two** layers:

1. **Transport layer (mitmdump `--allow-hosts`)**: a regex built from `constants.AI_PROXY_DOMAINS` (which equals `AI_API_DOMAINS` as of PR #51 — browser UI sites are intentionally excluded; see `constants.py` for rationale). Flows for hosts outside this regex are never intercepted; the addon never sees them.
2. **Addon layer (inside `ClaudeWatchAddon.request`)**: a secondary filter against `constants.AI_HOSTS` (API → service-name map) and `constants.AI_BROWSER_DOMAINS`. In the normal run path the browser branch is dead code because the transport-layer regex already rejects those hosts; the branch is retained for testability and for the rare manual-invocation case where the proxy is launched with a custom allow_hosts.

Adding a new AI service requires adding the hostname to `constants.AI_HOSTS` AND to `constants.AI_API_DOMAINS` (browser-facing UIs go in `constants.AI_BROWSER_DOMAINS` and are captured by the Chrome extension, not the proxy). There is no wildcard or pattern-match that could accidentally include non-AI hosts.

## 8. Hot-path notes

`ClaudeWatchAddon.response` runs on every intercepted response. Patterns to preserve:

- Sensitive-data scanning runs once per response body; results are cached
- CSV write is buffered (default 100 entries per flush)
- DB write is non-blocking (best-effort, fire-and-forget); CSV is the source of truth
- Token-count parsing from response headers is O(1) lookups, not regex

If the proxy is heavily loaded (developer running many AI agents simultaneously), the addon could become the bottleneck. v0.3 will add backpressure: drop oldest captures rather than block the addon.

## 9. Extension points

- **Support a new AI service:** add to `constants.AI_HOSTS` and `constants.AI_API_DOMAINS` (which is what `constants.AI_PROXY_DOMAINS` resolves to as of PR #51; browser-facing UI hosts go in `constants.AI_BROWSER_DOMAINS` and are captured by the Chrome extension, not the proxy)
- **Support a new AI agent for configuration:** add an entry to the per-agent config table in `cli_configure`
- **Add a new captured field:** extend the addon's `response` method and the database schema
- **Custom analysis:** the `cli_analyze` subcommand can dispatch to plugins (planned v0.3)

## 10. Testing

- **Unit tests:** `tests/test_watch.py` covers the addon's host filtering, payload parsing, and CSV format
- **Integration tests:** local mitmproxy + curl test in `tests/integration/test_proxy_capture.py`
- **Configuration tests:** `tests/test_watch_configure.py` covers per-agent setup logic with mocked shell profiles

## 11. Dependencies

- Standard library: `argparse`, `csv`, `json`, `os`, `subprocess`, `sys`, `pathlib`, `datetime`
- Project modules: `config`, `constants`, `utils`, `db`, `security`
- Third-party (only when proxy is active): `mitmproxy` (heavy dep, optional `[watch]` extra)
- Optional: `matplotlib` for `cli_plot` (separate `[plot]` extra)

## 12. Future direction

- **Cross-platform:** Windows support via WinDivert (v0.3)
- **Browser inspection:** add the browser extension as a parallel capture source (v0.2.1)
- **Streaming response support:** Anthropic's streaming response format already handled; need to verify GPT-4 streaming
- **Compression handling:** brotli and zstd decompression (currently only gzip)
- **Selective recording:** policies to skip capturing specific endpoints or methods (privacy mode)
- **Distributed proxy:** for fleet deployments where one proxy serves multiple endpoints (v1.0)
