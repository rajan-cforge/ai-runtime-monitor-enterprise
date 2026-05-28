# `claude-watch` CLI reference

`claude-watch` is Vigil's lower-level CLI for proxy-only operation and per-agent shell configuration. **Most users do not need to invoke `claude-watch` directly** — `ai-monitor --setup` and `ai-monitor --start --with-proxy` cover the full install + capture flow including the proxy.

You'd reach for `claude-watch` when:

- You want to run **just the mitmproxy interceptor** without the dashboard daemon (e.g., debugging a flow, capturing to a CSV for analysis outside Vigil).
- You need to **add `HTTPS_PROXY` to a specific agent's shell profile** so that agent picks up the proxy automatically in new terminals.
- You want a **standalone terminal-only analysis** of the latest captured session without launching the dashboard.

For the normal end-user flow (install, daemon, dashboard, browser extension), use `ai-monitor` — see the main [README](../README.md#install).

## Flags

| Option | Description |
|--------|-------------|
| `--setup` | First-time: ensures mitmproxy is installed and the Vigil CA is trusted. Equivalent to `ai-monitor --setup` minus the wizard's extra steps (Chrome extension prompt, dashboard token, system proxy). |
| `--start` | Start the proxy interceptor only (no dashboard daemon). Listens on `127.0.0.1:9080`. Captures intercepted flows to `~/claude_watch_output/sessions/`. |
| `--verify` | Health-check the proxy setup. Verifies mitmproxy is importable, CA cert exists, CA is trusted in admin keychain. Exits 0 on success. |
| `--configure <agent>` | Configure `HTTPS_PROXY=http://127.0.0.1:9080` in the shell profile for a specific agent. `claude-watch --configure list` shows supported agents. |
| `--unconfigure` | Remove the `HTTPS_PROXY` lines `claude-watch --configure` added to your shell profiles. |
| `--analyze` | Terminal analysis of the latest captured session. Prints token totals, model breakdown, cost (where computed), and the last N tool calls. No dashboard required. |
| `--plot` | Generate PNG dashboard charts from the captured data (requires `matplotlib`). Output: `~/claude_watch_output/plots/`. |
| `--dashboard` | Launch a standalone CSV-based web viewer over the latest captured proxy data in `~/claude_watch_output/sessions/`. **Not the same as the full `ai-monitor` dashboard** — this viewer reads proxy-captured CSVs only (no JSONL, no extension data, no process/file monitors), has no bearer-token auth, and runs without a daemon. Useful for ad-hoc inspection of proxy flows without standing up the full monitor. |
| `--scan` | Scan running processes for AI agents and print a one-shot report. |
| `--generate-test` | Generate synthetic test flows for development. Not for production use. |

## Relationship to `ai-monitor`

Both CLIs live in the same Python package (`claude_monitoring`):

- `ai-monitor` (entry point: `claude_monitoring.monitor:main`) — the full daemon + dashboard + proxy orchestrator. Owns the lifecycle of all four capture layers.
- `claude-watch` (entry point: `claude_monitoring.watch:main`) — the lower-level proxy + analysis CLI. Owns just the mitmproxy addon and the captured-data tooling around it.

The canonical install flow uses only `ai-monitor`. `claude-watch` is documented separately because the few advanced workflows that need it (debug-only proxy, ad-hoc CSV export, per-agent shell config) deserve dedicated documentation without cluttering the main README.

## When NOT to use `claude-watch`

- **Don't use `claude-watch --setup` for first-time install.** It does less than `ai-monitor --setup` — no Chrome extension prompt, no dashboard token, no system proxy enablement. Visitors who follow `claude-watch --setup` end up with a partial install.
- **Don't use `claude-watch --start` alongside `ai-monitor --start --with-proxy`.** They'll both try to bind port 9080 and one will crash.
- **Don't use `claude-watch --dashboard` if `ai-monitor --start` is already running.** Port 9081 conflict.

When in doubt: use `ai-monitor`.
