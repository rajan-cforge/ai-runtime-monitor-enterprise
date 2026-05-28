# Vigil

[![CI](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ai-runtime-monitor.svg)](https://pypi.org/project/ai-runtime-monitor/)
[![Python](https://img.shields.io/pypi/pyversions/ai-runtime-monitor.svg)](https://pypi.org/project/ai-runtime-monitor/)

**Endpoint security for the AI developer — monitor what AI coding agents actually do on your machine.**

Vigil is open-source runtime security monitoring for AI coding agents — Claude Code, Cursor, ChatGPT, Copilot, and any agent that runs on your machine or talks to an AI API. It captures conversations, inspects API traffic, watches process and filesystem activity, scans agent-issued install commands for supply chain risk, and detects credentials leaking into AI sessions. Behavioral monitoring at runtime, not static inventory after the fact.

## Install

> macOS today (Sequoia 15 / 26 supported). Linux is best-effort; Windows planned for v0.3.

The recommended path uses [pipx](https://pipx.pypa.io/), which installs Vigil into its own isolated environment and exposes `ai-monitor` / `claude-watch` on your PATH. This avoids the "externally-managed-environment" error you'll hit running bare `pip install` against Homebrew's Python.

```bash
brew install pipx                    # if you don't have it; or: python3 -m pip install --user pipx
pipx install ai-runtime-monitor
ai-monitor --setup                   # one-time: generates CA cert, walks trust + extension steps
ai-monitor --start                   # daemon + dashboard at http://localhost:9081
```

On macOS Sequoia (15) and later, `--setup` will prompt you to paste a single `sudo security add-trusted-cert` command in the same terminal — that's the OS-imposed step for adding a cert to the admin trust store, the same one mitmproxy and Charles ask for. The wizard polls and auto-detects when it's applied.

**Using a venv instead of pipx:**

```bash
python3 -m venv ~/.venvs/vigil
source ~/.venvs/vigil/bin/activate
pip install ai-runtime-monitor
ai-monitor --setup
ai-monitor --start
```

**From source (for development):**

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor-enterprise
cd ai-runtime-monitor-enterprise
python3 -m venv .venv && source .venv/bin/activate
make install   # editable install with dev deps
make start     # launches dashboard on http://localhost:9081
```

### What `ai-monitor --setup` prints on first run

On macOS Sequoia (15) and later, expect output like this:

```
══════════════════════════════════════════════════════════════
  AI Runtime Monitor — First-Time Setup
══════════════════════════════════════════════════════════════

  This tool monitors AI coding agents on YOUR machine.
  All data stays local. Nothing leaves your computer.
  You control what's monitored and can purge anytime.

[1/5] Ensuring unique monitoring certificate...
  ✅ Certificate: AI Runtime Monitor - <your-hostname>
  ✅ Valid for: 1 year
  ✅ Restricted to: AI domains only (Name Constraints)

[2/5] Trust the monitoring certificate
  ...
  Trust the certificate? [Y/n]: y

  macOS requires trust changes to be authorized from your
  terminal. Run this one command:

    sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain \
      /Users/<you>/claude_watch_output/ca-cert.pem

  Waiting for trust... (press Enter to check now, Ctrl-C to skip; up to 120s)
```

Paste the sudo command in the **same terminal** the wizard is running in (don't open a new window), enter your macOS password, and within 2-4 seconds the wizard will continue:

```
  ✅ Certificate trusted. Continuing setup.

[3/5] System proxy
  ...
[4/5] Browser extension
  ...
[5/5] Dashboard token + permissions
  ...

  ✅ Setup complete — Vigil is ready
```

Re-running `ai-monitor --setup` after this is idempotent — Step 1 reports "Reusing existing certificate," Step 2 reports "Certificate already trusted," and the wizard exits 0 quickly without touching state.

### Troubleshooting

**`externally-managed-environment` from `pip install`** — Homebrew Python protects itself per PEP 668. Use `pipx install ai-runtime-monitor` (recommended) or a venv as shown above. Do not use `--break-system-packages`.

**`python3` itself not found** — install Python 3.10+ from [python.org](https://www.python.org/downloads/) or `brew install python@3.12`.

**Setup says "Certificate trust step failed" but you ran the sudo command** — the wizard polls for 120s. If you finished the paste after the window closed, just re-run `ai-monitor --setup` — Step 1 will reuse the existing cert (no rotation), Step 2 will recognize the trust you applied, and Step 3 onward proceeds. (This is the [Bug 8](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/pull/58) idempotency fix.)

**Setup converges but `ai-monitor --start` still hits `Proxy mode requires the CA to be trusted`** — the sudo command needs all three flags: `-d` (admin domain), `-r trustRoot` (root cert), `-k /Library/Keychains/System.keychain` (target). Without any one, the cert is in the keychain but trust isn't applied. Re-run the command verbatim as the wizard printed it.

**Cert in keychain but trust-settings-export doesn't show it** — usually means the second-stage authorization (`SecTrustSettingsSetTrustSettings`) was denied. This is the [Bug 2](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/pull/59) failure mode the terminal-sudo fallback works around. The wizard's poll loop is the right path; don't try to apply trust via the macOS Keychain Access GUI (also subject to the same restriction on Sequoia+).

**"Address already in use" on port 9081 or 9080** — another process is using the port. Run `lsof -iTCP:9081 -sTCP:LISTEN` to find it, or start Vigil on a different port: `ai-monitor --start --port 9082`.

**Chrome extension card shows errors** — open the extension's "Errors" panel in `chrome://extensions/`. Most common cause: pointing "Load unpacked" at the parent directory instead of the `browser_extension/` folder itself. The wizard prints the exact path during Step 4.

A full step-by-step verification plan with `What to do` / `What should happen` / `How to verify` for each gate lives in the project notes: `~/Documents/vigil-notes/v02-new-laptop-test-plan.md`.

## What Vigil monitors

**Four layers of visibility, zero configuration:**

| Layer | What it captures | How |
|-------|------------------|-----|
| **AI API traffic** | Every prompt, response, token count, and tool call from agents that route through the HTTPS proxy | mitmproxy addon with selective SSL inspection — only AI API hostnames (X.509 NameConstraints) |
| **CLI agent sessions** | Full Claude Code conversation transcripts including system prompts, file reads, bash commands, and tool use | JSONL transcript tailing under `~/.claude/projects/` |
| **Browser AI** | ChatGPT, Gemini, Claude Web, Copilot, Perplexity, DeepSeek conversations | Chrome extension (content script, isolated world) + Chrome history fallback |
| **Process / filesystem / network** | Agent process lifecycle, files read or written, outbound connections, CPU and memory | `psutil` + `watchdog` / FSEvents |

The capture is selective: the proxy's `--allow-hosts` regex only intercepts AI API endpoints. Banking, email, and unrelated traffic flow through untouched.

## Detecting AI coding agent supply chain risk

Modern AI coding agents will happily run `npm install` or `pip install` on a typosquat or a hijacked package if a prompt convinces them to. Vigil watches every install command the agent issues and scores it before the package is installed:

- **Install command parsing** — npm, yarn, pnpm, pip, cargo, go get, gem, brew, apt, npx
- **Typosquat detection** — dozens of known patterns covering Python, npm, and other ecosystems (e.g. `requets` → `requests`, `colurs` → `colors`, `axois` → `axios`)
- **High-risk package flags** — network MITM tools, financial APIs, browser automation
- **Threat intel feeds** — abuse.ch URLhaus + ThreatFox correlation for outbound network targets

This is runtime behavioral monitoring: Vigil sees what the agent actually tries to do, not what's listed in a `package.json` after the fact.

## Credential leak detection

Every captured prompt, response, and tool output is scanned for leaked secrets before it's stored:

- AWS keys (AKIA / ASIA), GitHub tokens (`ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*`), private keys, JWT bearers, Anthropic / OpenAI API keys, Slack webhooks
- Credit cards (Luhn-validated), SSNs (with area/group filtering), phone numbers (context-suppressed), database connection strings
- Severity-ranked alerts (Critical / High / Medium / Low) with drill-down to the exact session turn

Plaintext credentials are masked on display (first 4 + asterisks + last 4) and auto-purged from the local store after 30 days.

## How runtime monitoring differs from static scanners

Static supply chain scanners (Bumblebee, Socket, Snyk, the OSV database) inventory what's in your `package.json` or `requirements.txt` and check it against known-bad lists. They're great at "this version of this package is malicious." Vigil sits in the runtime layer instead: it watches what the agent tries to do as it does it — the install command, the network call, the file write — and flags the behavior, whether or not the specific IOC is on a list yet.

Both approaches are complementary. Static scanners catch known-bad versions before they reach your tree. Vigil catches the agent reaching for something off-list, the credential ending up in a prompt, or the proxy being asked to connect to a host it shouldn't. If you already run a static scanner, treat Vigil as the runtime EDR layer underneath it.

## Who Vigil is for

- **Security engineers** monitoring AI tool usage across an engineering org — what agents are being used, what they're capturing, what credentials might be exposed
- **Developers** running Claude Code, Cursor, or similar agents on their own machine who want a local audit log of what the agent actually did, including which files it read and which APIs it called
- **Incident responders** investigating a suspected supply chain attack via AI coding agents — the local SQLite store has the full conversation, the API traffic, and the install commands the agent issued
- **Anyone curious where their Anthropic / OpenAI spend is going** — token-accurate cost tracking with subscription plan detection and burn-rate forecasting

## Dashboard

The dashboard at `http://localhost:9081` is bearer-token authenticated and bound to localhost by default.

- **Session Explorer** — full conversation timeline replay with Deep Dive cockpit (turn rail, API inspector, context gauge)
- **Live Feed** — real-time stream of all agent events
- **Analytics** — token usage charts, cost trends, tool frequency, model distribution, burn rate
- **System** — process table, network connections, file activity
- **Alerts** — sensitive data alerts with pattern filtering and session-level triage
- **Activity Timeline** — unified chronological feed across all AI sources

## Routing CLI agents through the proxy

```bash
export HTTPS_PROXY=http://127.0.0.1:9080
claude                 # API calls now appear in the API Traffic tab
```

**Per-agent helper:**

```bash
claude-watch --configure claude_code   # Adds HTTPS_PROXY to your shell profile
claude-watch --configure list          # Show supported agents and status
claude-watch --unconfigure             # Remove proxy config from shell
```

## Roadmap (NOT in v0.2)

To be straight with you about what isn't shipped yet:

- **Desktop app conversation capture** — Electron-based AI apps (Claude Desktop, ChatGPT Desktop) don't expose their conversations to Vigil yet; capture happens via the proxy, which sees the API calls but not the rendered UI text. Planned for v0.3.
- **MCP server config scanning** — auditing Model Context Protocol server configurations is on the roadmap, not shipped.
- **Prompt injection detection** — heuristics and ML for prompt-injection patterns. v0.3.
- **Privileged macOS helper** — eliminates the one-time `sudo` paste during setup by shipping a notarized helper that uses `SecTrustSettingsSetTrustSettings` directly. v0.3.
- **Linux + Windows support** — process and filesystem monitoring is partially portable today; the macOS-specific paths (system proxy, keychain) need replacements.

If you need any of these for an enterprise pilot, [file an issue](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/issues) — it helps us prioritize.

## Configuration

Generate a config file:
```bash
ai-monitor --init-config    # Creates ~/.config/ai-runtime-monitor/config.toml
```

**ai-monitor flags:**

| Option | Default | Description |
|--------|---------|-------------|
| `--start` | — | Start monitoring + dashboard. HTTPS proxy on by default since v0.2. |
| `--no-proxy` | — | Start without the HTTPS proxy (JSONL + extension capture only) |
| `--port` | 9081 | Dashboard HTTP port |
| `--setup` | — | First-time wizard (idempotent — reuses an existing valid CA) |
| `--regenerate-ca` | — | Modifier for `--setup`: force CA regeneration |
| `--status` | — | Show runtime status (monitor, proxy, cert, security) |
| `--scan` | — | One-shot process/network scan |
| `--install-service` | — | Install as macOS LaunchAgent (auto-start on login) |
| `--init-config` | — | Generate default config.toml |
| `--version` | — | Print installed version |

**claude-watch flags:**

| Option | Default | Description |
|--------|---------|-------------|
| `--setup` | — | First-time: install mitmproxy, trust cert |
| `--start` | — | Start proxy interceptor |
| `--verify` | — | Health-check proxy setup |
| `--configure <agent>` | — | Configure HTTPS_PROXY for an agent |
| `--unconfigure` | — | Remove proxy config from shell profiles |
| `--analyze` | — | Terminal analysis of latest session |
| `--plot` | — | Generate PNG dashboard charts |
| `--dashboard` | — | Launch standalone web dashboard |

Output directory: `~/claude_watch_output/`

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full API reference, database schema, and security model. See [docs/spec/THREAT-MODEL.md](docs/spec/THREAT-MODEL.md) for the STRIDE threat model and trust-boundary analysis.

## Development

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor-enterprise
cd ai-runtime-monitor-enterprise
make dev       # Install with dev deps
make test      # Run the test suite
make lint      # Lint check
```

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Email: `security@gocloudforge.com`. 48-hour acknowledgement target.

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 GoCloudForge, Inc.
