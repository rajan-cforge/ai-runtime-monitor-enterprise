# Vigil

[![CI](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ai-runtime-monitor.svg)](https://pypi.org/project/ai-runtime-monitor/)
[![Python](https://img.shields.io/pypi/pyversions/ai-runtime-monitor.svg)](https://pypi.org/project/ai-runtime-monitor/)

**Endpoint security for the AI developer — monitor what AI coding agents actually do on your machine.**

Vigil is open-source runtime security monitoring for AI coding agents — Claude Code, Cursor, ChatGPT, Copilot, and any agent that runs on your machine or talks to an AI API. It captures conversations, inspects API traffic, watches process and filesystem activity, scans agent-issued install commands for supply chain risk, and detects credentials leaking into AI sessions. Behavioral monitoring at runtime, not static inventory after the fact.

## Install

> macOS today (Sequoia 15 / 26 supported). Linux is best-effort; Windows planned for v0.3.

For v0.2, Vigil installs from source. Same flow for end users, security engineers, and contributors — clone the repo, create a venv, install editable, run setup.

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor-enterprise.git vigil
cd vigil
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
ai-monitor --setup                       # follow prompts; paste sudo command when shown
ai-monitor --start --with-proxy          # daemon + proxy + dashboard at http://localhost:9081

# Then enable API-traffic capture for desktop apps and CLI tools:
export HTTPS_PROXY=http://127.0.0.1:9080
ai-monitor --enable-system-proxy
```

`ai-monitor --status` reprints these two commands as a footer whenever capture isn't fully configured, so you don't need to memorize them.

**Restart any AI app that was already running** before you enabled the proxy — environment variables are read at process start, so a running app can't pick up `HTTPS_PROXY` retroactively:

| App / tool                              | Restart needed? | Why |
| --------------------------------------- | --------------- | --- |
| Claude Code (`claude` CLI)              | **Yes**         | Node process; env vars sticky at fork |
| Claude Desktop                          | **Yes**         | Electron app; same reason |
| ChatGPT Desktop                         | **Yes**         | Electron app; same reason |
| Cursor                                  | **Yes**         | Electron app; same reason |
| Chrome (claude.ai, chatgpt.com, gemini) | **No**          | Extension captures the DOM directly, independent of any proxy. The content script runs whenever you visit the page and reads the rendered conversation — no network interception involved, no env vars to inherit. |
| Ollama (local model)                    | **No**          | Captured by the process + network scanner; doesn't route through the HTTPS proxy at all |
| `curl` / shell scripts                  | Conditional     | Yes if relying on system proxy alone; no if `HTTPS_PROXY` is already in your shell rc |

### First-run capture verification — the right order of operations

After `ai-monitor --start --with-proxy`, the canonical sequence to actually capture desktop apps and CLI agents end-to-end is:

```bash
# 1. Quit anything that was already running with stale environment.
#    Cmd-Q in macOS (not just close the window — the dock icon must disappear):
#      - Claude Desktop
#      - ChatGPT Desktop
#      - Cursor
#    For active `claude` CLI sessions: type /exit, close the shell tab.

# 2. Enable the macOS system proxy (one-shot setting that GUI apps inherit at launch):
ai-monitor --enable-system-proxy

# 3. Persist HTTPS_PROXY in your shell rc so EVERY new terminal exports it:
echo 'export HTTPS_PROXY=http://127.0.0.1:9080' >> ~/.zshrc
echo 'export HTTP_PROXY=http://127.0.0.1:9080'  >> ~/.zshrc
#    Bash users: use ~/.bashrc instead.

# 4. Open a FRESH terminal (the env is per-process; existing shells won't auto-reload).
#    Verify: echo $HTTPS_PROXY    # should print the URL

# 5. Re-launch the apps (Spotlight, Finder, or dock are fine — they read the
#    system proxy at process startup). For CLI tools, start them from the
#    fresh terminal so they inherit HTTPS_PROXY.

# 6. Verify capture is live:
ai-monitor --status
#    Expect:
#      System proxy:    ✅ Enabled
#      Claude Desktop:  ✅ Proxy (full capture)
#      ChatGPT Desktop: ✅ Proxy (full capture)
#      Cursor:          ✅ Proxy (full capture)
#      Chrome <hosts>:  ✅ Extension content    (independent of proxy state)
```

**Why this order matters.** Electron apps and Node CLIs snapshot the environment and read the macOS proxy configuration exactly once — at process start — and keep that view for their entire lifetime. Reconfiguring while they're running has no effect; only the next launch picks up the change. Chrome is the deliberate exception in the matrix above because its extension reads the rendered page DOM rather than the network, so it never depended on proxy state in the first place.

On macOS Sequoia (15) and later, `--setup` will prompt you to paste a single `sudo security add-trusted-cert` command in the same terminal — that's the OS-imposed step for adding a cert to the admin trust store, the same one mitmproxy and Charles ask for. The wizard polls and auto-detects when it's applied.

> Every new terminal where you want to run `ai-monitor` needs `cd vigil && source .venv/bin/activate` first. A published-package install path (PyPI / pipx) is planned for v0.3 alongside the privileged macOS helper.

The companion install guide with prerequisites, the full 5-step wizard walkthrough, and an 8-check verification protocol lives at `docs/INSTALL.md` (and in `~/Documents/vigil-notes/new-laptop-setup-guide.md` for ongoing iteration before it lands in the repo).

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

**`externally-managed-environment` from `pip install -e .`** — you didn't activate the venv. Run `source .venv/bin/activate` (from inside the cloned `vigil/` directory) and re-run `pip install -e .`. Your shell prompt should show `(.venv)` after activation. Do not use `--break-system-packages`.

**`python3` itself not found** — install Python 3.10+ from [python.org](https://www.python.org/downloads/) or `brew install python@3.12`.

**Setup says "Certificate trust step failed" but you ran the sudo command** — the wizard polls for 120s. If you finished the paste after the window closed, just re-run `ai-monitor --setup` — Step 1 will reuse the existing cert (no rotation), Step 2 will recognize the trust you applied, and Step 3 onward proceeds. (This is the [Bug 8](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/pull/58) idempotency fix.)

**Setup converges but `ai-monitor --start` still hits `Proxy mode requires the CA to be trusted`** — the sudo command needs all three flags: `-d` (admin domain), `-r trustRoot` (root cert), `-k /Library/Keychains/System.keychain` (target). Without any one, the cert is in the keychain but trust isn't applied. Re-run the command verbatim as the wizard printed it.

**Cert in keychain but trust-settings-export doesn't show it** — usually means the second-stage authorization (`SecTrustSettingsSetTrustSettings`) was denied. This is the [Bug 2](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/pull/59) failure mode the terminal-sudo fallback works around. The wizard's poll loop is the right path; don't try to apply trust via the macOS Keychain Access GUI (also subject to the same restriction on Sequoia+).

**"Address already in use" on port 9081 or 9080** — another process is using the port. Run `lsof -iTCP:9081 -sTCP:LISTEN` to find it, or start Vigil on a different port: `ai-monitor --start --port 9082`.

**Chrome extension card shows errors** — open the extension's "Errors" panel in `chrome://extensions/`. Most common cause: pointing "Load unpacked" at the parent directory instead of the `browser_extension/` folder itself. The wizard prints the exact path during Step 4.

A full step-by-step verification plan with `What to do` / `What should happen` / `How to verify` for each gate lives in the project notes: `~/Documents/vigil-notes/v02-new-laptop-test-plan.md`.

## What Vigil monitors

**Four layers of visibility — set up once, captures continuously:**

| Layer | What it captures | How |
|-------|------------------|-----|
| **AI API traffic** | Every prompt, response, token count, and tool call from agents that route through the HTTPS proxy | mitmproxy addon with selective SSL inspection — only AI API hostnames (X.509 NameConstraints) |
| **CLI agent sessions** | Full Claude Code conversation transcripts including system prompts, file reads, bash commands, and tool use | JSONL transcript tailing under `~/.claude/projects/` |
| **Browser AI** | Claude Web (claude.ai), ChatGPT (chatgpt.com), Gemini (gemini.google.com) conversations — verified end-to-end in v0.2. Perplexity, Copilot, and DeepSeek have coded support; verification in progress. | Chrome extension (content script, isolated world) + Chrome history fallback |
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
- **Claude Code users** who want to see what their session actually cost — Vigil surfaces the per-message cost that Claude Code writes into its own JSONL session logs (the cost field is computed and recorded client-side by Claude Code; Vigil reads and aggregates). Token counts captured for every intercepted call across all providers; per-call dollar cost for non-Claude-Code traffic (OpenAI, Anthropic API direct, Cohere, etc.) is on the v0.3 roadmap.

## Dashboard

The dashboard at `http://localhost:9081` is bearer-token authenticated and bound to localhost by default.

- **Session Explorer** — full conversation timeline replay with Deep Dive cockpit (turn rail, API inspector, context gauge)
- **Live Feed** — real-time stream of all agent events
- **Analytics** — token usage charts across all providers; Claude Code spend (from the cost field Claude Code writes into its JSONL session logs); tool frequency, model distribution
- **System** — process table, network connections, file activity
- **Alerts** — sensitive data alerts with pattern filtering and session-level triage
- **Activity Timeline** — unified chronological feed across all AI sources

## Routing CLI agents through the proxy

```bash
export HTTPS_PROXY=http://127.0.0.1:9080
claude                 # API calls now appear in the API Traffic tab
```

**Per-agent helper** (uses the lower-level `claude-watch` CLI — see [docs/CLAUDE-WATCH.md](docs/CLAUDE-WATCH.md) for the full flag reference; most users only need the `--configure` form below):

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

**`claude-watch` is a lower-level CLI** for advanced use (proxy-only mode without the dashboard daemon, per-agent shell profile configuration, ad-hoc debugging). Most users never need it directly — `ai-monitor --setup` and `ai-monitor --start --with-proxy` handle the full install + capture flow. Full flag reference: [docs/CLAUDE-WATCH.md](docs/CLAUDE-WATCH.md).

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
