# AI Runtime Monitor — Live Demo

A scripted 7-scenario demo that exercises the monitor against realistic
AI agent behavior, including a malicious package, a typosquat, a
credential leak, and four legitimate installs. Takes about 40 seconds
end to end.

Used as the basis for the 90-second pitch recording
(`recording_script.md`).

---

## Quick start

```bash
# 1. Start the monitor (if not already running as a LaunchAgent)
ai-monitor --status          # should say Monitor: ✅ Running
#   or
ai-monitor --start --with-proxy --daemon

# 2. Bring up the sandbox
cd demo && docker compose up -d
docker ps | grep ai-demo-sandbox   # verify it's up

# 3. Run the demo
python run_demo.py

# 4. Verify everything fired
python verify_demo.py
#   → ✅ All 8 demo checks passed.

# 5. Open the dashboard
open "http://localhost:9081/?token=$(cat ~/claude_watch_output/.dashboard_token)"
```

---

## What the 8 scenarios do

| # | Scenario | How it reaches the monitor |
|---|----------|---------------------------|
| 1 | Legit: requests + beautifulsoup4 + flask | JSONL tool_use → JSONL watcher → supply chain |
| 2 | Vulnerable: python-dotenv | JSONL tool_use → OSV scan finds CVEs |
| 3 | **Malicious: strapi-plugin-cron** | JSONL tool_use → matches KNOWN_MALICIOUS_PACKAGES → CRITICAL alert |
| 4 | High-capability: python-binance | JSONL tool_use → risk score +3 for financial API |
| 5 | **Credential leak: AWS key in claude.ai response** | POST /api/browser/ingest → auto-mask + sensitive_data alert |
| 6 | **Typosquat: requets** | JSONL tool_use → matches KNOWN_TYPOSQUATS → CRITICAL alert |
| 7 | Elevated: playwright | JSONL tool_use → risk score +3 for browser automation |
| 8 | **Version-pinned backdoor: mistralai==2.4.6** | JSONL tool_use → matches KNOWN_MALICIOUS_VERSIONS → CRITICAL alert (May 2026 reported supply-chain attack) |

Scenarios 1, 2, 4, 7 also run real `pip install` inside the Docker
container so `docker exec ai-demo-sandbox pip list` shows the packages.
Scenarios 3 (malicious) and 6 (typosquat) are JSONL-only because those
packages don't exist on PyPI.

---

## Architecture notes

- **JSONL path is the primary capture mechanism** — `run_demo.py`
  writes `~/.claude/projects/demo-scraper/demo-<timestamp>.jsonl` and
  the `JSONLSessionWatcher` in the running monitor picks it up through
  the exact same code path as a real Claude Code session. No demo-only
  API endpoints. No changes to `src/`.
- **Docker is safe isolation for real installs**, not a monitored
  target. The monitor doesn't observe the container.
- **Typosquat uses `requets`** (not `reqeusts`) because that's what's
  hardcoded in `supply_chain.py::KNOWN_TYPOSQUATS`. Exercising
  unmodified shipping behavior is more defensible for a pitch demo.
- **Credential leak uses browser ingest** (not JSONL) because it
  models a user pasting an AWS key into claude.ai in a browser tab
  (different capture path), and exercises the P1-02 masking fix.

---

## Re-running

`run_demo.py` generates a new `DEMO_SESSION_ID` each run (epoch
seconds), so successive demos don't collide. The dashboard handles
multiple demo sessions cleanly.

---

## Cleanup

```bash
rm -rf ~/.claude/projects/demo-scraper
docker compose down -v
```

Demo rows in `monitor.db` (sessions, events, agent_dependencies,
alerts) can be left in place — they don't interfere with real data.
