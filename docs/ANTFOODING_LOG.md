# Antfooding log

Per Q8 of `docs/CC_DISPATCH_phase_3_kickoff.md`: install the latest
build on the dev machine today and use it during the sprint. Daily
entry expected, even if the entry is "nothing surfaced today."

If the build is too unstable to use during development, that itself is
the most important antfooding finding of the sprint — document it.

---

## Day 0 — 2026-05-22

**Status**: Sprint Phase 2 → 3 transition; install not yet run by user.

**Plan**:
1. `make install` from current `main` (sha `3d93105`) on the dev laptop.
2. Verify `ai-monitor --status` returns green.

3. Open dashboard at `http://localhost:9081`, confirm key tabs render
   (Live Feed, Sessions, Supply Chain, Threat Intel, Alerts, Settings).
4. Note any surface-level issues seen during use across the workday.

**Findings**: (to be populated by user after install.)
Status is GREEN but some details not loading 
(.venv) rajanyadav@Mac-2178 ai-runtime-monitor-enterprise % ai-monitor --status
AI Runtime Monitor — Status

  Service:
    LaunchAgent:    ✅ Installed (com.gocloudforge.ai-runtime-monitor)
    State:          ⚠ Loaded but not running

  Core:
    Monitor:        ✅ Running
    Dashboard:      http://localhost:9081
    Database:       ✅ Active (chmod 600 + FileVault)
                    Optional encryption: pip install 'ai-runtime-monitor[security]'

  Proxy:
    mitmproxy:      ✅ Running :9080
    System proxy:   ✅ Enabled
    CA certificate: ✅ Trusted (AI domains only)
    SSL inspection: API + Browser metadata

  Capture matrix:
    Claude Code:      ✅ JSONL + ✅ Proxy
    OpenClaw:         ✅ JSONL
    Claude Desktop:   ✅ Proxy (full capture)
    ChatGPT Desktop:  ✅ Proxy (full capture)
    Cursor:           ✅ Proxy (full capture)
    Chrome claude.ai: ✅ Proxy metadata + Extension content
    Chrome chatgpt:   ✅ Proxy metadata + Extension content
    Chrome gemini:    ✅ Proxy metadata + Extension content
    Ollama:           ✅ Process + Network

  Security:
    CA type:        Custom (AI Runtime Monitor - Mac-45)
    CA constraints: 19 AI domains only
    CA expiry:      2027-04-12
    DB encryption:  ⚠ Unencrypted (install sqlcipher3)
    File perms:     ✅ 600/700 enforced
    Dashboard auth: ✅ Token required
    Data retention: 30 days (auto-purge)

  Reliability:
    Heartbeat:      ✅ 11s ago
    Recent crashes: ⚠ 4 in last 7 days
    Log file:       /Users/rajanyadav/claude_watch_output/logs/monitor.log (0.3MB)

  Extension:
    Host:           chatgpt.com
    Last heartbeat: 2026-05-22T22:18:53.580885+00:00
    Selectors:      ⚠ selectors not matching
(.venv) rajanyadav@Mac-2178 ai-runtime-monitor-enterprise % pwd
/Users/rajanyadav/code/ai-runtime-monitor-enterprise
(.venv) rajanyadav@Mac-2178 ai-runtime-monitor-enterprise % 


**Reproductions / regressions to file**: none yet.


**Audit findings exercised**: C1–C4 are not yet fixed; the antfooding
build still exhibits them. Specifically:
- C2 XSS in `dashboard.html::esc()` — observable by typing
  `"><img src=x onerror=alert(1)>` into a session title field if
  reachable from the browser extension ingest path.
- C4 osascript notification path — observable by issuing a critical
  supply-chain alert and noting that the notification body builds via
  shell=True.

---

## Day N template (copy + adapt for each daily entry)

### Day N — YYYY-MM-DD

**Used for**: <one-line: what tasks did you do with the product today>

**Worked**: <bullet list of things that just worked>

**Friction**: <bullet list of things that slowed you down or surprised you>

**Bug filed**: <issue links or "none">

**Re-deployed?** <yes/no — did you rebuild and reinstall today?>

## Day 1 — 2026-05-22 — Phase 3A antfood pass

Repo state:  integration/phase-3a @ 825f203
Daemon:      PID 52027, running with full SSL inspection
Duration:    ~30 min using the dashboard + 20 min Claude in Chrome probe

### What I used it for
Ran a Claude Code session while watching the Live Feed populate.
Drilled into Supply Chain and saw strapi-plugin-cron and mistralai
both correctly flagged as MALICIOUS with full registry intelligence.
Checked Alerts and observed 564 alerts including the system catching
its own auth token in a Claude Code session capture — the detection
and redaction pipeline working end-to-end was the most striking
moment. Ran Claude in Chrome through a structured 9-test probe.

### What surprised me
- The system caught its own token leak with proper masking. That's
  a positive signal I didn't expect to see this clearly.
- Claude in Chrome found that /api/* endpoints serve data without
  server-side token check. The HTML layer is gated; the API is not.
  This is a real gap, promoting to C1-FOLLOWUP critical.
- A noisy TypeError fires every 3 seconds on loadProcesses() polling.
  Pre-existing, Lane D1 scope, but visible.

### Structured probe
docs/CLAUDE_CHROME_PROBE_2026-05-22.md — verdict was READY TO MERGE
with the C1-FOLLOWUP caveat noted above.

### Verdict
HOTFIX REQUIRED before integration → main: C1-FOLLOWUP
(server-side token enforcement on /api/* routes).
After C1-FOLLOWUP merges to integration/phase-3a, ready to merge
integration → main with all 5 commits preserved via rebase-merge.

