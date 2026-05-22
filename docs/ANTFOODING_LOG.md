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

**Reproductions / regressions to file**: none yet.

**Baseline expectation** (per Guardrail 4 in
`docs/CC_DISPATCH_phase_3_safety_addendum.md`): the integration → main
PR for Phase 3A must show parity against this baseline. The CI smoke
workflow `.github/workflows/smoke.yml` automates the boot-and-render
shape check; the manual antfooding entry below covers what CI cannot:
visual, behavioral, and "feels right" judgment.

What to record when you do the local install (replacing the "to be
populated" line above):

- Dashboard URL: `http://localhost:9081/?token=$(cat ~/claude_watch_output/.dashboard_token)`
- Tabs rendering without console errors: Live Feed, Sessions, Supply
  Chain, Threat Intel, Alerts, Settings, Inventory
- Daemon log path: `~/claude_watch_output/logs/*.log`
- Expected log: no `Traceback`, no `ERROR:`, no `Exception:` lines
- `/api/stats` returns JSON with session/event/alert counters
- A short (~5 min) Claude Code session populates the Sessions tab

The post-fix entry (after `integration/phase-3a` lands) compares
against this list. Any regression blocks the integration → main PR.

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
