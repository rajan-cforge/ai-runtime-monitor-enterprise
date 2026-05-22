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
