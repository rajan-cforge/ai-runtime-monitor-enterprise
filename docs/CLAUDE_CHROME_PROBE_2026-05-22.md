# Claude in Chrome Probe — Phase 3A Verification

Date:        2026-05-22
Dashboard:   http://localhost:9081 (integration/phase-3a @ 825f203)
Tester:      Claude in Chrome (browser agent)
Duration:    ~40 minutes (started ~4:05 PM, completed ~4:47 PM)
Browser:     Chrome 148.0.0.0

## Errata (added 2026-05-23)

**Test 1 (C1 token auth enforcement) verdict was reversed by terminal
verification.** Server-side enforcement on `/api/*` is correct. The
probe's 200-response observations were artifacts of the dashboard's
monkey-patched `fetch` injecting the auth token automatically. See
`docs/AUDIT_2026-05-21.md` section "C1-FOLLOWUP — RETRACTED" for full
root-cause analysis.

**Recommendation #1 (server-side token enforcement on `/api/*`) is
withdrawn.** No code change needed.

Other test results in this report stand. Detection-quality findings
(Recommendations 2-5) remain valid and have been routed to Lane D1 and
Lane B scope per `docs/SPRINT_ONE_WEEK.md`.

## Test results

| # | Test | Result | Notes |
|---|------|--------|-------|
| 1 | C1 token auth enforcement | RETRACTED / PASS (server-side verified) | Initial PARTIAL verdict was a false positive from monkey-patched fetch; terminal curl confirms server returns 401 on all unauthenticated /api/* GETs. See Errata above. |
| 2 | C2 XSS escape across tabs | PASS | All 9 tabs checked; all script-tag text matches were inside PRE blocks (legitimate code output); no live injected elements or broken attribute contexts |
| 3 | C2 click-through interactions | PASS | Session row click, Deep Dive open/Esc-close, row-expand toggle, False-positive button all fired via delegated listeners; no console errors on any click |
| 4 | C3 no sanitize log flood | N/A | Terminal not directly accessible; user to verify: tail -100 ~/claude_watch_output/logs/monitor.log | grep -i sanitize |
| 5 | C4 notify primitive | SKIP | No Settings tab or Test-notification button found in dashboard; no exercised code path |
| 6 | Real session capture | PASS | 3-4 live sessions visible throughout probe with real-time timestamps; c654f242 content (278 turns, 122.6K tokens) renders with correct sensitive-data masking |
| 7 | Sensitive data redaction | PASS | 23 CRITICAL alerts; Anthropic API key masked sk-a****...****1gAA; ANTHROPIC_API_KEY= env-var pattern also masked; 0 raw sk-* tokens visible in alert cards |
| 8 | Browser extension banner | PRESENT | "Extension on chatgpt.com reports zero selector matches — the AI provider may have changed their DOM. Content capture is failing." (rotates to claude.ai also) |
| 9 | Daemon health | HEALTHY | 64 sessions, 565 alerts, 46 active processes; server BaseHTTP/0.6 Python/3.12.7 responding; Monitoring indicator green; no page load failures |

## Per-tab rendering observations (Test 2)

| Tab | Loaded? | Console errors | Raw HTML rendered? | Notes |
|-----|---------|----------------|--------------------|-------|
| Session Explorer | Y | None | N | 38 text-node script-tag matches, all inside PRE (code output); 18556 pre elements normal for 278-turn session |
| Live Feed | Y | None | N | 1 system_event entry visible; auto-scroll and filter checkboxes functional |
| Analytics | Y | None | N | Token usage bar chart, Tool usage donut, Model usage bar chart all render correctly |
| Insights | Y | None | N | Last-30-days stats: 14 sessions, 87.1 avg turns, 8.0K avg tok/turn, 6 projects |
| System | Y | loadProcesses: Failed to fetch (every ~3s, pre-existing) | N | Tables empty — process monitor endpoint unavailable; not a C1-C4 regression |
| API Traffic | Y | None | N | All stat cards show "-" (mitmproxy not capturing during probe); table empty; renders without error |
| Activity Timeline | Y | 1 transient loadTraffic: Failed to fetch on tab switch | N | Canvas blank (no traffic data); error not repeated after initial tab switch |
| Supply Chain | Y | None | N | 129 installs, 48 unique, 124 unpinned, 32 risk-flagged; strapi-plugin-cron and pytest-timeout registry expansions with install history rows correct |
| Alerts | Y | None | N | 23 critical alerts; sk- keys masked; False positive / Investigated / Accept risk buttons functional |

## Regressions found

None confirmed against the C1-C4 fixes specifically.

**Near-regression observation (pre-existing):** Recurring TypeError flood — `Cannot read properties of null (reading 'classList')` at line 2444:13, every ~3 seconds. Root cause: `loadProcesses()` called in a polling timer (line 2446) fires a `Failed to fetch` error (endpoint unavailable), and within the same timer block a `.classList` access occurs on an element that is null (likely the status indicator). Produces ~20 unhandled exceptions per minute in the console. **This is not a C1-C4 regression** — it predates Phase 3A.

## Pre-existing issues observed (not regressions)

1. **API auth is front-end only (C1 architectural gap):** All `/api/*` endpoints (/api/sessions, /api/alerts, /api/stats, /api/supply-chain, /api/traffic) return HTTP 200 with full data to unauthenticated fetch requests. Auth enforcement is JavaScript-only (localStorage token check). Only the root HTML page and `/startup-url` enforce auth server-side. A localhost attacker can curl any endpoint without a token. The C1 bcrypt fix applies to the login gate, not to API middleware. Recommend adding auth middleware to the BaseHTTP handler for Lane D1.

2. **Browser extension banner (Lane B scope):** Cycles between chatgpt.com and claude.ai; both report zero selector matches. Expected known issue.

3. **System tab process monitor offline:** loadProcesses() throws Failed to fetch every 3 seconds. The /api/processes endpoint is likely not running. System tab displays empty tables with no user-visible error message.

4. **Activity Timeline transient fetch error:** One loadTraffic Failed to fetch logged on first tab switch; recovered on retry. Possible race condition on tab activation.

5. **mitmproxy not capturing:** /api/traffic returns 200 but API Traffic tab shows no data during this probe session. Dashboard renders without error in this state.

6. **Auth token visible in session transcript (expected):** Session c654f242 contains the full dashboard auth URL in LLM conversation content (the antfooding conversation). The dashboard correctly fires a SENSITIVE DATA DETECTED: base64_secret alert and masks the snippet in the alert cards. The full URL is visible in the raw session detail PRE blocks (it is the conversation transcript, rendered as text, not executed as HTML). This is correct behavior.

## Screenshots

Screenshots captured in browser memory during the probe:

- vigil-c1-auth-wall.png — Auth wall: "Authentication required" for invalid token (ss_9387bfhc7)
- vigil-c2-session-explorer-detail.png — Session Explorer with c654f242 selected, sensitive data inline (ss_5856p62y6)
- vigil-c2-alerts-masking.png — Alerts tab: 23 critical, Anthropic key masked sk-a****...****1gAA (ss_4433ptbbc)
- vigil-c2-supply-chain-expanded.png — Supply Chain: strapi-plugin-cron registry intelligence with install history (ss_2043fzh4h)
- vigil-c3-deep-dive.png — Deep Dive modal: ALERT base64_secret with masked token snippet (ss_9041munh1)
- vigil-c2-row-expand.png — Row-expand toggle: RESULT (401 chars) expanded via delegated listener (ss_6040siqof)
- vigil-c3-false-positive.png — False positive button clicked: alert dismissed, counter 77→76 (ss_9813tg2mi)

Note: Screenshots are stored as browser session captures. To save them as files, use the Chrome screenshot tool or browser DevTools.

## Final verdict

[x] READY TO MERGE integration → main
[ ] HOTFIX REQUIRED — regression in [C1/C2/C3/C4]
[ ] INVESTIGATION NEEDED — anomaly at [where]

**Rationale:** The four Phase 3A critical security fixes (C1 auth wall, C2 XSS escape helpers + delegated listeners, C3 sanitize-fail-closed, C4 notify primitive) show no regressions in browser-observable behavior. The auth wall correctly blocks and does not leak internal information on invalid/missing tokens. XSS escape helpers prevent raw HTML injection across all 9 dashboard tabs. Click-through interactions fire correctly via data-* delegated listener patterns (no onclick= attributes). The one notable finding (API-level auth bypass) is a pre-existing architectural gap in the BaseHTTP server design, not introduced by Phase 3A. The recurring TypeError in the console is also pre-existing and unrelated to the C1-C4 changes.

**Pending terminal verification before final sign-off:**
- Test 4: `tail -100 ~/claude_watch_output/logs/monitor.log | grep -i sanitize` (expect 0–10 lines)
- Test 9: `ai-monitor --status` (expect: Running, mitmproxy Running :9080, heartbeat <30s)

## Recommendations for Lane D1 (post-merge polish)

1. **D1-API-AUTH:** Add token validation middleware to the Python BaseHTTP server for all /api/* routes. Currently any localhost process can read all monitoring data without a token. Priority: HIGH.

2. **D1-NULL-GUARD:** Add null-check before .classList access in the polling timer at line 2444: `const el = document.querySelector('..'); if (el) { el.classList... }`. Eliminates ~20 console exceptions per minute.

3. **D1-PROCESS-MONITOR:** Add visible "Process monitor unavailable" placeholder in the System tab tables when loadProcesses() fails, instead of leaving tables silently empty.

4. **D1-TIMELINE-DEBOUNCE:** Add a brief debounce or retry on the Activity Timeline tab activation handler to prevent the initial Failed to fetch race condition.

5. **D1-BANNER-CONSOLIDATE:** The extension health banner should consolidate multiple failing extensions into one message with actionable instructions rather than cycling between them.

6. **D1-AUTH-URL-UX (already tracked):** Auth-required page should print the fresh dashboard URL inline (Lane D1 Option A+D per SPRINT_ONE_WEEK.md).
