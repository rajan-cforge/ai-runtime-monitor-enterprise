# Sprint state — Vigil v0.2 launch

**Started**: 2026-05-21
**Target ship**: 2026-05-28 (Day 7)
**Lead**: orchestrator (Claude Code main session, Opus 4.7)
**Source of truth**: this file. Updated at every phase transition.

---

## Phase ledger

| Phase | Description                                  | Status      | PR(s)         |
|-------|----------------------------------------------|-------------|---------------|
| -1    | Tooling foundation + branching policy        | DONE        | #1, #2        |
| 0     | Read all docs + repo state                   | DONE        | (no PR)       |
| 1     | Reconciliation log                           | DONE        | #3            |
| H1    | Unscheduled CI rescue (Py3.9 PEP-604 fix)    | DONE        | #4            |
| 2     | Stop and present Q1-Q10                      | DONE        | (no PR)       |
| 3.0   | Plugin integration audit (capability map)    | DONE        | #5            |
| 3.0a  | Q1-Q10 record + governance docs              | DONE        | #6            |
| 3.0b  | Smoke workflow + antfood loop + RUNBOOK      | DONE        | #8, #9, #10   |
| 3.0c  | setuptools_scm install fix                   | DONE        | #11           |
| 3.0d  | Antfood loop robustness (Phase B)            | DONE        | #16           |
| 3A.C1 | Security fix C1 (control-plane bcrypt)       | DONE        | #13 → #20     |
| 3A.C2 | Security fix C2 (dashboard.html XSS)         | DONE        | #15 → #20     |
| 3A.C3 | Security fix C3 (sync.py fail-open)          | DONE        | #14 → #20     |
| 3A.C4 | Security fix C4 (osascript primitive)        | DONE (preventive — see audit annotation) | #12 → #20 |
| 3A    | Antfood + probe + retraction + incident      | DONE        | #17, #19, #20 |
| 3A.aux| Liveness roadmap + SSDLC enforcement doc     | DONE / IN-FLIGHT | #18 / #21 |
| 3B    | Quality Gates Q1                             | READY       | (awaiting proceed) |
| 3C    | Multi-agent harness install                  | BLOCKED on 3B |             |
| 3D    | Quality Gates Q2                             | BLOCKED on 3C |             |
| 3E.B  | Lane B — extension scanner                   | BLOCKED on 3D |             |
| 3E.C  | Lane C — Vigil brand site                    | BLOCKED on 3D |             |
| 3E.D1 | Lane D1 — dashboard.html polish              | BLOCKED on 3D |             |
| 3F    | Audit Highs batch fix                        | BLOCKED on 3E |             |
| 3G    | Quality Gates Q3 (post-launch)               | POST-LAUNCH |               |
| 3H    | Launch (Vigil v0.2 — CLI + Homebrew)         | DAY 7       |               |

**Removed from this sprint per Q3**: Lane A (Tauri shell) — deferred to v0.3.

---

## Per-lane brief (post-Q1-Q10)

### Lane B — extension scanner
- Home: `src/claude_monitoring/extension_scanner/`
- Routes: inline into `monitor.py::DashboardHandler`, each tagged
  `# TODO(M6): extract to api/extension_routes.py during monitor.py split`
- Deps to add: `pytest-asyncio>=0.23`, `python-Levenshtein>=0.25`
- Rubric: `.claude/rubrics/lane-B-scanner.md` (installed in Phase 3C)
- Specialist: `extension-scanner-specialist` (installed in Phase 3C)

#### Lane B — additions from Day 1 antfooding probe (post-launch scope)

- **LB-RESEARCH-PRIOR** (alert quality)
  - Research-session false-positive prior. When session title contains
    research indicators ("research", "how does", "best-in-class",
    "explore the") AND `turn_number ≤ 5` AND context is `tool_result`,
    apply `confidence: low` override and mark
    `likely_false_positive: true`. Currently the `env_file` detector
    does this via a repeat heuristic; extend to multi-pattern clusters
    in research sessions.
- **LB-CREDENTIAL-DUMP** (new alert category)
  - When ≥4 credential pattern types fire simultaneously in a single
    `tool_result`, emit a higher-level `credential_dump` alert type
    with consolidated metadata. Currently this fires as N individual
    alerts; a single "CREDENTIAL DUMP — N patterns" alert is more
    actionable. Observed at probe Alert #4 (ACMS session, 6 patterns
    at once).
- **LB-CONFIDENCE-CONSISTENCY** (alert state machine)
  - See D1-FP-CONSISTENCY for description. If the Lane D1 fix proves
    insufficient (e.g., requires broader state-machine rework), this
    is the post-launch follow-through.

### Lane C — Vigil brand site
- Product name: **Vigil**
- Domain: `vigil.gocloudforge.com` (subdomain via CNAME, DNS by user)
- Hosting: Vercel
- Local path: `/Users/rajanyadav/code/airuntimemonitor-site`
- CLI binary: `vigil`
- Brew tap: `gocloudforge/tap/vigil`
- PyPI: `vigil-monitor`
- Stripe Payment Link: deferred to launch day; placeholder `STRIPE_PRO_LINK`
- Rename scope: customer-surface only — repo, Python package, internal
  docs stay as `ai-runtime-monitor-enterprise` / `claude_monitoring`

### Lane D1 — dashboard.html polish
- Scope: in-place security fixes + visual cleanup, no framework change
- C2 XSS fix is the entry work (split into `escHtml`/`escAttr`/`escJs`/`escUrl`)
- React migration is Lane D2, post-launch
- **Dashboard URL UX gap** (added 2026-05-22 during Phase 3A antfooding):
  - Option A — `monitor.py` prints the dashboard URL to stderr before
    `redirect_stdio_to_log()` runs in `--daemon` mode. Currently the URL
    only lands in `~/claude_watch_output/logs/monitor.log`, so users who
    daemon-start can't see it without grepping the log.
  - Option D — the auth-required failure page reads
    `~/claude_watch_output/.dashboard_token` and renders the correct
    `?token=...` URL inline, so users who arrive without a token get
    unblocked without log spelunking.
  - Rationale: the developer install path (`brew` + `pip install`) hits
    `--daemon` mode; v0.3+'s Tauri setup wizard solves it for the
    consumer install path, but the dev path needs this regardless.
- **E. Supply Chain install-history prompt access** (added 2026-05-22
  during Phase 3A antfooding):
  - Each install row must surface the full originating session prompt,
    not just the truncated preview.
  - Two UI options to evaluate together: hover tooltip with full prompt,
    OR expandable row that reveals full prompt + clickable session-ID
    link to jump to the originating session in the Sessions tab.
  - Acceptance: from any Supply Chain install row, the user can in
    ≤1 click read the exact prompt that triggered the install AND
    navigate to that session.
- **D1-NULL-GUARD: `loadProcesses()` classList null TypeError** (added
  2026-05-22 during Phase 3A antfooding):
  - Every ~3 seconds the dashboard's `loadProcesses()` poll throws a
    TypeError attempting `.classList.add(...)` on a null element
    (the row template doesn't exist on first paint OR the selector
    misses after a re-render).
  - Add a null-guard before the `.classList` mutation; ideally also
    short-circuit the poll's render path if the target row is absent
    so we don't burn cycles each tick.
  - Acceptance: open dashboard with empty Sessions, wait 60s, browser
    console has zero TypeErrors from `loadProcesses`.
- **F. Alerts cards expandable inline detail pane** (added 2026-05-22
  during Phase 3A antfooding):
  - Each Alert card opens inline (no modal) into a details pane
    containing:
    - Full context: 5 lines before and 5 lines after the matched span
    - Session turn link (deep-link into the originating Sessions row)
    - Classifier reasoning: which rule fired, severity rationale
    - Recommended remediation (per-rule playbook text)
    - History of pattern occurrences (count + first/last seen
      timestamps, optionally a sparkline)
  - Acceptance: SOC-analyst-style triage of any alert is possible
    without leaving the Alerts tab.

#### Lane D1 — additions from Day 1 antfooding probe

- **D1-FP-SUPPRESSOR** (alert quality)
  - Test fixture key suppressor. If a matched key token appears within
    50 chars of a masking demonstration pattern (`->`, `****`,
    `[REDACTED]`), set `likely_false_positive: true` regardless of
    confidence. Catches the `AKIAJ5TESTXXXXXXXXXX` false positive
    observed in probe.
- **D1-DEDUP-TURN** (alert quality)
  - Turn-window deduplication. When multiple `sensitive_data` events
    fire within a 5-second window in the same session with the same
    pattern and similar hashes, consolidate into a single alert with
    `keys_found: N`. Currently 4 separate criticals fire for 1 logical
    CI log read.
- **D1-TYPOSQUAT-UI** (UI consistency)
  - Supply Chain registry intelligence panel: when a package is flagged
    as typosquat, suppress "Scanned — no known vulnerabilities" and
    display "N/A — typosquat flagged" instead. CVE absence is irrelevant
    for typosquat placeholders.
- **D1-FP-CONSISTENCY** (alert quality)
  - Confidence re-classification consistency. Same hash should not be
    reclassified from `low/likely_fp:true` to `critical/likely_fp:false`
    based on a different search context. Require positive contextual
    evidence (outbound send, assignment statement, credentials file
    pattern) for upward reclassification. Observed at probe Alert #2
    (hash `5acb12837d61733d`).

### Lane A — Tauri (DEFERRED)
- Re-evaluate at v0.3 planning. No work this sprint.

---

## Audit critical findings

Per `docs/AUDIT_2026-05-21.md` (now on `main` after PR #17). All four
fixes merged via the integration → main PR with rebase strategy
preserving individual commits.

| ID | Branch (deleted post-merge)      | Status    | Commit on main |
|----|----------------------------------|-----------|----------------|
| C1 | `security/c1-bcrypt`             | DONE      | `94e3345`      |
| C2 | `security/c2-xss-esc`            | DONE      | `73232b3`      |
| C3 | `security/c3-sync-fail-open`     | DONE      | `346115a`      |
| C4 | `security/c4-osascript-injection`| DONE (preventive — annotated as non-finding in audit doc) | `f99ae4f` |
| C1-FOLLOWUP | (none — never opened)   | RETRACTED | annotated in `docs/AUDIT_2026-05-21.md` |

Phase 3A closed on 2026-05-23 via PR #20 (rebase-merge). Antfood
evidence at `docs/ANTFOODING_LOG.md` Day 1. Structured probe at
`docs/CLAUDE_CHROME_PROBE_2026-05-22.md`. Credential discoveries at
`docs/incidents/2026-05-22-credential-discovery.md` (NOT ROTATING
disposition).

---

## Discipline (every phase)

- `make ci-fast` before every commit (target lands in Phase 3B)
- `make ci-local` before every push (target lands in Phase 3B)
- Conventional commits, no `Co-Authored-By: Claude` trailer
- Update this file at every phase transition
- Update `docs/RECONCILIATION_LOG.md` whenever a new discrepancy surfaces
- Daily entry to `docs/ANTFOODING_LOG.md`

---

## What success looks like

End of week 1:
- C1-C4 fixed and validated by regression tests
- Quality Gates Q1 in CI, blocking new regressions
- Multi-agent harness installed and exercising the gates
- Lanes B and C shipped (extension scanner + Vigil brand site)
- Lane D1 shipped (dashboard.html polished, XSS hardened)
- Audit Highs triaged
- Vigil v0.2 released via CLI + Homebrew tap

End of week 2:
- Quality Gates Q2 in CI
- Lane D2 React migration in flight
- High findings batch closed
- 7+ days of antfooding log entries
- First seed-fund conversations
