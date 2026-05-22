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
| 3.0   | Plugin integration audit (capability map)    | IN-FLIGHT   | #5            |
| 3.0a  | Q1-Q10 record + governance docs              | IN-FLIGHT   | this PR       |
| 3A.C1 | Security fix C1 (control-plane bcrypt)       | NOT STARTED |               |
| 3A.C2 | Security fix C2 (dashboard.html XSS)         | NOT STARTED |               |
| 3A.C3 | Security fix C3 (sync.py fail-open)          | NOT STARTED |               |
| 3A.C4 | Security fix C4 (osascript shell=True)       | NOT STARTED |               |
| 3B    | Quality Gates Q1                             | BLOCKED on 3A |             |
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

### Lane A — Tauri (DEFERRED)
- Re-evaluate at v0.3 planning. No work this sprint.

---

## Audit critical findings

Per `docs/AUDIT_2026-05-21.md` (lives on `audit/adversarial-self-audit`
branch). All four locations confirmed extant.

| ID | Branch                          | Status      |
|----|---------------------------------|-------------|
| C1 | `security/c1-bcrypt`            | NOT STARTED |
| C2 | `security/c2-xss-esc`           | NOT STARTED |
| C3 | `security/c3-sync-fail-open`    | NOT STARTED |
| C4 | `security/c4-osascript-injection` | NOT STARTED |

After C1-C4 merge: update `docs/AUDIT_2026-05-21.md` (on the audit
branch) with resolved-status + commit links.

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
