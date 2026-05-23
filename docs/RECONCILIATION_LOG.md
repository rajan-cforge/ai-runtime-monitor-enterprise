# Reconciliation Log — 2026-05-21

## How to read this

For each prior prompt, this log captures every assumption that
disagrees with the actual repo, plus the proposed path. Original prompts
stay as audit trail. This log is the canonical record of what gets
built.

Verified state at 2026-05-21 17:30 PT:
- `main` at `d8f56c8` (`infra(pr-template)` merged)
- Python `requires-python = ">=3.9"` (not 3.12 as several prompts assume)
- Source layout: `src/claude_monitoring/*.py` flat (19 files), no
  `api/`, `services/`, `alerts/`, `extension_scanner/` subpackages
- Dashboard: single `src/claude_monitoring/dashboard.html` (~3500 LOC)
  served by stdlib `BaseHTTPServer` from `monitor.py` (4800 LOC)
- Control-plane: separate FastAPI app under `control-plane/cp/`
- Tests: 1319 passed + 5 skipped (not 1015+ as harness prompt assumed)
- Makefile targets present: `help install dev start start-deep verify
  configure stop status test lint format coverage security ci clean`
- Dev deps installed: pytest, pytest-cov, ruff, bandit, pip-audit
- Dev deps **missing**: mypy, pytest-asyncio, python-Levenshtein,
  semgrep, mutmut, detect-secrets, interrogate, radon, xenon, vulture,
  lint-imports
- No `desktop/` directory (Lane A is greenfield)
- No `extension_scanner/` directory (Lane B is greenfield)
- No `claude_monitoring/dashboard/app/` Next.js (Lane D is migration)
- No `.claude/` directory other than `scheduled_tasks.lock`,
  `settings.local.json`, `worktrees/` (harness not yet installed)

---

## CC_PROMPT_00 — multi-agent harness

| Assumption | Reality | Proposed adjustment |
|---|---|---|
| Python 3.12 | `>=3.9`, CI matrix runs 3.9/3.11/3.12/3.13 | Drop 3.12-specific syntax. Use `from __future__ import annotations` if PEP-604 needed. |
| `claude_monitoring/dashboard/` exists | Single `src/claude_monitoring/dashboard.html` + handlers in `monitor.py` | Subagent definitions referring to `claude_monitoring/dashboard/app/components/` are aspirational (Lane D creates them). Don't reference until Lane D lands. |
| `claude_monitoring/alerts/dispatcher.py` exists | No such module. Alerts dispatched inline from `monitor.py::_alert_supply_chain` and friends. | Lane B specialist must write to the actual alert path: `monitor.py::_fire_alert` or new module. Update extension-scanner-specialist prompt. |
| `desktop/src-tauri/` exists | No `desktop/` directory | Greenfield. tauri-rust-engineer subagent only useful after Day 0 Tauri scaffold. |
| 1015+ tests baseline | 1319 passed + 5 skipped | Update CLAUDE.md draft accordingly. |
| `make test`, `make lint`, `make build`, `make dev` | `make test`, `make lint`, `make dev`, **no `make build`** | Stop hook references `make test` and `make lint` — both work. `make build` does not exist; replace any reference with explicit per-lane build commands. |
| `frontmatter` Python package for verification step 5 | Not installed | Replace `python -c "import frontmatter; ..."` with a simpler YAML frontmatter regex check, or `pip install python-frontmatter` as a dev dep. |
| Subagent `extension-scanner-specialist` | Subsystem doesn't exist | Define the subagent, but block dispatching it until Lane B's `claude_monitoring/extension_scanner/` skeleton lands in a precursor commit. |
| `make test` runs `pytest + vitest` | Just pytest. No vitest because no JS testing infrastructure. | Stop hook can call `make test`. Frontend tests await Lane D. |
| `make build` builds dashboard + Tauri | Neither exists yet | Defer the target to Day 5 integration. |
| Hooks at `.claude/hooks/*.sh` executable | Directory will be created | Ensure `chmod +x` in install script. |
| 11 specialist subagents | Only `code-reviewer`, `security-reviewer`, `test-writer`, `doc-writer`, `file-explorer` are useful Day 1. The 5 lane specialists become useful when their lane starts. The 1 `threat-intel-scout` is unused. | Phase 3C installs the 6 generally-useful subagents now. Lane specialists land on their lane branches when the lane opens. |
| `permissions.deny` with `Bash:git push --force*` | Matches policy | Add `Bash:git config*` to deny (CLAUDE.md rule: never touch git config). |
| `.claude/settings.json` | User already has `.claude/settings.local.json` | Use `settings.json` (project-shared) for harness; preserve user's `settings.local.json` (machine-local). |

---

## CC_PROMPT_01 — extension scanner (Lane B)

| Assumption | Reality | Proposed adjustment |
|---|---|---|
| `claude_monitoring/extension_scanner/` package home | Doesn't exist | Greenfield. Create under `src/claude_monitoring/extension_scanner/`. |
| `claude_monitoring/api/extension_routes.py` | No `api/` subpackage. Routes live inline in `monitor.py::DashboardHandler.do_GET/do_POST`. | Either (a) add routes as new branches in `monitor.py`, or (b) create the `api/` package as part of Lane B's scope. Recommend (a) for sprint speed; (b) is post-launch refactor (audit M6). |
| Existing FastAPI app on dashboard | Dashboard is stdlib `BaseHTTPServer`. control-plane (`control-plane/cp/app.py`) is FastAPI. | Wire `/api/extensions/*` into the stdlib dashboard handler, not FastAPI. |
| `alerts/dispatcher.py` contract | Doesn't exist | Read `monitor.py::_check_supply_chain` (line 1190) as the alert-dispatch reference pattern. |
| `from typing import Any` and PEP-604 (`X | None`) syntax | py39 target requires `from __future__ import annotations` | Add the future import to every new module. |
| `python-Levenshtein` library | Not installed | Add to `[project.optional-dependencies] dev` or pin in scanner module deps. Alternative: built-in `difflib.SequenceMatcher.ratio()` for typosquat detection. |
| `pytest-asyncio` | Not installed | Add to dev deps. Or rewrite the threat-intel client as sync with `requests` (already a dep via control-plane). |
| `mypy --strict` in verification | mypy not installed | Defer to Quality-Gates Q2. Replace step 1 with `ruff check`. |
| Severity enum collides with `threat_intel.py` `assess_risk` severity strings | Existing returns `"critical"/"high"/"medium"/"low"`. New `Severity` enum matches. | Reuse the existing string convention; no new enum needed unless Lane B prefers stricter typing. |
| 9 risk rules, including R007 AI-correlated installs | Existing JSONL watcher in `monitor.py` knows agent activity per session | R007 implementation must query `agent_activity` table; document the join. |
| `osascript` for native notifications on critical findings | Audit C4 flagged `osascript` `shell=True` injection in existing `lifecycle.py` | Lane B's notification path must use argv-list `subprocess.run([osascript, -e, ...])`, NOT `shell=True`. Add to specialist prompt. |
| `~/.ai-runtime-monitor/threat_intel_cache/` | Existing cache is `~/claude_watch_output/` | Use `config.get_output_dir() / "extension_threat_intel"` for consistency. |
| Coverage target ≥85% on new module | Repo-wide gate is 70% (Q1 raises to 90% eventually). New code at ≥85% aligns. | Keep ≥85%. |

---

## CC_PROMPT_02 — brand site (Lane C)

Separate repo (`rajan-cforge/airuntimemonitor-site`). Greenfield.
Reconciliation is just confirming Day-0 prereqs (covered by Q5).

| Assumption | Reality | Proposed adjustment |
|---|---|---|
| Repo at `/Users/rajan/code/airuntimemonitor-site` | Username is `rajanyadav`; path is likely `/Users/rajanyadav/code/airuntimemonitor-site` | Confirm path with user (Q5). Doesn't affect code, only docs/dispatch scripts. |
| Domain `airuntimemonitor.com` registered | Unknown | Q5 covers. |
| Stripe Pro Payment Link configured | Unknown | Q5 covers. Use env placeholder `STRIPE_PRO_LINK` for build. |
| Brand voice rules cited from `.claude/skills/brand-voice-check/` | Skill doesn't exist yet (Phase 3C installs it) | Phase 3C must precede or accompany Lane C launch. |
| Lighthouse ≥95 on all routes | N/A until built | No reconciliation needed pre-build. |

---

## CC_PROMPT_03 — Tauri shell (Lane A)

Greenfield. Reconciliation focuses on prereqs and integration points.

| Assumption | Reality | Proposed adjustment |
|---|---|---|
| `npm create tauri-app@latest desktop` | Node/npm/cargo installation unknown | Pre-flight: confirm `node --version`, `cargo --version`, `tauri --version` all >= required. (Q3.) |
| Apple Developer Program enrollment | Unknown | Q3 covers. Hard blocker for notarized DMG. |
| `tauri signer generate` keypair | Doesn't exist | Day 0 work. Q3. |
| `~/Library/LaunchAgents/com.gocloudforge.ai-runtime-monitor.plist` | Repo's `lifecycle.py` already manages a plist at `~/Library/LaunchAgents/com.gocloudforge.airuntimemonitor.plist` (different identifier) | Lane A must reuse the existing identifier or coordinate a rename. Recommend reuse — changing identifier breaks existing user installs. |
| GET `/api/status` endpoint | Doesn't exist (audit found this — actual health check is `/api/feed` or `/api/stats`) | Tauri `daemon.rs::get_status` calls `/api/stats` instead. |
| `tauri-plugin-updater` GitHub Releases endpoint with `latest.json` | No existing `latest.json` publishing step. Existing `release.yml` workflow builds Python wheel only. | Add `latest.json` generation to release workflow as part of Lane A. |
| `entitlements.plist` with `allow-unsigned-executable-memory` | Required by Tauri runtime — fine | Confirm signing identity supports this entitlement. |
| Memory footprint <60 MB at idle | Goal, not enforceable in spec | Track in rubric, not as hard gate. |
| `desktop/scripts/notarize.sh` references `$APPLE_ID`, `$TEAM_ID`, `$APP_SPECIFIC_PASSWORD` env vars | Convention is fine | Add to release workflow secrets list. |
| Dashboard auth via shared token | Existing dashboard token at `~/claude_watch_output/.dashboard_token` (mode 0600) — Tauri must read this for any authenticated calls | Document in cert_install.rs / daemon.rs. |

---

## CC_PROMPT_04 — dashboard UI polish (Lane D) — THE BIG ONE

This prompt assumed an existing React dashboard. Reality: single
`dashboard.html` file. The "polish" is actually "migrate to React, then
polish."

| Assumption | Reality | Proposed adjustment |
|---|---|---|
| `claude_monitoring/dashboard/` directory with React app | Single `src/claude_monitoring/dashboard.html` (~3500 LOC inline JS+HTML+CSS) | Q2 covers the choice. Three viable paths: (a) migrate to React in Lane D, (b) split into Lane D1 (polish HTML) + Lane D2 (React migration post-launch), (c) defer Lane D entirely and ship with current HTML. |
| FastAPI serving the dashboard | stdlib `BaseHTTPServer` in monitor.py | If migrating to React, the served path becomes `<output>/dashboard_app/dist/index.html` instead of inline string. Need to add asset-serving logic to `DashboardHandler.do_GET`. |
| Lane B's `/api/extensions` ready as input | Lane B is also greenfield in this sprint | Strict serial dependency: Lane D cannot start until Lane B's API is testable. |
| TanStack Table virtualization for >200 rows | Sessions table sometimes shows hundreds of rows | Real win for the migration. |
| Shiki syntax highlighting | Build-time | If migration ships, fine. If staying on HTML, use highlight.js or no syntax highlighting (current behaviour). |
| SSE for live alerts via `/api/alerts/stream` | No such endpoint exists. Existing polling via `/api/feed` | Either add SSE to monitor.py (real change) or migrate to use polling with TanStack Query. |
| Audit C2 (XSS in `esc()`) "fixed by Lane D migration" | Migration could absorb the fix, but blocks on Lane D's choice in Q2 | If Q2 = (c) "defer Lane D", C2 fix must be a separate dashboard.html patch (still required for launch). If Q2 = (a) or (b), C2 can be baked into the React rewrite. **Choice impacts execution order for C1-C4 batch.** |
| Audit H21, H22 (other dashboard.html XSS) | Same family as C2 | Same coupling as above. |

---

## CC_PROMPT_QUALITY_GATES — already triaged

Prior session split this into Q1/Q2/Q3 cuts (`infra/quality-gates-q1`
branch already exists locally with no commits). The triage:

- **Q1 (this sprint, Phase 3B)**: Makefile target additions
  (`ci-fast`, `ci-local`), pre-commit hooks (hygiene + ruff + bandit),
  detect-secrets baseline, pip-audit workflow, SBOM via cyclonedx-py,
  coverage-ratchet script, file/function size scripts, branch
  protection doc (not yet applied).
- **Q2 (Phase 3D)**: Rewrite `importlinter.cfg` against actual modules
  (start with one rule), introduce mypy non-strict, expand ruff in
  staged PRs, add interrogate at 60%.
- **Q3 (Phase 3G, post-refactor)**: gitsign for signed commits,
  mutation testing on ≥90% modules, full mypy --strict after monitor.py
  split, apply branch protection.

No change needed here. Validated as-written.

---

## Audit critical findings (C1-C4) status

All four locations confirmed extant in current main.

| ID | Title                                       | File                                  | Est fix | Tests needed                                     |
|----|---------------------------------------------|---------------------------------------|---------|--------------------------------------------------|
| C1 | control-plane endpoint API keys never verified | `control-plane/cp/auth.py`, `registry.py` | 4h      | regression: bcrypt verify on ingest + bypass test |
| C2 | `dashboard.html::esc()` does not escape quotes | `src/claude_monitoring/dashboard.html` | 3h      | Playwright E2E with `"><script>` payload         |
| C3 | `sync.py::_sanitize_string` swallows exceptions, fail-open | `src/claude_monitoring/sync.py:308-312` | 2h      | malformed-input unit test                        |
| C4 | `lifecycle.py` osascript `shell=True`        | `src/claude_monitoring/lifecycle.py:412-438` | 1h      | shell-meta injection unit test                   |

**Coupling**: C2 fix overlaps with Q2 Lane D scope. Execution order
depends on Q2 answer.

---

## Scope changes that need user approval

1. **Q1 — Quality Gates Q1/Q2/Q3 split.** Accept as triaged?
2. **Q2 — Lane D scope.** (a) migrate now (3-4 day extension), (b)
   split D1 polish + D2 React post-launch, or (c) defer Lane D
   entirely. **This choice affects C2's fix location.**
3. **Q3 — Lane A scope.** Tauri now or ship CLI + Homebrew first and
   add Tauri post-launch?
4. **Q4 — Lane B home.** Confirm `src/claude_monitoring/extension_scanner/`
   (flat layout, fits current convention)?
5. **Q5 — Lane C prereqs.** Domain registered? Stripe Payment Link
   configured? Parallel with Lane B from Day 1?
6. **Q6 — Criticals batching.** One `security/audit-criticals` branch or
   four separate branches?
7. **Q7 — `Co-Authored-By: Claude` trailers.** 3 existing commits
   (`8f07f9e`, `770eef2`, `7a8d712`). Rewrite (force-push), allowlist,
   or defer signed-commit gate?
8. **Q8 — Antfooding.** Install own latest build during the sprint?
9. **(New) Q9 — Lane B prereq.** Does Lane B create `src/claude_monitoring/api/`
   as a real subpackage, or wire routes inline into `monitor.py` for
   speed? (Recommend: inline for sprint; refactor with audit M6.)
10. **(New) Q10 — Python deps.** Lane B needs `pytest-asyncio` and
    `python-Levenshtein` (or `difflib` fallback). Add to `pyproject.toml`
    `[dev]`?

---

## Execution order proposal

Per CC_PROMPT_MASTER_orchestrator Phase 3 unchanged:

- Phase 3A — Critical security fixes C1–C4 (per Q6 branching)
- Phase 3B — Quality Gates Q1 cut
- Phase 3C — Multi-agent harness (this prompt; adjusted via Q1–Q5)
- Phase 3D — Quality Gates Q2
- Phase 3E — Lane execution (per Q1–Q8)
  - Lanes B + C in parallel from Day 1
  - Lane A from Day 2 (if Q3 = yes)
  - Lane D per Q2
- Phase 3F — Audit Highs batch fix
- Phase 3G — Quality Gates Q3
- Phase 3H — Launch

**One adjustment surfaces**: if Q2 = (c) defer Lane D, then C2 dashboard
XSS fix must move from Phase 3A into a small dashboard.html PR before
launch. If Q2 = (a) migrate now, C2 fix is absorbed into Lane D's React
rewrite.

---

## Plugin/MCP discovery (Phase -1A complete)

Documented in `docs/TOOLING.md`. Summary:
- codebase-memory-mcp connected (14 tools)
- Plugins installed: superpowers v5.1.0, security-guidance, code-review,
  frontend-design, playwright, feature-dev
- Index status: ready, 2792 nodes / 6185 edges, last indexed 2026-05-18

Index is 3 days stale (since 5/18). The 4 lane prompts + branching
infra commits since then are docs-only — no graph changes. Detect-changes
run unneeded for Phase 1.

---

## Phase 2 → Phase 3 — Q1-Q10 answered (2026-05-22)

User answers landed via `docs/CC_DISPATCH_phase_3_kickoff.md`.

| #   | Question                              | Decision |
|-----|---------------------------------------|----------|
| Q1  | Quality Gates Q1/Q2/Q3 triage         | **Accept as triaged.** Q1 this sprint, Q2 next, Q3 post-launch. |
| Q2  | Lane D scope                          | **(b) Split.** D1 = polish dashboard.html in place this sprint (security fixes + visual cleanup, no framework change). D2 = React migration as its own post-launch week. C2 XSS fix lands in dashboard.html's escape pipeline now. |
| Q3  | Lane A Tauri                          | **DEFER to v0.3.** Ship CLI + Homebrew tap this sprint. Tauri ships with its own launch moment later. |
| Q4  | Lane B home                           | **Confirmed**: `src/claude_monitoring/extension_scanner/`. |
| Q5  | Lane C brand                          | Product name **Vigil**. Domain `vigil.gocloudforge.com` (subdomain under existing Squarespace-managed gocloudforge.com — no domain registration). CLI binary `vigil`. Brew tap `gocloudforge/tap/vigil`. PyPI `vigil-monitor`. Local path `/Users/rajanyadav/code/airuntimemonitor-site`. Vercel hosting via CNAME (DNS handled outside session). Stripe Payment Link deferred to launch day; use placeholder `STRIPE_PRO_LINK` env var. **Rename customer-surface only** — do NOT rename repo, Python package, or internal docs. |
| Q6  | C1-C4 batching                        | **Four separate branches**: `security/c1-bcrypt`, `security/c2-xss-esc`, `security/c3-sync-fail-open`, `security/c4-osascript-injection`. |
| Q7  | Co-Authored-By: Claude trailers       | **(c) Defer signed-commits gate** to post-launch (Q3 of quality gates). Document the 3 pre-policy SHAs (`8f07f9e`, `770eef2`, `7a8d712`) as historical exceptions in `docs/COMMIT_HISTORY_EXCEPTIONS.md`. New policy prospective from next commit. |
| Q8  | Antfooding                            | **Yes**. Day-0 entry in `docs/ANTFOODING_LOG.md` (created in this PR). |
| Q9  | Lane B API routes                     | **Inline into `monitor.py::DashboardHandler`**. No new `api/` subpackage this sprint. Every new handler tagged `# TODO(M6): extract to api/extension_routes.py during monitor.py split`. |
| Q10 | Lane B dev deps                       | **Add both** to `pyproject.toml [project.optional-dependencies.dev]`: `pytest-asyncio>=0.23`, `python-Levenshtein>=0.25`. No difflib fallback (R008 typosquat scoring against 100 popular extensions every scan would spike CPU). |

### New phase: Phase 3.0 — plugin integration audit

Per dispatch, runs before Phase 3A. Reconciled CC_PROMPT_00's custom
subagents/skills against the 6 connected plugins. Net: drop 4 of 11
subagents, drop 3 of 5 skills. Capability map appended to
`docs/TOOLING.md`. Phase 3C installs the resolved set.

### Adjustment summary

- C2 XSS fix lands in dashboard.html now (Q2 = (b)), not via React rewrite.
- Lane A removed from this sprint's parallel execution diagram.
- 7 subagents + 2 skills install in Phase 3C (not 11+5).

---

## Architectural decision — dashboard host (2026-05-22)

Decided during Phase 3A antfooding setup.

**Dashboard is HTML served by the Python daemon on `localhost:9081`,
opened in the user's default browser. Tauri (v0.3) provides menu-bar
tray, LaunchAgent supervision, setup wizard, and auto-update — but
never hosts the dashboard. `tauri-plugin-shell::open` delegates to the
default browser.**

Implications:
- No Electron, no Tauri WebView for the dashboard.
- React migration (Lane D2, post-launch) stays a normal SPA, not
  bundled into a native app.
- Future Linux/Windows builds get the dashboard for free via browser.
- Bookmarkable URLs, standard DevTools, no app-update treadmill for UI.

Rejected alternatives:
- Tauri WebView hosting the dashboard — adds packaging surface, breaks
  the cross-platform-by-default property, ties UI update cadence to
  native-app update cadence.
- Electron shell — same drawbacks, plus larger memory footprint and
  Chromium update overhead.
