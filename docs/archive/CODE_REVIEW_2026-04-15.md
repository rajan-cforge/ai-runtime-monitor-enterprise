# AI Runtime Monitor — Comprehensive Code Review

**Date**: 2026-04-15
**Reviewer**: Claude (automated audit via codebase-memory-mcp graph + source reads)
**Scope**: Full codebase
- `src/claude_monitoring/` — main package (~14,044 LOC across 18 files)
- `control-plane/cp/` — fleet control plane (FastAPI)
- `browser-extension/` — Chrome extension
- `tests/` — 1,103 passing tests, ~45 files
**Passes**: 3 (security audit, code quality / modularity, functionality correctness)
**Graph stats**: 2,293 nodes, 4,881 edges, 90 indexed files

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Review Methodology](#2-review-methodology)
3. [Priority Framework](#3-priority-framework)
4. [**P-1 — Product Reality Gaps** (orchestration / scope)](#4-p-1--product-reality-gaps-orchestration--scope-bugs)
5. [P0 — Functionality Bugs](#5-p0--functionality-bugs-wrong-behavior-now)
6. [P1 — Security: CRITICAL & HIGH](#6-p1--security-critical--high)
7. [P2 — Security: MEDIUM](#7-p2--security-medium)
8. [P3 — Security: LOW & INFO](#8-p3--security-low--info)
9. [P4 — Modularity & Framework](#9-p4--modularity--framework-major-refactors)
10. [P5 — Code Quality & Tech Debt](#10-p5--code-quality--tech-debt)
11. [Parallel Execution Plan](#11-parallel-execution-plan)
12. [Testing Strategy](#12-testing-strategy)
13. [Regression Prevention Checklist](#13-regression-prevention-checklist)
14. [Appendix A — All Findings Index](#appendix-a--all-findings-index)
15. [Appendix B — File × Finding Matrix](#appendix-b--file--finding-matrix)
16. [Appendix C — Reviewer's Note on Methodology](#appendix-c--reviewers-note-on-methodology)

---

## 1. Executive Summary

### Overall Assessment

The codebase is a **functional CrowdStrike-style monitoring tool** with breadth of coverage (JSONL watching, process scanning, network monitoring, Chrome history, browser extension, mitmproxy traffic capture, supply-chain scanning) but structural debt that is **compounding faster than it's being paid down**. Between the first review pass (three days ago) and this one, `monitor.py` grew by **+926 lines** despite an extraction of `lifecycle.py`. The dashboard HTTP handler class now contains **40 API handlers** in a single 2,500-line class.

**Equally important**: there is an entire class of bug — **product reality gaps** — where features exist in the UI, the tests pass, and the code is shipped, but the feature does not actually work in production. These are more damaging than classic "bugs" because they undermine the core value prop ("CrowdStrike-style full visibility") while appearing healthy to CI. See [§4 — P-1 Product Reality Gaps](#4-p-1--product-reality-gaps-orchestration--scope-bugs). This category was **missed in the original two passes** of this review and added after the product owner flagged a specific instance (empty Supply Chain → Full Environment table despite the feature existing in code). See [Appendix C](#appendix-c--reviewers-note-on-methodology) for the methodology post-mortem.

### Severity Distribution

| Priority | Category | Count | Est. Effort |
|---------:|----------|------:|------------:|
| **P-1** | Product reality gaps (orchestration/scope) | 7 | 3–5 days |
| **P0** | Functionality bugs | 10 | 3–5 days |
| **P1** | Security CRITICAL + HIGH | 5 | 2–3 days |
| **P2** | Security MEDIUM | 12 | 4–6 days |
| **P3** | Security LOW + INFO | 8 | 2 days |
| **P4** | Modularity / Framework | 14 | 3–5 weeks |
| **P5** | Code quality / tech debt | 11 | 1–2 weeks |
| **Total** | — | **67** | — |

### The Three Findings You Should Fix Before Anything Else

1. **P-1-01 — `run_pip_audit` scans the wrong environment** (`vuln_scanner.py:51`). The scanner invokes `pip-audit --format=json --desc` with no target flag, so it scans the venv of the monitor process itself (`.venv/bin/python`), not the agent projects being monitored. The Supply Chain tab reports "0 records" or near-zero vulnerabilities **not because the agents are clean, but because the wrong tree is being scanned**. This is not a bug in the traditional sense — every test passes, the code works correctly — the **product does not do what it claims to do**.

2. **P0-01 — `SyncAgent._read_sessions` ignores its `last_id` parameter** (`sync.py:135-155`). After 100 sessions on an endpoint, new sessions **silently stop syncing to the control plane**. This is silent data loss on a product whose primary selling point is fleet-wide visibility.

3. **P1-01 — Control-plane API key comparison uses `!=`** (`control-plane/cp/auth.py:15`). Classic byte-timing attack. The control plane is the internet-facing component; the fleet-wide API key protecting all endpoints can be extracted remotely in hours.

### The Top Structural Problem

`monitor.py` at **5,352 lines** is a god file containing 7 unrelated classes including a single 2,500-line `DashboardHandler` class with 40 API endpoints. This is the dominant source of:
- Low cohesion scores (two Louvain clusters at **0.25** and **0.29**)
- Duplicated sensitive-data handling logic that caused **P1-02** (unmasked credentials)
- Coverage stuck at 72% (target 90%) because the class is untestable in isolation
- Per-commit merge friction as the file grows

### Pattern Across Passes

| Pattern | Evidence | Count |
|---------|----------|------:|
| Silent exception swallowing | `except Exception: pass` | 100+ sites |
| Inline circular import workarounds | `from claude_monitoring.X import Y` inside function bodies | 30+ sites |
| Global mutable state | `global X` declarations | 11 sites |
| Raw SQL in handlers | `db.execute("SELECT ...")` scattered across business logic | 100+ sites |
| Duplicated alert pipelines | Sensitive-data handling implemented 3× differently | 3 paths |

---

## 2. Review Methodology

### Tools Used

- **codebase-memory-mcp** — `get_architecture`, `search_graph`, `search_code`, `trace_call_path`, `query_graph` against a Neo4j-backed graph of 2,293 code nodes
- **Direct source reads** via Read tool for verification of each finding
- **Bash** for line counts and diff summaries
- Three sequential audit passes — security, quality/modularity, functionality

### Review Categories

| Category | What We Checked |
|----------|-----------------|
| **Functionality** | Data loss, race conditions, silent failures, incorrect watermarks, type confusion |
| **Security** | Timing attacks, auth bypass, secret masking, TLS, SQL injection, CORS, shell injection |
| **Modularity** | File size, fan-in/out, cohesion clusters, coupling hotspots, circular imports |
| **Design** | Abstraction gaps, duplicated logic, missing patterns, extensibility |
| **Quality** | Dead code, exception handling, test asymmetry, global state |

### What We Did NOT Review

- Browser extension JavaScript internals (beyond contract boundaries)
- Dashboard HTML / frontend JavaScript logic
- Test files (they were used as reference, not audited)
- Build/CI configuration beyond the `.github/workflows/` smoke check

---

## 3. Priority Framework

### Priority Definitions

| Priority | Meaning | SLA |
|---------:|---------|-----|
| **P0** | Wrong behavior in production NOW. Data loss, silent failure, incorrect output. | 1 week |
| **P1** | Exploitable security vulnerability. Direct credential/data exposure. | 1 week |
| **P2** | Security hardening. Defense-in-depth. No single-click exploit. | 1 month |
| **P3** | Security informational. Best practices. | Next quarter |
| **P4** | Structural refactor. Major modularity rework. Long-term maintainability. | 1 quarter |
| **P5** | Small tech debt. Linting, naming, minor dedup. | Opportunistic |

### Rationale for P0 > P1

Functionality bugs are ranked above security vulnerabilities because a tool that gives you **wrong answers** is worse than a tool that has an **exploitable surface** — a silently broken audit trail actively misleads operators, whereas an exploitable surface can be mitigated by network isolation until patched.

### Work Unit Sizing (for parallel agent dispatch)

| Size | LOC changed | Files touched | Est. time | Parallel-safe? |
|------|------------:|--------------:|-----------|---------------:|
| **S** | < 50 | 1–2 | < 2h | Yes |
| **M** | 50–300 | 2–5 | 2–6h | Usually |
| **L** | 300–1000 | 5–15 | 1–3 days | Sequential |
| **XL** | > 1000 | 15+ | > 3 days | Sequential + review gates |

Every P0/P1/P2/P3 finding below is sized **S or M** so they can be dispatched to parallel Claude Code agents in a single batch. P4 findings are mostly **L/XL** and require sequential orchestration.

---

## 4. P-1 — Product Reality Gaps (Orchestration / Scope Bugs)

> **Architect's framing**: This category exists because software can be **correct per its tests** and **wrong per its contract with the user**. These are the bugs that a shipping engineer catches by *using the product like a customer* — not by reading code. A function named `get_full_environment` that exists, has tests, and is not called from any production pathway is a **broken feature masquerading as dead code**. A function named `run_pip_audit` that runs but scans the wrong tree is a **wrong answer masquerading as a working feature**. Both fail the only test that matters: "does the dashboard show the right thing when a customer uses it?"
>
> These findings are ranked **above P0** because functionality bugs produce wrong answers intermittently, but reality gaps produce wrong answers *every single time* — they are deterministically broken features with green test suites.

### How This Category Was Missed

The original two audit passes searched the graph for dead code (functions with zero inbound calls), flagged `get_full_environment`, `is_proxy_enabled`, and `get_mcp_known_servers` as "delete candidates" (P5-06), and moved on. The correct question was **not** "is this dead code?" but rather **"what UI feature was this written to support, and why isn't it wired up?"**

This review now adopts three new heuristics for detecting reality gaps, added to the standing methodology (see [Appendix C](#appendix-c--reviewers-note-on-methodology)):

1. **Orphan production code** — a non-test, non-trivial function that has no inbound CALLS edges. Instead of deleting it, grep the UI (HTML, dashboard JS, product docs) for mentions of the feature the function was clearly written to support.
2. **Scope verification** — for any function that executes a subprocess, a network call, or a filesystem walk, explicitly verify **what tree/namespace/environment** it actually targets at runtime. Test-time mocks erase this entirely.
3. **End-to-end UI smoke** — every dashboard tab should be loaded against a populated DB as part of review, and every "empty state" message observed should be traced back to whether the population path actually runs in production.

---

### P-1-01 — `run_pip_audit` scans the wrong Python environment

- **File**: `src/claude_monitoring/vuln_scanner.py:51-84`
- **Category**: Scope bug / wrong answer
- **Severity**: **CRITICAL** (undermines core value prop)
- **Work unit**: M (single function + tests + likely a brew/npm equivalent)

**What**
```python
def run_pip_audit():
    result = subprocess.run(
        ["pip-audit", "--format=json", "--desc"],
        capture_output=True, text=True, timeout=120,
    )
    ...
```
`pip-audit` with no target flag scans "the current Python environment" — which is the Python executable that ran `subprocess.run`, i.e., the monitor's own venv (`.venv/bin/python`). It does **not** scan the `agent_dependencies` table (packages the agent was observed installing) and it does **not** scan any project's own venv.

**Why (root cause)**
The function was written as a thin `pip-audit` wrapper with the implicit assumption that "the Python environment" means "what the user cares about". For a one-shot developer tool run from the project root, that's true. For a long-lived **monitoring daemon** installed as a LaunchAgent under a venv that only contains the monitor's own runtime dependencies, it's completely wrong.

**So What**
- Dashboard shows "pip-audit ✓ 0 records" regardless of how many vulnerable packages are in the agent projects.
- OSV.dev phase does scan `agent_dependencies` correctly (see line 302-338) — so there's a partial answer, but the "pip-audit" card on the Supply Chain tab is forever a lie.
- CISO demo: "why does the security tool say we have zero Python vulnerabilities when `pip-audit` in our project venv shows 12?" — this is a product-credibility killer.
- Worse: the scan appears green, so the operator trusts it. A false green is worse than a false red.

**How to Fix**
Two fixes, shippable together.

**Fix 1**: Stop scanning the monitor's own venv. Audit the `agent_dependencies` table via `pip-audit --requirement` on a synthetic requirements file built from observed installs:

```python
def run_pip_audit(db):
    """Run pip-audit against packages the agent installed, not the monitor's own venv."""
    import tempfile
    rows = db.execute(
        """SELECT DISTINCT package_name, package_version
           FROM agent_dependencies
           WHERE package_manager = 'pip' AND category = 'package'
           AND package_version IS NOT NULL AND package_version != 'latest'"""
    ).fetchall()
    if not rows:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        for r in rows:
            name = r["package_name"] if hasattr(r, "keys") else r[0]
            version = r["package_version"] if hasattr(r, "keys") else r[1]
            f.write(f"{name}=={version}\n")
        req_path = f.name
    try:
        result = subprocess.run(
            ["pip-audit", "--requirement", req_path, "--format=json", "--desc"],
            capture_output=True, text=True, timeout=180,
        )
        # parse as before
    finally:
        os.unlink(req_path)
```

**Fix 2**: For observed installs with **no pinned version** (`pip install requests` with no version), enrich via the OSV phase only — pip-audit cannot audit unpinned requirements. Mark these as "unpinned — cannot audit" in the dashboard so operators understand the gap.

**Fix 3** (deferred, maybe P4): Maintain a per-project `requirements.txt` view by joining `agent_dependencies` with `sessions.cwd`. Then audit each project's requirements separately and show per-project vuln counts.

**Impact of Fix**
- Real vulnerability counts appear on the Supply Chain tab.
- Aligns `pip-audit` scope with `get_full_environment` (both look at what the **agent** does, not what the **monitor** does).
- Adds a ~5-line temp file creation; negligible perf hit.

**Testing**
- `test_run_pip_audit_uses_requirements_file` — mock `subprocess.run`, seed DB with 3 package rows, assert the call to `pip-audit` includes `--requirement` and the temp file contains the 3 packages.
- `test_run_pip_audit_skips_unpinned` — seed DB with one pinned + one unpinned, assert only the pinned row is in the temp file.
- `test_run_pip_audit_empty_table` — no packages, assert no subprocess call, returns `[]`.
- **Integration test (new)**: spin up a fake project with a known-vulnerable package (e.g., `urllib3==1.25.1`), seed via `agent_dependencies`, run `run_full_scan`, assert the vuln appears in `package_vulnerabilities`.

**Regression Risk**: MEDIUM. Existing tests mock subprocess; they'll need updates. No behavior change for the target DB state, just for the subprocess args.

**Dependencies**: None.

---

### P-1-02 — Supply Chain "Full Environment" view was empty for users on stale code

- **File**: `src/claude_monitoring/vuln_scanner.py:270-284` (now wired), `src/claude_monitoring/supply_chain.py:654-678` (the inventory functions)
- **Category**: Orchestration gap (NOW FIXED in code, but ships stale for existing installs)
- **Severity**: **HIGH** (shipped broken for ≥1 release cycle)
- **Work unit**: S (ensure graceful upgrade path)

**What**
Until recently, `run_full_scan` did not call `get_full_environment()` / `store_environment_packages()`. The functions existed with tests (`test_environment.py::test_store_and_query`, etc.), the DB table existed (`environment_packages`), and the dashboard tab rendered it — but nothing in the production path ever populated it. Users saw **"No environment data. Click 'Scan now' to gather installed packages."** and clicking "Scan now" did nothing to fix it because the scan didn't include that phase.

The fix landed (see `vuln_scanner.py:275-283` — literally comments "Before this phase existed, the table stayed empty forever"), but users on stale versions still see an empty table until they upgrade AND run a fresh scan.

**Why**
- The feature was shipped as three independent pieces: UI tab, DB table, inventory functions. None of the three referenced each other by contract.
- Tests covered each piece in isolation. `test_environment.py` tested `store_environment_packages` with hand-crafted input. `test_vuln_scanner.py::test_scans_all_packages` tested `run_full_scan` **without asserting** that environment data got populated.
- No end-to-end test loaded the Supply Chain tab against a populated DB and asserted the Full Environment section rendered data.

**So What**
- The user discovered this by running the product and seeing the empty tab. **This is the exact bug that a methodical code review should find, and the original two passes did not.**
- Even with the fix in code, operators on stale versions (the user, at the time of reporting) still have empty tables. Upgrade-and-scan is required.
- Every existing field install needs: (a) upgrade, (b) trigger a fresh scan, (c) wait for the environment phase to complete.

**How to Fix**
The code fix has landed. This finding now captures the **process gap**:

1. **Migration trigger**: On monitor startup, if `environment_packages` is empty AND `_scan_state` has never run the environment phase, log a prominent WARNING: *"Supply Chain → Full Environment is empty. Run `ai-monitor --status` and then click 'Scan now' on the dashboard to populate it."*

2. **Startup auto-scan option**: Add `--scan-on-start` flag that runs the environment phase at daemon startup (respecting a 24h cache) so operators don't need to manually click.

3. **Smoke-test addition**: Add an E2E test that loads the dashboard, asserts the Full Environment section renders with >0 rows after a scan has completed. Ties the UI element to the production code path.

**Testing**
- `test_startup_warns_when_env_table_empty` — fresh DB, assert WARN line in log.
- `test_e2e_supply_chain_full_environment_renders` — spin up the server, POST to `/api/supply-chain/scan`, wait for completion, GET `/api/supply-chain/environment`, assert response has packages.
- Regression test: remove `get_full_environment()` from `run_full_scan`, assert the E2E test fails. This locks the contract in place.

**Regression Risk**: LOW.

**Dependencies**: None for the code; but should be coordinated with a user-facing release note.

---

### P-1-03 — `get_brew_packages` assumes `brew` is on PATH in LaunchAgent context

- **File**: `src/claude_monitoring/supply_chain.py:633-651`
- **Category**: Environment assumption / scope bug
- **Severity**: HIGH
- **Work unit**: S

**What**
```python
def get_brew_packages():
    try:
        result = subprocess.run(
            ["brew", "list", "--versions"],
            capture_output=True, text=True, timeout=15,
        )
```
When the monitor runs as a LaunchAgent via `launchctl`, the `PATH` environment variable is the minimal system default (`/usr/bin:/bin:/usr/sbin:/sbin`). Homebrew installs to `/opt/homebrew/bin` (Apple Silicon) or `/usr/local/bin` (Intel) — **neither is on the LaunchAgent PATH by default**. The subprocess will fail with `FileNotFoundError`, and the `except Exception: pass` at line 650 silently returns an empty list.

**Why**
The code was tested from a user shell where `brew` is on PATH. LaunchAgent context inherits `launchd`'s minimal environment, not the user's shell.

**So What**
- On macOS installs (the primary target platform per CLAUDE.md), `get_brew_packages()` **always returns []**.
- The "Full Environment" view shows Python packages (pip works because it's in the venv) but **zero brew packages** on every install.
- The user doesn't know their brew inventory is missing — the UI just shows fewer packages than reality.

**How to Fix**
```python
def get_brew_packages():
    brew_paths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
    brew_bin = next((p for p in brew_paths if os.path.exists(p)), None)
    if brew_bin is None:
        get_logger().info("brew not found at standard locations; skipping brew inventory")
        return []
    try:
        result = subprocess.run(
            [brew_bin, "list", "--versions"],
            capture_output=True, text=True, timeout=30,
        )
        # ... existing parsing ...
```
Or use an absolute path lookup via `shutil.which` but with the augmented PATH:
```python
def _find_brew():
    paths = os.environ.get("PATH", "").split(":") + ["/opt/homebrew/bin", "/usr/local/bin"]
    for p in paths:
        candidate = Path(p) / "brew"
        if candidate.exists():
            return str(candidate)
    return None
```

**Testing**
- `test_get_brew_packages_with_custom_path` — patch `/opt/homebrew/bin/brew` to exist, assert subprocess called with that path.
- `test_get_brew_packages_when_brew_missing` — patch no brew paths exist, assert logs info, returns `[]`.
- **E2E test**: run the scanner under a subprocess with a stripped PATH, assert brew packages still get inventoried if brew is installed.

**Regression Risk**: LOW.

**Dependencies**: None.

---

### P-1-04 — `get_pip_packages` scans the monitor's venv, not agent environments

- **File**: `src/claude_monitoring/supply_chain.py:618-630`
- **Category**: Scope bug (same pattern as P-1-01)
- **Severity**: HIGH
- **Work unit**: M

**What**
```python
def get_pip_packages():
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=15,
        )
```
Calling `pip list` runs `pip` from whichever venv the monitor is in, listing **the monitor's dependencies** (`requests`, `mitmproxy`, `psutil`, `cryptography`, …) — **not** the packages the user's agents are running with.

**Why**
Same root cause as P-1-01: the function was written as "give me what's installed", without grounding in *which environment*.

**So What**
- The "Full Environment" view, once wired (P-1-02), will show the monitor's own dependencies as if they were the user's environment.
- A developer reading the dashboard will see `mitmproxy==10.x` and think they installed it — they didn't; the monitor did.
- Combined with P-1-01, **two separate functions in `vuln_scanner.py` and `supply_chain.py` both scan the wrong environment**, producing a coherent but entirely wrong picture.

**How to Fix**
Strategy A (simplest): Deprecate `get_pip_packages()` and replace its feed-in with the observed `agent_dependencies` join:
```python
def get_full_environment(db):
    """Build the environment view from observed agent installs plus brew."""
    pip_from_observed = db.execute(
        """SELECT package_name AS name, package_version AS version, 'pip' AS manager
           FROM agent_dependencies
           WHERE package_manager = 'pip' AND category = 'package'"""
    ).fetchall()
    brew = get_brew_packages()
    return [dict(r) for r in pip_from_observed] + brew
```

Strategy B (more accurate): For each agent session that has `cwd` set, check if a `pyproject.toml` / `requirements.txt` / `venv/` exists in that directory and run `pip list` inside it. Much more complex; a P4-size task.

**Testing**
- `test_get_full_environment_uses_agent_deps_not_monitor_venv` — seed `agent_dependencies` with 3 packages, assert the output contains those 3 (plus brew), not the monitor's `requests` / `mitmproxy` / etc.

**Regression Risk**: MEDIUM. Changes the data shape slightly. Adjust dashboard column headers if needed.

**Dependencies**: Ship with P-1-01 as a bundle (both scope bugs in the same subsystem).

---

### P-1-05 — Environment phase runs but dashboard doesn't auto-refresh after completion

- **File**: `src/claude_monitoring/dashboard.html` (Supply Chain tab JS), `monitor.py:_api_supply_chain_scan_progress`
- **Category**: UX / wiring
- **Severity**: MEDIUM
- **Work unit**: S

**What**
After a scan completes, the progress panel shows "done" but the Full Environment table beneath it does not automatically re-fetch. The user must click "All" or refresh the page to see the newly-populated data.

**Why**
The progress endpoint and the environment endpoint are not linked in the frontend; the frontend polls `/scan-progress` but doesn't trigger a `/environment` refetch on state transition.

**So What**
Operators click Scan Now, wait, see "done" next to Full Environment, but the table below is still "No environment data" — and they conclude the feature is broken. Even though it worked.

**How to Fix**
In `dashboard.html`, in the polling loop that updates scan progress, detect the transition from `running` → `done` for the `environment` phase and trigger a refetch of `/api/supply-chain/environment`:

```js
async function pollScanProgress() {
  const prev = window._scanProgress || {};
  const state = await fetchJSON('/api/supply-chain/scan-progress');
  window._scanProgress = state;
  renderProgress(state);
  // Transition detection:
  for (const [phase, info] of Object.entries(state.per_source || {})) {
    if ((prev.per_source?.[phase]?.status !== 'done') && info.status === 'done') {
      if (phase === 'environment') await refreshEnvironmentTab();
      if (phase === 'pip-audit' || phase === 'osv') await refreshVulnerabilityList();
    }
  }
  if (state.running) setTimeout(pollScanProgress, 1500);
}
```

**Testing**
- Playwright E2E: click Scan Now, wait for `environment` phase to hit `done`, assert Full Environment table has >0 rows **without** a manual refresh.

**Regression Risk**: LOW.

**Dependencies**: Ships standalone, but better after P-1-02 / P-1-04 land.

---

### P-1-06 — Browser AI count stuck at 0 despite ChatGPT/Claude capture wiring

- **File**: `src/claude_monitoring/monitor.py:_api_browser_ingest`, `_api_stats`
- **Category**: Orchestration / counter wiring
- **Severity**: MEDIUM
- **Work unit**: S

**What**
The user's dashboard screenshot shows "Browser AI: 0" despite the browser extension being installed and the endpoint being reachable (`_api_browser_heartbeat` has data). The stats endpoint computes Browser AI count from `browser_sessions` but doesn't include extension-captured rows, OR the extension isn't POSTing successfully, OR the dedup window drops everything.

**Why (investigation needed)**
Three possible root causes — requires verification:
1. `_api_browser_ingest` at `monitor.py:2339-2354` dedups on `content_hash` with a 7-day window. For a long-running test install, every captured message matches and gets dropped as duplicate. **Likely**.
2. The `_api_stats` counter queries `SELECT COUNT(*) FROM browser_sessions` filtered by some time window; if the window doesn't match the ingest timestamps, count stays at zero. **Possible**.
3. Extension auth is silently rejected and the user never sees 401s because the extension logs to browser console only. **Possible given P2-01**.

**So What**
Even though browser capture is a marquee feature (listed in the top-level stats bar), it shows 0 on the user's dashboard with no indication why. Loss of user trust in the feature.

**How to Fix**
Add **diagnostic counters** visible in the Browser AI section:
- `ingest_received_total` — bumped on every POST regardless of outcome
- `ingest_stored_total` — bumped on successful INSERT
- `ingest_deduped_total` — bumped on duplicate skip
- `ingest_failed_total` — bumped on exception

Surface these via `/api/browser/extension-health` so the dashboard can show *"400 ingests received, 397 deduped, 2 stored, 1 failed"* — which immediately explains the 0 state.

**Testing**
- Unit: POST an ingest event, assert `ingest_received_total` += 1.
- Integration: POST 10 identical events, assert `ingest_deduped_total` += 9.

**Regression Risk**: LOW.

**Dependencies**: Ties with P2-01 (browser extension auth) for full diagnostic coverage.

---

### P-1-07 — Watch the other orphans: `is_proxy_enabled`, `get_mcp_known_servers`

- **Files**: `src/claude_monitoring/config.py:191, 197`
- **Category**: Possible orchestration gaps (investigate before deleting)
- **Severity**: MEDIUM (investigation task)
- **Work unit**: S per function

**What**
My original review flagged these as dead code in P5-06. Given the `get_full_environment` miss, I am no longer confident they're actually dead. Each one needs a product-aware investigation before deletion.

| Function | Config key | UI feature it might serve |
|----------|-----------|--------------------------|
| `is_proxy_enabled` | reads `proxy.enabled` from TOML | Probably the "should I even start mitmproxy?" gate in status checks |
| `get_mcp_known_servers` | reads `mcp.known_servers` | The MCP Stats / MCP Servers dashboard tabs (confirmed to exist — `_api_mcp_stats`, `_api_mcp_servers` at `monitor.py:3788, 3885`) |

**Why**
The user's config file has sections for these features. The dashboard has UI for them. The accessor functions exist. Graph says zero callers. This is the exact pattern of P-1-02.

**So What**
Without investigation, either:
- Delete them and break a feature that worked yesterday (tests pass because nothing depends on them), OR
- Leave them and ship a feature that doesn't read its own config (silent config-drift).

**How to Fix**
For each function:
1. Search the dashboard HTML for the corresponding feature name.
2. Trace whether any production path reads the config key in question.
3. If orphaned: either wire it up (matching the apparent intent) OR delete it AND the associated UI AND the associated docs.
4. Write a test that asserts the config key is honored end-to-end.

**Testing**
- For each function, an integration test: set the config key, exercise the feature, assert the config value is reflected in the output.

**Regression Risk**: LOW (investigation task).

**Dependencies**: None.

---

### Product Reality Gap — How to Find More

For the remaining review cycles, run this checklist against every dashboard tab:

| Tab | Data source endpoint | Populated by | Test asserts population? |
|-----|---------------------|--------------|--------------------------|
| Session Explorer | `/api/sessions` | `JSONLSessionWatcher._ensure_session` | ✓ (`test_jsonl_watcher.py`) |
| Live Feed | `/api/feed` | `push_live_event` from multiple sources | Partial |
| Analytics | `/api/stats` | Joins across 4 tables | ✓ |
| Insights | `/api/insights` | Computes from events | ✓ |
| System | `/api/processes`, `/api/connections`, `/api/files` | `ProcessScanner`, `NetworkMonitor`, `FileActivityHandler` | ✓ |
| API Traffic | `/api/traffic` | `ClaudeWatchAddon` (mitmproxy) | ? |
| Activity Timeline | `/api/activity/timeline` | Joins across events | ✓ |
| Supply Chain → Packages | `/api/supply-chain` | `agent_dependencies` — populated by `_check_supply_chain` | ✓ |
| Supply Chain → Tool Executions | derived from events | `_process_user_message` / `_process_assistant_message` | ✓ |
| Supply Chain → System Tools | `/api/supply-chain/environment` | `run_full_scan` → `get_full_environment` | **NEWLY wired — P-1-02** |
| Supply Chain → Full Environment | `/api/supply-chain/environment` | same as above | **Was broken, now fixed** |
| Browser AI stats | `/api/stats` | `_api_browser_ingest` | ? (see P-1-06) |
| MCP Stats / Servers | `/api/mcp/*` | ? | ? (see P-1-07) |
| Alerts | `/api/alerts` | `_check_sensitive` / `_api_browser_ingest` | ✓ but P1-02 bug |

Rows marked `?` require manual verification. This table should be maintained as a living document in `tests/e2e/COVERAGE_MATRIX.md`.

---

## 5. P0 — Functionality Bugs (Wrong Behavior NOW)

### P0-01 — SyncAgent silently stops syncing after 100 sessions

- **File**: `src/claude_monitoring/sync.py:135-155`
- **Category**: Data loss / watermark
- **Severity**: CRITICAL (silent data loss on flagship feature)
- **Work unit**: S (single function + 2 tests)

**What**
`_read_sessions(self, conn, last_id)` accepts `last_id` as a parameter but **never uses it**. The query is:
```python
rows = conn.execute("SELECT * FROM sessions ORDER BY rowid LIMIT 100").fetchall()
```
No `WHERE rowid > ?`, no `OFFSET`. Every sync cycle returns the same first 100 sessions by rowid.

**Why (root cause)**
The comment at line 137 says *"Sessions use UPSERT, so send all (CP handles dedup)"*. The author's assumption was that sending "all" sessions is safe because the CP upserts. But "all" was silently capped at 100 by the `LIMIT` clause, and the rowid ordering means the 101st+ session is **never** selected.

Compounding: `sync.py:95` increments the session watermark by `len(new_sessions)` regardless of whether those rows were actually new. After a few cycles, `watermarks['sessions']` grows beyond the actual session count, but `_read_sessions` doesn't use the watermark for filtering anyway.

**So What (impact)**
- Any endpoint with >100 sessions (reached within hours of heavy use) **stops reporting new sessions** to the fleet view.
- The local dashboard is unaffected (sessions are read directly from SQLite).
- The control plane's fleet dashboard shows stale data with no warning.
- CISO buying this product for fleet observability gets silently wrong numbers.

**How to Fix**
```python
def _read_sessions(self, conn, last_id):
    rows = conn.execute(
        "SELECT * FROM sessions WHERE rowid > ? ORDER BY rowid LIMIT 100",
        (last_id,),
    ).fetchall()
    results = [...]  # unchanged
    return results, (rows[-1]["rowid"] if rows else last_id)
```
Also change the caller in `_do_sync` (line 77) to capture and store the new max rowid instead of `len(new_sessions)` increment:
```python
new_sessions, new_sessions_watermark = self._read_sessions(conn, watermarks.get("sessions", 0))
...
"watermarks": {
    "events": watermarks.get("events", 0) + len(new_events),  # already correct
    "sessions": new_sessions_watermark,
    ...
},
```

**Impact of Fix**
- Fixes silent data loss.
- Schema unchanged; `sync_state.last_synced_id` semantics align with how `_read_events` already uses it.
- Existing endpoints with stale watermarks will re-sync old sessions once (acceptable — CP dedups via UPSERT).

**Testing**
- Unit test `test_sync.py::test_read_sessions_honors_last_id` — insert 150 sessions, call with `last_id=100`, assert only rowids 101–150 returned.
- Unit test `test_sync.py::test_sync_watermark_advances_monotonically` — run `_do_sync` twice on a growing DB, assert watermark advances by actual rowid delta, not by +100 each cycle.
- Regression test — confirm 150 sessions end up in the CP after 2 sync cycles.

**Regression Risk**
LOW. The function has one caller inside `_do_sync`. The new contract (returns tuple) is a single-site change.

**Dependencies**: None. Can ship standalone.

---

### P0-02 — SyncAgent session watermark increments by wrong value

- **File**: `src/claude_monitoring/sync.py:95`
- **Category**: Data integrity
- **Severity**: HIGH
- **Work unit**: S (bundled with P0-01)

**What**
```python
"sessions": watermarks.get("sessions", 0) + len(new_sessions),
```
The `sessions` watermark is treated as a **counter** (incremented by count) but the events watermark above it is **also** treated as a counter, while the query at line 160 (`WHERE id > ?`) treats it as a **rowid**. The semantics are inconsistent.

**Why**
No clear mental model for what "watermark" means. The schema column is `last_synced_id` which implies "max rowid seen", but sync.py line 94-96 uses it as "count of rows ever sent". Two different semantics in the same data structure.

**So What**
Even after P0-01 fixes the session query, the watermark will still drift if the semantics aren't aligned. The events watermark at line 94 (`+len(new_events)`) is also wrong — it works by accident today because events table rowids are contiguous from 0 and events are deleted only via bulk purge, but any gap (from `INSERT OR IGNORE` dedup failures) causes the counter to misalign from actual rowids.

**How to Fix**
Change all three watermark updates to max-rowid semantics (aligned with the column name `last_synced_id`):
```python
"watermarks": {
    "events": new_events[-1]["client_event_id"] if new_events else watermarks.get("events", 0),
    "sessions": new_sessions_max_rowid,
    "api_calls": new_api_calls[-1]["client_call_id"] if new_api_calls else watermarks.get("api_calls", 0),
},
```

**Testing**
- Test that `INSERT OR IGNORE` causing a gap in event rowids doesn't break watermark advancement.
- Test that watermark never decreases across sync cycles.

**Regression Risk**: MEDIUM. Existing deployments will re-sync any rows whose rowid > current watermark. CP deduplication (UPSERT) handles this.

**Dependencies**: Bundle with P0-01.

---

### P0-03 — Browser ingest reports success for failed writes

- **File**: `src/claude_monitoring/monitor.py:2387, 2423`
- **Category**: Audit trail / observability
- **Severity**: HIGH
- **Work unit**: S

**What**
```python
try:
    db.execute("INSERT INTO browser_sessions ...")
    stored += 1
except Exception:
    continue   # silently skipped, but `stored` not decremented
```
And immediately below, the sensitive-alert INSERT wraps in `except Exception: pass`. The response at line 2432 is `{"stored": stored, "alerts": alerts}` where `alerts` was incremented *before* the insert attempt (line 2394).

**Why**
Optimistic increment pattern. Counter increments happen before the write attempt, then exceptions silently drop the write.

**So What**
- The browser extension sees HTTP 200 and `alerts: 5` and assumes 5 sensitive alerts were stored. If 3 of them failed to INSERT (e.g., unique constraint collision, locked DB), the extension's telemetry is wrong.
- Under sustained load with `database is locked` errors, the dashboard shows 0 new alerts while the extension confirms "all delivered".
- An adversary flooding the ingest endpoint could cause `stored` to report success while actually corrupting the audit trail.

**How to Fix**
```python
try:
    cur = db.execute("INSERT INTO browser_sessions ...")
    if cur.rowcount > 0:
        stored += 1
    else:
        skipped += 1
except Exception as exc:
    failed += 1
    get_logger().warning("browser_ingest insert failed: %s", exc)
    continue
```
Return `{"stored": stored, "skipped": skipped, "failed": failed, "alerts": alerts}`. Also move the `alerts += len(matches)` AFTER the INSERT succeeds.

**Testing**
- Force a DB error (set read-only), assert `failed` counter is returned and the response is not 200 (change to 207 Multi-Status or a structured error).
- Unit test with a corrupt `events` table (missing columns) asserting the alert increment happens only on success.

**Regression Risk**: LOW. Response shape change is additive.

**Dependencies**: None.

---

### P0-04 — `_scan_state` reassignment defeats its own lock

- **File**: `src/claude_monitoring/monitor.py:4460-4515`
- **Category**: Concurrency bug
- **Severity**: HIGH
- **Work unit**: S

**What**
```python
with _scan_state_lock:
    _scan_state = _new_scan_state()      # REBINDS the module global
    _scan_state["running"] = True
```
The lock guards mutation but the code **rebinds the name**. Any reader that captured a reference to the old `_scan_state` dict before this line continues to read the stale dict.

**Why**
Mixing "rebind module global" with "lock protects mutation" doesn't compose. The lock synchronizes mutations to a single dict, but `_new_scan_state()` creates a new dict and rebinds — readers holding the old reference see stale data.

**So What**
- Progress callback (`_progress_cb` at line 4479) captures `_scan_state` via the `global` keyword, so it correctly reads the new binding *if* it runs after the rebind.
- But `_api_supply_chain_scan_progress` at line 4519 uses `with _scan_state_lock: snapshot = json.loads(json.dumps(_scan_state))` — if a caller had captured the variable reference before the lock (unlikely, but possible in dev tooling), they would read stale data.
- The more realistic bug: the `_new_scan_state()` factory returns a fresh dict with `per_source: {...}`. After rebinding, any thread that did `state = _scan_state; state["per_source"]["osv"] = ...` before the rebind writes to the **old orphaned dict**.

**How to Fix**
Never rebind. Mutate in place:
```python
with _scan_state_lock:
    if _scan_state["running"]:
        ...return 409...
    _scan_state.clear()
    _scan_state.update(_new_scan_state())
    _scan_state["running"] = True
```

Or better — use a dataclass with a single `reset()` method and stop using module globals:
```python
@dataclass
class ScanState:
    running: bool = False
    phase: str = "idle"
    per_source: dict = field(default_factory=dict)
    # ...
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def reset(self):
        with self._lock:
            self.running = False
            self.phase = "idle"
            self.per_source.clear()

SCAN_STATE = ScanState()
```

**Testing**
- Race test: spawn 2 threads calling `_api_supply_chain_scan_post` simultaneously, assert one gets 409 and the other proceeds without corrupting state.
- Progress callback test: verify progress updates from the `_runner` thread are visible to the next `_api_supply_chain_scan_progress` call.

**Regression Risk**: MEDIUM. Anywhere else in the code that does `_scan_state = ...` needs to change to `_scan_state.update(...)`.

**Dependencies**: None.

---

### P0-05 — `_alert_dedup` dict accessed without lock from multiple threads

- **File**: `src/claude_monitoring/monitor.py:1127-1177`
- **Category**: Concurrency bug
- **Severity**: MEDIUM (Python dicts are GIL-safe for individual ops, but compound ops are not)
- **Work unit**: S

**What**
```python
if dedup_key in self._alert_dedup:   # read
    ...
    self._alert_dedup[dedup_key] = existing_id   # write
if len(self._alert_dedup) > 500:
    self._alert_dedup.clear()   # mutation
```
`_alert_dedup` is an instance attribute on `JSONLSessionWatcher`. The watcher runs in a background thread, but the same `JSONLSessionWatcher` instance is also referenced by the dashboard handler's `_check_sensitive` path (indirectly, via shared event storage). Under concurrent dispatch, `len(self._alert_dedup) > 500` + `.clear()` is not atomic.

**Why**
Instance-level cache without explicit threading consideration. The class also holds `self._file_lock` (line 485) for file positions, showing the author knows about threading — but missed this dict.

**So What**
- Race: thread A reads `len() > 500` → True, thread B inserts a new key, thread A calls `clear()`, thread B's key is lost.
- Worse: if two threads enter the `if dedup_key in _alert_dedup` check simultaneously for the same key, both think they're "first" and both fall through to the INSERT.
- Symptom: duplicate alerts appear in the dashboard for the same `(session, pattern, value)` combination, which undermines the dedup feature.

**How to Fix**
Add `self._alert_dedup_lock = threading.Lock()` in `__init__` and wrap all access:
```python
with self._alert_dedup_lock:
    if dedup_key in self._alert_dedup:
        existing_id = self._alert_dedup[dedup_key]
        # ... update SQL ...
        return
    # after INSERT:
    self._alert_dedup[dedup_key] = row[0]
    if len(self._alert_dedup) > 500:
        self._alert_dedup.clear()
```

**Testing**
- Multi-threaded stress test: 10 threads calling `_check_sensitive` with the same `(session, pattern)`. Assert exactly 1 alert row in DB.

**Regression Risk**: LOW. Lock is contained to the dedup path.

**Dependencies**: None.

---

### P0-06 — `_LOGGER_CACHE` double-init race

- **File**: `src/claude_monitoring/lifecycle.py:54-74`
- **Category**: Concurrency bug
- **Severity**: LOW (leak, not corruption)
- **Work unit**: S

**What**
```python
def get_logger():
    global _LOGGER_CACHE
    if _LOGGER_CACHE is not None:
        return _LOGGER_CACHE
    # ... creates handler, sets up logger ...
    _LOGGER_CACHE = logger
```
Check-then-assign without a lock. Under cold start with concurrent callers (e.g., multiple daemon threads starting), two `RotatingFileHandler` instances can be added to the same `logging.Logger` object.

**Why**
Classic double-checked-locking omission.

**So What**
Every log line gets written twice. Log files bloat at 2× expected rate, rotation triggers sooner than configured, parseable-log analytics count duplicates.

**How to Fix**
```python
_LOGGER_LOCK = threading.Lock()

def get_logger():
    global _LOGGER_CACHE
    if _LOGGER_CACHE is not None:
        return _LOGGER_CACHE
    with _LOGGER_LOCK:
        if _LOGGER_CACHE is not None:
            return _LOGGER_CACHE
        # ... setup ...
        _LOGGER_CACHE = logger
        return logger
```
Also guard against adding duplicate handlers: the `if not logger.handlers` check at line 65 helps but isn't sufficient under the race.

**Testing**
- Spawn 20 threads calling `get_logger()` simultaneously. Assert `len(logger.handlers) == 1`.

**Regression Risk**: NONE.

**Dependencies**: None.

---

### P0-07 — `get_thread_db()` connection leaked on early raise in `_runner`

- **File**: `src/claude_monitoring/monitor.py:4488-4512`
- **Category**: Resource leak
- **Severity**: MEDIUM (SQLite can exhaust file descriptors after many scans)
- **Work unit**: S

**What**
```python
def _runner():
    global _scan_state
    try:
        from claude_monitoring.vuln_scanner import run_full_scan
        db = get_thread_db()
        try:
            results = run_full_scan(db, progress_cb=_progress_cb)
        finally:
            db.close()
    except Exception as exc:
        ...
```
If `get_thread_db()` itself raises (e.g., DB locked, disk full) or if `run_full_scan` import fails, `db` is never assigned → `finally` never closes it. The outer `except Exception` swallows the error.

**Why**
The `try/finally` only wraps the execution, not the acquisition.

**So What**
Under error conditions, every scan attempt leaks a connection. After N failures you hit SQLite's max connection limit and the process becomes unresponsive.

**How to Fix**
```python
def _runner():
    global _scan_state
    db = None
    try:
        from claude_monitoring.vuln_scanner import run_full_scan
        db = get_thread_db()
        results = run_full_scan(db, progress_cb=_progress_cb)
        # ... update state ...
    except Exception as exc:
        # ... update state ...
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
```

Or better: use a context manager wrapper.
```python
@contextlib.contextmanager
def thread_db():
    conn = get_thread_db()
    try:
        yield conn
    finally:
        conn.close()

# usage:
with thread_db() as db:
    results = run_full_scan(db, progress_cb=_progress_cb)
```

**Testing**
- Mock `get_thread_db` to raise, assert no leaked state in `_scan_state`.
- Mock `run_full_scan` to raise, assert `db.close()` was called.

**Regression Risk**: LOW.

**Dependencies**: None.

---

### P0-08 — `scan_sensitive` silently truncates at 50KB

- **File**: `src/claude_monitoring/utils.py:34`
- **Category**: Silent data loss / false negatives
- **Severity**: MEDIUM
- **Work unit**: S

**What**
```python
scan_text = text[:50000] if len(text) > 50000 else text
```
No warning, no log, no metric when truncation happens. A 60KB payload has its last 10KB unscanned.

**Why**
Performance guardrail added without observability.

**So What**
A SOC analyst trusting this tool has no way to know scanning was incomplete. A large .env file pasted into a chat could have its last half (containing the real credentials) unscanned while the tool reports "clean".

**How to Fix**
```python
def scan_sensitive(text, names_only=False, validate=True):
    if not text:
        return []
    truncated = False
    if len(text) > 50000:
        scan_text = text[:50000]
        truncated = True
        from claude_monitoring.lifecycle import get_logger
        get_logger().info(
            "scan_sensitive truncated %d bytes → 50000", len(text)
        )
    else:
        scan_text = text
    # ... existing logic ...
    if truncated:
        # Append a synthetic "truncation" event so the alert record carries this fact
        for entry in found:
            entry["scan_truncated"] = True
            entry["scan_original_length"] = len(text)
    return found
```
Also propagate `scan_truncated` into the alert's `data_json` so the dashboard can flag it.

**Testing**
- Pass 100KB text containing a credential only in the last 10KB, assert match is missed but a log line is written.
- Pass 45KB text, assert no truncation flag.
- Pass 55KB text, assert truncation flag propagated to alert record.

**Regression Risk**: LOW. Additive.

**Dependencies**: None.

---

### P0-09 — `subprocess.run` without timeout on `ps aux` / `lsof`

- **File**: `src/claude_monitoring/watch.py:1493, 1527`
- **Category**: Hang / liveness
- **Severity**: MEDIUM
- **Work unit**: S

**What**
```python
result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
# line 1527:
result = subprocess.run(["lsof", "-i", "-n", "-P"], capture_output=True, text=True)
```
Neither call specifies `timeout=`. On a busy machine with thousands of processes or many open files, these can hang for tens of seconds.

**Why**
Forgotten argument. Other `subprocess.run` sites in the same file (`security.py:231`) do specify `timeout=60`.

**So What**
The scanner thread blocks until the external command returns. If the scanner runs on a health-check path, the entire monitor stops responding.

**How to Fix**
```python
try:
    result = subprocess.run(
        ["ps", "aux"],
        capture_output=True, text=True,
        timeout=15,
    )
except subprocess.TimeoutExpired:
    get_logger().warning("ps aux timed out; skipping process scan cycle")
    return []
```
Same for `lsof`. Audit all `subprocess.run` sites (there are ~20) and add timeouts to every one.

**Testing**
- Mock `subprocess.run` to raise `TimeoutExpired`, assert scanner handles gracefully.

**Regression Risk**: LOW. Timeout values chosen conservatively (15s for ps, 30s for lsof).

**Dependencies**: None.

---

### P0-10 — `DASHBOARD_PORT` captured at module import time

- **File**: `src/claude_monitoring/monitor.py:84`
- **Category**: Stale configuration
- **Severity**: LOW-MEDIUM
- **Work unit**: S

**What**
```python
DASHBOARD_PORT = get_dashboard_port()
```
Evaluated once at module import. Later config changes (via `set_cli_overrides` at `config.py:113` or reloaded TOML) are not reflected in this constant.

**Why**
Module-level side effect masquerading as a constant.

**So What**
- Tests that parametrize the port must reimport the module (which breaks patch lifecycles).
- If `--config` or `set_cli_overrides` is called after import, handlers that use `DASHBOARD_PORT` read the stale value.
- Line 5078 has `global DASHBOARD_PORT` — the code already knows this is wrong and tries to hot-patch it at runtime in one place, which confirms the smell.

**How to Fix**
Delete the module-level binding. Replace every use with `get_dashboard_port()`. The config module already caches its result, so there's no perf penalty.

```python
# delete: DASHBOARD_PORT = get_dashboard_port()
# every reference:
-   self._send_json({"port": DASHBOARD_PORT})
+   self._send_json({"port": get_dashboard_port()})
```

**Testing**
- Test that `config.set_cli_overrides(dashboard_port=9999)` takes effect in a running handler without reimport.
- Existing `test_config.py::test_override_dashboard_port` already exercises the config side; add an integration test for the handler side.

**Regression Risk**: LOW. Search-and-replace is mechanical.

**Dependencies**: None.

---

## 5. P1 — Security: CRITICAL & HIGH

### P1-01 — Control plane API key comparison uses `!=` (timing attack)

- **File**: `control-plane/cp/auth.py:15`
- **Category**: Timing attack
- **Severity**: **CRITICAL**
- **Work unit**: S

**What**
```python
def validate_api_key(x_api_key: str = Header(...)):
    expected = os.environ.get("CP_API_KEY", "")
    if not expected:
        raise HTTPException(401, "API key not configured on server")
    if x_api_key != expected:
        raise HTTPException(401, "Invalid API key")
    return x_api_key
```

**Why**
Python's `!=` short-circuits on first mismatching byte. The time-to-response of the `HTTPException` raise is measurably different depending on how many leading bytes matched.

**So What**
The control plane is the internet-facing component. An attacker with network access can brute-force the `CP_API_KEY` byte-by-byte. For a 32-char key over a 50ms-RTT link, extraction is feasible in hours with standard timing-attack tooling. Once obtained, the attacker can **read all fleet data and dismiss alerts** via `/api/v1/ingest` and related endpoints.

**How to Fix**
```python
import hmac

def validate_api_key(x_api_key: str = Header(...)):
    expected = os.environ.get("CP_API_KEY", "")
    if not expected:
        raise HTTPException(401, "API key not configured on server")
    if not hmac.compare_digest(x_api_key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(401, "Invalid API key")
    return x_api_key
```

**Impact of Fix**
- Constant-time comparison eliminates the timing signal.
- `hmac.compare_digest` is ~µs slower than `!=` — irrelevant for a 401 path.
- Note: `compare_digest` raises if inputs are of different types — ensure both are `bytes`.

**Testing**
- Unit test: pass correct key, assert success.
- Unit test: pass wrong key with matching prefix, assert 401.
- Unit test: pass `None` / empty / wrong-type, assert 401 without crash.
- Timing test (optional, flaky): measure response time for correct-prefix vs. wrong-first-byte — should be indistinguishable within noise.

**Regression Risk**: NONE. Identical semantics for correct/incorrect inputs.

**Dependencies**: None.

---

### P1-02 — Browser ingest stores raw credentials unmasked

- **File**: `src/claude_monitoring/monitor.py:2402-2413`
- **Category**: Sensitive data at rest
- **Severity**: **CRITICAL**
- **Work unit**: M (refactor the duplicated path)

**What**
The browser ingest path stores sensitive data without masking:
```python
data_json = json.dumps({
    "patterns": [m["name"] for m in matches],
    "severity": severity,
    "categories": list(set(m.get("category", "credential") for m in matches)),
    "context": f"browser_{ev_type}",
    "snippet": text[:200],               # RAW plaintext
    "matched_value": matched_value,      # RAW credential
    "confidence": confidence,
    "likely_false_positive": False,
})
```
Compare to `_check_sensitive` at line 1143-1166 which correctly calls `mask_value()` and `hash_value()` before storing.

**Why**
Sensitive-data storage logic was duplicated across three call sites (JSONL, browser, proxy). The browser path was written as a separate inline implementation and forgot the masking step.

**So What**
- Every credential captured from a browser AI conversation (Claude, ChatGPT, Gemini) is stored in plaintext in `monitor.db`.
- `SyncAgent` at `sync.py:221` then forwards the raw `snippet` field to the control plane, where it lands in `fleet_alerts.snippet`.
- A dashboard viewer sees the raw secret. A compromised DB file exposes every secret ever typed into a browser AI.
- Directly contradicts the product's "CrowdStrike-style" positioning.

**How to Fix**
Extract a shared function in `security.py`:
```python
def build_sensitive_alert_payload(
    matches: list[dict],
    text: str,
    context: str,
    confidence: str,
) -> dict:
    """Build a redacted sensitive-data alert payload.

    Single source of truth used by JSONL watcher, browser ingest,
    and proxy addon. The raw `matched_value` is NEVER included —
    only its mask (first4/last4) and hash (16-char SHA-256).
    """
    if not matches:
        return {}
    first = matches[0]
    matched_value = first.get("matched_value", "")
    masked = mask_value(matched_value)
    raw_snippet = text[:200]
    safe_snippet = raw_snippet.replace(matched_value, masked) if matched_value else raw_snippet
    severity = min(
        (m.get("severity", "medium") for m in matches),
        key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 99),
    )
    return {
        "patterns": [m["name"] for m in matches],
        "severity": severity,
        "categories": list({m.get("category", "credential") for m in matches}),
        "context": context,
        "snippet": safe_snippet,
        "matched_value": masked,
        "matched_hash": hash_value(matched_value),
        "confidence": confidence,
        "likely_false_positive": confidence == "low",
    }
```

Then replace both `_check_sensitive` (line 1143-1166) and `_api_browser_ingest` (line 2402-2413) with calls to `build_sensitive_alert_payload(...)`.

Also audit `watch.py` addon paths (line 86, 293) for the same pattern.

**Impact of Fix**
- Fixes the data-at-rest exposure.
- Eliminates ~50 lines of duplication across 3 sites.
- One function to test instead of three code paths.
- Future pattern additions need only be wired in one place.

**Testing**
- `test_security_hardening.py::test_browser_ingest_masks_credentials` — POST an event containing a real-format AWS key, assert DB row has `AKIA****` mask, not the full key.
- `test_security_hardening.py::test_jsonl_watcher_masks_credentials` — existing test; should still pass.
- `test_security_hardening.py::test_build_sensitive_alert_payload_never_returns_raw_value` — unit test the new function directly.
- Negative test: inject a string containing the raw matched value, assert it does NOT appear in the serialized JSON.

**Regression Risk**: MEDIUM. Three call sites change. Existing alerts in DB still have the old un-masked data (migration required — see P1-05).

**Dependencies**: Ships standalone but should be done alongside P1-05 (retroactive scrubbing).

---

### P1-03 — Control plane dashboard endpoints have NO auth

- **File**: `control-plane/cp/app.py:12-13`, `control-plane/cp/dashboard.py` (all routes)
- **Category**: Broken access control
- **Severity**: **HIGH**
- **Work unit**: M

**What**
```python
# app.py line 12-13:
# Include dashboard routes (no auth required for dashboard HTML)
app.include_router(dashboard_router)
```
Every route in `dashboard.py` — `/api/v1/fleet/stats`, `/fleet/sessions`, `/fleet/endpoints`, `/fleet/alerts`, `/fleet/stats/alert_trend`, `POST /fleet/alerts/{id}/dismiss` — has **no** `Depends(validate_api_key)`.

**Why**
Comment says "no auth required for dashboard HTML". The HTML page itself doesn't need auth, but the **JSON API endpoints** that the HTML calls absolutely do.

**So What**
- Any reachable attacker enumerates all fleet endpoints, sessions, and alerts.
- Attacker can dismiss alerts (data modification) — `POST /api/v1/fleet/alerts/{id}/dismiss`.
- Complete bypass of the authentication layer the author thinks they have.

**How to Fix**
Split routes by auth requirement:
```python
# dashboard.py
router = APIRouter()
api_router = APIRouter(dependencies=[Depends(validate_api_key)])

@router.get("/dashboard", response_class=HTMLResponse)
async def fleet_dashboard():
    # HTML only — safe to be open
    ...

@api_router.get("/api/v1/fleet/stats")
async def fleet_stats(db=Depends(get_db)):
    ...

# (move every /api/v1/fleet/* route to api_router)

# app.py
app.include_router(router)       # HTML
app.include_router(api_router)   # JSON, authenticated
```

Alternative: add a `Depends(validate_api_key)` to each route function individually (more verbose, but explicit).

**Impact of Fix**
- Eliminates the broken access control.
- Frontend needs to send `X-API-Key` header on fetch calls. Existing `fleet_dashboard.html` likely doesn't, so the HTML needs updating too (prompt for key, store in localStorage, include in fetch).

**Testing**
- `test_control_plane_auth.py::test_fleet_stats_requires_api_key` — POST without header → 401.
- `test_control_plane_auth.py::test_fleet_stats_with_valid_key` → 200.
- `test_control_plane_auth.py::test_dashboard_html_no_auth` → 200 (still open).
- E2E test: dashboard HTML with valid key in localStorage loads and renders data.

**Regression Risk**: HIGH. This is a breaking change for any existing fleet dashboard users. Rollout plan:
1. Deploy auth change with a feature flag `CP_REQUIRE_DASHBOARD_AUTH=1`.
2. Update HTML to include key.
3. Flip flag to default-on after grace period.

**Dependencies**: None. But should coordinate with HTML update.

---

### P1-04 — SyncAgent transmits raw snippets to control plane

- **File**: `src/claude_monitoring/sync.py:221`
- **Category**: Sensitive data in transit
- **Severity**: **HIGH**
- **Work unit**: S (after P1-02)

**What**
```python
alerts.append({
    ...
    "snippet": data.get("snippet", ""),
    ...
})
```
For alerts generated by the browser path (P1-02), this contains **raw plaintext credentials**. Even after P1-02, the JSONL path stores `masked_value` (e.g., `AKIA****XXXX`), which still leaks the first 4 / last 4 of the credential.

**Why**
SyncAgent is a pure forwarder — it doesn't re-redact.

**So What**
Raw or partially-masked credentials traverse the network (over HTTP unless TLS is manually configured — see P2-07) and land in PostgreSQL. Control-plane compromise exposes all fleet secrets.

**How to Fix**
In `_extract_alerts`, strip or re-hash the snippet:
```python
def _extract_alerts(self, events):
    alerts = []
    for ev in events:
        if ev["event_type"] != "sensitive_data":
            continue
        data = ev["data_json"]
        # Never forward the snippet field to CP — only the hash and metadata.
        alerts.append({
            "client_event_id": ev["client_event_id"],
            "timestamp": ev["timestamp"],
            "session_id": ev["session_id"],
            "severity": data.get("severity", "medium"),
            "patterns": data.get("patterns", []),
            "context": data.get("context", ""),
            "matched_hash": data.get("matched_hash", ""),
            "confidence": data.get("confidence"),
            "validated": data.get("validated", False),
        })
    return alerts
```
Remove `snippet` from `AlertPayload` in `control-plane/cp/models.py` and from `fleet_alerts` schema (migration) — see P1-05.

**Impact of Fix**
- Zero-trust posture: CP cannot see any credential fragments, only hashes for cross-fleet correlation.
- Downside: the fleet dashboard can no longer show a snippet preview. Acceptable trade-off — severity/pattern are sufficient for triage, and drill-down can go back to the endpoint.

**Testing**
- `test_sync.py::test_extract_alerts_omits_snippet` — build an event with snippet, assert extracted alert has no snippet key.
- `test_sync.py::test_extract_alerts_preserves_hash` — assert `matched_hash` is forwarded.

**Regression Risk**: MEDIUM. CP schema and models change. Existing `fleet_alerts.snippet` column must be dropped or marked deprecated.

**Dependencies**: P1-02 (needs masked alerts in local DB first).

---

### P1-05 — Retroactive scrub of historical unmasked alerts

- **File**: `src/claude_monitoring/security.py:393` (`purge_old_sensitive_data`)
- **Category**: Sensitive data cleanup
- **Severity**: **HIGH**
- **Work unit**: M

**What**
Fixing P1-02 only helps new alerts. Any alerts already in `monitor.db` from before the fix still contain raw credentials. `purge_old_sensitive_data` at security.py:393 only strips after 30 days.

**Why**
The purge was designed for retention, not for migration.

**So What**
Operator upgrades to the fixed version, still has 30 days of unmasked secrets sitting in their DB. An attacker who copied `monitor.db` post-upgrade still has the plaintext.

**How to Fix**
Add a one-shot migration that runs at startup after the fix:
```python
# db.py, in init_db() migration block:
c.execute("""
    SELECT id, data_json FROM events
    WHERE event_type = 'sensitive_data'
    AND json_extract(data_json, '$.matched_value') IS NOT NULL
    AND json_extract(data_json, '$.matched_hash') IS NULL
""")
for row in c.fetchall():
    data = json.loads(row["data_json"])
    raw = data.get("matched_value", "")
    data["matched_value"] = mask_value(raw)
    data["matched_hash"] = hash_value(raw)
    snippet = data.get("snippet", "")
    if raw and raw in snippet:
        data["snippet"] = snippet.replace(raw, data["matched_value"])
    c.execute("UPDATE events SET data_json = ? WHERE id = ?",
              (json.dumps(data), row["id"]))
```
Gate behind a schema_version check so it only runs once.

**Impact of Fix**
- All existing alerts get retroactively masked on next startup.
- One-time operation; irreversible (raw value is lost).

**Testing**
- Seed DB with an unmasked alert, run migration, assert value is masked and hash is populated.
- Idempotency: run migration twice, assert no-op on second run.

**Regression Risk**: LOW-MEDIUM. Data mutation is one-way. If the migration has a bug, alerts lose their raw data forever. **Critical**: write migration unit tests before enabling.

**Dependencies**: P1-02 (the mask function must be the one used going forward).

---

## 6. P2 — Security: MEDIUM

### P2-01 — Browser ingest / heartbeat POST endpoints skip auth

- **File**: `src/claude_monitoring/monitor.py:1883`
- **Category**: Auth bypass
- **Work unit**: M

**What**
```python
if path not in ("/api/browser/ingest", "/api/browser/heartbeat") and not self._check_auth(path, params):
```
Two POST endpoints explicitly bypass token auth. The comment cites "Chrome extension origin constraint".

**So What**
Any local process (or browser tab on `localhost`) can flood ingest with bogus events or trigger alert floods. The 1MB payload limit is the only guard.

**How to Fix**
Give the Chrome extension its own token, stored in `chrome.storage.local`:
1. On first install, the extension calls `GET /api/browser/auth/provision` which returns a fresh token generated via `secrets.token_urlsafe(32)` — but this endpoint is itself protected by a localhost-origin check + one-time bootstrap (open for 60 seconds after `ai-monitor start`).
2. Extension sends this token in `X-Extension-Token` header on every subsequent request.
3. Server validates with `hmac.compare_digest`.

Alternative (simpler): bind ingest/heartbeat to `127.0.0.1` only via explicit socket check, reject any request whose `Origin` isn't `chrome-extension://<expected-id>`.

**Testing**
- Reject requests without the extension token → 401.
- Accept valid token → 200.
- Confirm existing integration tests still pass (extension flow).

**Work unit**: M. **Risk**: MEDIUM (affects extension onboarding flow).

---

### P2-02 — `DISABLE_DASHBOARD_AUTH` has no loopback binding check

- **File**: `src/claude_monitoring/monitor.py:1775`
- **Category**: Auth bypass / misconfiguration
- **Work unit**: S

**What**
```python
if os.environ.get("DISABLE_DASHBOARD_AUTH") == "1":
    return True
```
No verification that the server is loopback-only when auth is disabled.

**How to Fix**
```python
if os.environ.get("DISABLE_DASHBOARD_AUTH") == "1":
    from claude_monitoring.config import get_bind_address
    if get_bind_address() in ("127.0.0.1", "localhost", "::1"):
        return True
    get_logger().error(
        "DISABLE_DASHBOARD_AUTH set but server bound to %s — refusing",
        get_bind_address(),
    )
    # fall through to normal auth check
```

Also read the env var **once** at server startup, not per-request.

**Testing**
- Set env + bind to 0.0.0.0 → auth still enforced.
- Set env + bind to 127.0.0.1 → auth bypassed.

**Risk**: LOW. **Work unit**: S.

---

### P2-03 — `enforce_permissions` silently swallows chmod failures

- **File**: `src/claude_monitoring/security.py:275-308`
- **Category**: Observability
- **Work unit**: S

**How to Fix**
Replace `except Exception: pass` with `except Exception as e: get_logger().warning("chmod failed on %s: %s", path, e)`. Also return a `(fixed, failed)` tuple so the caller can surface failures to the user.

**Risk**: NONE. **Work unit**: S.

---

### P2-04 — Hardcoded `changeme` Postgres password

- **File**: `control-plane/cp/db.py:17`
- **Category**: Credentials in source
- **Work unit**: S

**How to Fix**
```python
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError(
        "DATABASE_URL is required. See control-plane/.env.example."
    )
```
Remove the fallback entirely. Fail loudly at startup.

**Risk**: MEDIUM — existing `docker-compose.yml` deployments may rely on the default. Update `docker-compose.yml` and `.env.example` in the same PR.

**Work unit**: S.

---

### P2-05 — `mask_value` reveals 8 chars for short credentials

- **File**: `src/claude_monitoring/security.py:367-378`
- **Category**: Insufficient masking
- **Work unit**: S

**How to Fix**
```python
def mask_value(value: str | None) -> str:
    if not value:
        return "****"
    if len(value) < 12:
        return "****"   # fully mask short values
    # For 12+ char values, show first 4 / last 4
    return value[:4] + "*" * (len(value) - 8) + value[-4:]
```

Also consider a stricter policy: always `****` regardless of length, and rely on `matched_hash` for correlation.

**Testing**
- `mask_value("short")` → `****`
- `mask_value("ABCD1234EFGH")` → `****` (exactly 12 chars → fully masked under new rule)
- `mask_value("AKIAJ5TESTXXXXXXXXXX")` (20 chars) → `AKIA************XXXX`

**Risk**: LOW. **Work unit**: S.

---

### P2-06 — `hash_value` uses 64-bit truncated SHA-256

- **File**: `src/claude_monitoring/security.py:381-385`
- **Category**: Weak hash
- **Work unit**: S

**What**
16 hex chars = 64 bits. For credentials with known prefixes, brute-force the remaining entropy in hours.

**How to Fix**
Use 32 hex chars (128 bits) — still compact enough for display, infeasible to brute-force:
```python
def hash_value(value: str | None) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:32]
```

Or use HMAC-SHA256 with a per-install random key (stored in `~/claude_watch_output/.hash_key`):
```python
def hash_value(value: str | None) -> str:
    if not value:
        return ""
    key = _get_or_create_hash_key()  # 32 random bytes
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:32]
```

**Risk**: Existing `matched_hash` values become invalid (migration needed — increment schema version). **Work unit**: S.

---

### P2-07 — SyncAgent API key transmitted over HTTP

- **File**: `src/claude_monitoring/sync.py:100-104`
- **Category**: Credential in transit
- **Work unit**: S

**How to Fix**
```python
def __init__(self, cp_url, api_key, interval=30):
    if not cp_url.startswith("https://"):
        get_logger().error(
            "SyncAgent refuses to send API key over HTTP: %s", cp_url
        )
        raise ValueError("cp_url must be https://")
    ...
```
Add override env var `CP_ALLOW_INSECURE=1` for local dev only.

**Risk**: LOW. Breaks dev setups that use `http://localhost:9090`. Document the override.

**Work unit**: S.

---

### P2-08 — `trust_ca_cert` / `untrust_ca_cert` shell injection via cert_path

- **File**: `src/claude_monitoring/security.py:225-228, 246`
- **Category**: Command injection
- **Work unit**: S

**How to Fix**
Use `shlex.quote`:
```python
import shlex
script = (
    'do shell script "security add-trusted-cert -d -r trustRoot '
    f'-k /Library/Keychains/System.keychain {shlex.quote(str(cert_path))}" '
    'with administrator privileges'
)
```
Better: pass via osascript stdin to avoid string concatenation entirely:
```python
script_template = """
on run argv
    do shell script "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " & quoted form of item 1 of argv with administrator privileges
end run
"""
subprocess.run(
    ["osascript", "-", str(cert_path)],
    input=script_template, text=True, timeout=60,
)
```

**Risk**: MEDIUM — change osascript invocation pattern. Test manually on macOS with paths containing spaces, quotes, backticks.

**Work unit**: S.

---

### P2-09 — Wildcard CORS `Access-Control-Allow-Origin: *`

- **File**: `src/claude_monitoring/monitor.py:2162`
- **Category**: CORS
- **Work unit**: S

**How to Fix**
Reflect origin from an allowlist:
```python
ALLOWED_ORIGINS = {
    "http://localhost",
    "http://127.0.0.1",
    # plus the dashboard origins and chrome-extension://<id>
}

def _send_json(self, data, status=200):
    origin = self.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        self.send_header("Access-Control-Allow-Origin", origin)
    # don't send Access-Control-Allow-Origin at all if origin isn't allowed
```

**Testing**
- Request with allowed Origin → header echoed.
- Request with disallowed Origin → no header, browser blocks.
- Same-origin request → works.

**Risk**: LOW. **Work unit**: S.

---

### P2-10 — Token accepted in URL query string

- **File**: `src/claude_monitoring/monitor.py:1778`
- **Category**: Credential in URL
- **Work unit**: S

**How to Fix**
Deprecate `?token=`. Accept only `Authorization: Bearer` header. Update `dashboard.html` to use `fetch(..., { headers: { Authorization: 'Bearer ' + token } })` and store the token in `sessionStorage` (never in URL).

Transition: accept both for one release with a deprecation warning log line when `?token=` is used.

**Risk**: MEDIUM — user bookmarks with `?token=` break. **Work unit**: S.

---

### P2-11 — Raw exceptions leaked in API responses

- **File**: `src/claude_monitoring/monitor.py:1866-1869`
- **Category**: Information disclosure
- **Work unit**: S

**How to Fix**
```python
except Exception as e:
    error_id = secrets.token_hex(8)
    get_logger().error("handler failed [%s]: %s", error_id, e, exc_info=True)
    self._send_json(
        {"error": "internal error", "error_id": error_id},
        500,
    )
```
Clients see only an error ID; operators grep logs by ID.

**Risk**: NONE. **Work unit**: S.

---

### P2-12 — `watch.py` dashboard binds with zero auth

- **File**: `src/claude_monitoring/watch.py:1400-1421`
- **Category**: Auth bypass (secondary dashboard)
- **Work unit**: S

**How to Fix**
Add the same `_check_auth` pattern as `monitor.py`. Or deprecate the `watch.py` standalone dashboard entirely if it's a legacy from pre-`monitor.py` days (the graph shows it's rarely called — only from `run_dashboard` CLI).

**Risk**: LOW — legacy code path. **Work unit**: S.

---

## 7. P3 — Security: LOW & INFO

### P3-01 — TOCTOU race between file creation and chmod

- **File**: `src/claude_monitoring/security.py:331-337, 167-170`
- **Work unit**: S

**Fix**: Use `os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)` then `os.write()`. This creates the file with correct permissions atomically.

### P3-02 — Hardcoded test API key in simulate_endpoint.py

- **File**: `control-plane/test-client/simulate_endpoint.py:14`
- **Work unit**: S

**Fix**: Remove the fallback. Require `CP_API_KEY` env var. Update dev docs.

### P3-03 — Port parameter not validated before subprocess call

- **File**: `src/claude_monitoring/monitor.py:4363`
- **Work unit**: S

**Fix**: Assert `1 <= port <= 65535` and `isinstance(port, int)` before calling `networksetup`.

### P3-04 — f-string SQL with `# nosec` markers

- **File**: `src/claude_monitoring/monitor.py:356, 3653, 3751`
- **Work unit**: S

**Fix**: Use parameterized column names via a safe helper:
```python
_ALLOWED_UPDATE_COLS = {"total_input_tokens", "total_output_tokens", ...}
def _safe_update(table, cols, values, where_col, where_val):
    for col in cols:
        if col not in _ALLOWED_UPDATE_COLS:
            raise ValueError(f"Unsafe column: {col}")
    ...
```

### P3-05 — No rate limiting on any endpoint

- **Files**: both dashboards
- **Work unit**: M

**Fix**: Add a token-bucket limiter (50 req/sec per IP). For browser ingest, apply per-extension-token (after P2-01).

### P3-06 — CA private key unencrypted on disk

- **File**: `src/claude_monitoring/security.py:163-164`
- **Work unit**: M

**Fix**: Encrypt with a key derived from the machine's secure enclave (macOS keychain) or at minimum a passphrase stored separately.

### P3-07 — Control plane `/health` is unauthenticated

- **File**: `control-plane/cp/app.py:16-18`
- **Work unit**: INFO (acceptable for load balancers)

### P3-08 — Unused bcrypt hash in registry

- **File**: `control-plane/cp/registry.py:39`
- **Work unit**: S

**Fix**: Either wire it into the auth path (each endpoint validates its per-endpoint key via bcrypt) or delete the column and the hashing call.

---

## 8. P4 — Modularity & Framework (Major Refactors)

These are sequential; they require coordination and review gates. Do **not** parallelize these without an explicit plan.

### P4-01 — Split `DashboardHandler` into per-concern modules

- **File**: `src/claude_monitoring/monitor.py:1757-3938` (now extends further with 40 handlers)
- **Work unit**: **XL** (3–5 days)
- **Current size**: 2,500 lines, 40 API handlers, 1 class

**Target layout**:
```
src/claude_monitoring/dashboard/
├── __init__.py
├── router.py           # BaseHTTPRequestHandler subclass, routes only
├── middleware.py       # _check_auth, _send_json, _send_html, error handler
├── sessions.py         # _api_sessions, _api_session_detail, _api_session_turns
├── alerts.py           # _api_alerts, _api_alerts_dismiss
├── browser.py          # _api_browser, _api_browser_sessions, _api_browser_*
├── traffic.py          # _api_traffic, _api_traffic_stats, _api_session_traffic
├── insights.py         # _api_insights, _api_insights_projects, _api_insights_efficiency
├── mcp.py              # _api_mcp_stats, _api_mcp_servers
├── supply_chain.py     # _api_supply_chain_* (12 handlers)
└── core.py             # _api_stats, _api_feed, _api_processes, _api_files,
                        # _api_connections, _api_activity_timeline, _api_process_detail,
                        # _api_export, _api_report
```

Each module exposes a `register(router)` function that binds handlers to routes. The main `router.py` imports and calls `register()` for each domain.

**Step-by-step plan**:
1. Create the `dashboard/` package with `__init__.py` and `router.py` (just the BaseHTTPRequestHandler subclass).
2. Move `_check_auth`, `_send_json`, `_send_html`, `do_GET`, `do_POST`, `do_OPTIONS` into `middleware.py`.
3. Extract one domain at a time: `sessions.py` first (smallest, well-understood). Each extraction:
   - Copy the handlers to the new file.
   - Rewrite as module-level functions taking `(handler, params)`.
   - Register with the router.
   - Delete from `monitor.py`.
   - Run full test suite.
4. Continue with `alerts.py`, `core.py`, `mcp.py`, `insights.py`, `traffic.py`, `browser.py`, `supply_chain.py`.

**Testing**: After each extraction, run `pytest -q` and expect the same 1,103 tests passing. Also re-run the E2E browser test suite.

**Regression Risk**: HIGH for the sheer size, but LOW per-step if done one domain at a time.

**Dependencies**: None, but easier after P4-03 (repository pattern).

---

### P4-02 — Split `lifecycle.py` into focused modules

- **File**: `src/claude_monitoring/lifecycle.py` (1,038 lines, 53 symbols)
- **Work unit**: **L** (2 days)

**Target**:
```
src/claude_monitoring/
├── log.py              # get_logger, get_log_path, _StreamToLogger, redirect_stdio_to_log
├── pid.py              # write_pid_file, read_pid_file, remove_pid_file, is_pid_alive
├── supervisor.py       # is_mitmproxy_process, find_orphan_mitmproxy_on_port, kill_orphan
├── heartbeat.py        # write_heartbeat, heartbeat_age_seconds
└── system_proxy.py     # disable_system_proxy, is_system_proxy_enabled_for_port
```

Delete `lifecycle.py` entirely after extraction. Update all importers.

**Testing**: Module-by-module tests already exist in `tests/test_status.py` and `tests/test_monitor_main.py`. Run after each split.

**Regression Risk**: MEDIUM (many import sites). Use a single-commit "big rename" to avoid half-broken states.

**Dependencies**: None.

---

### P4-03 — Extract data access layer (repository pattern)

- **Scope**: 100+ raw SQL calls across 12 files
- **Work unit**: **XL** (1 week)

**Target**:
```python
# src/claude_monitoring/repositories/
# ├── __init__.py
# ├── sessions_repo.py
# ├── events_repo.py
# ├── browser_repo.py
# ├── traffic_repo.py
# └── supply_chain_repo.py

class SessionsRepository:
    def __init__(self, db):
        self.db = db

    def list_recent(self, limit=100, agent_type=None):
        sql = "SELECT * FROM sessions WHERE 1=1"
        params = []
        if agent_type:
            sql += " AND agent_type = ?"
            params.append(agent_type)
        sql += " ORDER BY last_activity DESC LIMIT ?"
        params.append(limit)
        return self.db.execute(sql, params).fetchall()

    def get_by_id(self, session_id): ...
    def upsert(self, session): ...
```

Use in handlers:
```python
def _api_sessions(self, params):
    repo = SessionsRepository(get_thread_db())
    rows = repo.list_recent(limit=int(params.get("limit", [100])[0]))
    self._send_json([dict(r) for r in rows])
```

**Testing**: Test each repository in isolation with a tmp_path DB. Handler tests become ~5 lines.

**Regression Risk**: HIGH — touches every SQL site. Do domain-by-domain alongside P4-01.

**Dependencies**: None, but P4-01 benefits from this.

---

### P4-04 — Extract `JSONLSessionWatcher` to its own module

- **File**: `src/claude_monitoring/monitor.py:276-1208` (932 lines)
- **Work unit**: **L** (2 days)

**Target**: `src/claude_monitoring/session_watcher.py`. Dependencies to pull along: the supply-chain check, confidence calculator, sensitive-data check.

**Testing**: `tests/test_jsonl_watcher.py` already covers this — should pass unchanged.

**Regression Risk**: MEDIUM. Private methods (`_process_record`, etc.) must stay private; imports must be updated.

**Dependencies**: P1-02 (sensitive data helper extracted first).

---

### P4-05 — Declare the import hierarchy + enforce with import-linter

- **Scope**: Whole package
- **Work unit**: **M** (1 day)

**What**
Currently, 30+ inline `from claude_monitoring.*` imports inside function bodies hide circular dependencies. Modules form implicit cycles: `monitor ↔ lifecycle ↔ db ↔ status ↔ security`.

**How to Fix**
1. Draw the intended layer diagram:
   ```
   Layer 0 (foundation):  config, constants
   Layer 1 (infra):       db, log
   Layer 2 (security):    security, pid, heartbeat, supervisor
   Layer 3 (domain):      threat_intel, supply_chain, validators, utils
   Layer 4 (monitors):    session_watcher, process_scanner, network_monitor
   Layer 5 (app):         dashboard/, wizard, cleanup, status, sync
   Layer 6 (entry):       monitor (CLI only)
   ```
2. Add `import-linter` to dev deps, configure `.importlinter` with layered contracts.
3. Fix every inline import that's there to dodge a cycle — move it to module top. If the move fails, the actual cycle must be broken (usually by introducing an interface module).
4. Wire `lint-imports` into CI.

**Testing**: CI runs `lint-imports` — failing build if someone reintroduces a cycle.

**Regression Risk**: LOW — import-linter catches mistakes before merge.

**Dependencies**: Best after P4-02 and P4-04 (when `lifecycle.py` and `session_watcher.py` are split).

---

### P4-06 — Introduce an alert pipeline abstraction

- **Scope**: Sensitive-data processing (3 call sites)
- **Work unit**: **M** (1 day)

**What**
Alert creation involves: scan → filter false positives → calculate confidence → cap severity → dedup → mask → hash → store → push to live feed → sync. Implemented three times with different subsets of steps.

**How to Fix**
```python
# src/claude_monitoring/alert_pipeline.py
@dataclass
class AlertPipeline:
    scanner: Callable
    filterers: list[Callable]
    confidence_fn: Callable
    dedup_store: DedupStore
    storage: AlertStorage
    live_feed: LiveFeed

    def process(self, text: str, context: AlertContext) -> list[Alert]:
        matches = self.scanner(text)
        for f in self.filterers:
            matches = f(matches, context)
        if not matches:
            return []
        confidence = self.confidence_fn(context, matches)
        payload = build_sensitive_alert_payload(matches, text, context.name, confidence)
        if self.dedup_store.is_duplicate(payload):
            return self.dedup_store.increment(payload)
        alert = self.storage.store(payload, context)
        self.live_feed.push(alert)
        return [alert]

# Usage:
alert_pipeline = AlertPipeline(...)
alerts = alert_pipeline.process(text, AlertContext(source="jsonl", session=session_id))
```

**Testing**: One pipeline test suite replaces three duplicated test paths. Coverage for the pipeline goes from split-across-files to a single, clear module.

**Regression Risk**: MEDIUM. Ship behind a feature flag, switch over each source one at a time.

**Dependencies**: P1-02 (shared payload function must exist first).

---

### P4-07 — Event bus for monitoring sources

- **Scope**: 6 data sources writing directly to DB
- **Work unit**: **L** (3 days)

**Target**:
```python
class EventBus:
    def publish(self, event: MonitoringEvent): ...
    def subscribe(self, handler: Callable): ...

# Sources publish events:
bus.publish(SessionStartedEvent(session_id, ...))
bus.publish(SensitiveDataDetectedEvent(...))

# Subscribers:
db_writer = DBEventWriter()
live_feed = LiveFeedEventWriter()
sync_agent = SyncAgentEventWriter()

bus.subscribe(db_writer.handle)
bus.subscribe(live_feed.handle)
bus.subscribe(sync_agent.handle)
```

**Benefits**:
- Adding a new subscriber (Slack alerts, webhook notifications) doesn't modify any source.
- Testing: mock the bus instead of mocking the DB.
- Observability: one place to log all events.

**Regression Risk**: HIGH. Big architectural change. Do after P4-06 is stable.

**Dependencies**: P4-06, P4-03.

---

### P4-08 — Strategy pattern for agent-type normalization

- **File**: `src/claude_monitoring/monitor.py:_process_record` (line 471-541)
- **Work unit**: **M** (1 day)

**How to Fix**
```python
# src/claude_monitoring/agents/
# ├── __init__.py
# ├── base.py           # class AgentAdapter protocol
# ├── claude_code.py
# ├── openclaw.py
# └── registry.py       # agent_type → AgentAdapter

class AgentAdapter(Protocol):
    def normalize_record(self, raw: dict) -> NormalizedRecord: ...
    def detect_channel(self, raw: dict) -> str: ...

AGENT_REGISTRY: dict[str, AgentAdapter] = {
    "claude_code": ClaudeCodeAdapter(),
    "openclaw": OpenClawAdapter(),
}
```

**Benefits**:
- Adding Cursor, Windsurf, or Aider support = new file.
- `_process_record` becomes ~10 lines dispatching to the adapter.

**Regression Risk**: MEDIUM. **Dependencies**: P4-04.

---

### P4-09 — Middleware pattern for auth/CORS/error handling

- **Scope**: Dashboard HTTP server
- **Work unit**: **M** (1 day)

**What**
Currently auth is called manually at the top of `do_GET` and `do_POST`. If a new HTTP method is added (`do_DELETE`), auth must be manually wired.

**How to Fix**
```python
class MiddlewareChain:
    def __init__(self):
        self._handlers = []
    def use(self, handler):
        self._handlers.append(handler)
    def dispatch(self, req):
        for m in self._handlers:
            result = m(req)
            if result is not None:
                return result
        return None

# Setup:
chain = MiddlewareChain()
chain.use(auth_middleware)
chain.use(cors_middleware)
chain.use(error_middleware)
```

**Regression Risk**: LOW. **Dependencies**: P4-01.

---

### P4-10 — Pre-compile regex patterns

- **File**: `src/claude_monitoring/constants.py:202` (SENSITIVE_PATTERNS) + `utils.py:45`
- **Work unit**: **S** (2 hours)

**How to Fix**
```python
# constants.py
SENSITIVE_PATTERNS = {
    "aws_key": {
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),  # pre-compiled
        "severity": "critical",
        "category": "credential",
    },
    ...
}

# utils.py
match = info["pattern"].search(scan_text)  # was re.search(info["pattern"], ...)
```

**Benefits**: Eliminates recompilation cost on hot path. Python's regex cache (128 slots) no longer matters.

**Testing**: Existing `test_sensitive.py` unchanged.

**Risk**: NONE. **Work unit**: S. Quick win.

---

### P4-11 — Replace `VALIDATORS` dict with registry protocol

- **File**: `src/claude_monitoring/validators.py:473`
- **Work unit**: **M** (1 day)

**How to Fix**
```python
# validators.py
VALIDATOR_REGISTRY: dict[str, Validator] = {}

def register_validator(pattern_name: str):
    def decorator(fn):
        VALIDATOR_REGISTRY[pattern_name] = fn
        return fn
    return decorator

@register_validator("aws_key")
def validate_aws_key(match_text, surrounding_text=""): ...

@register_validator("jwt")
def validate_jwt(match_text, surrounding_text=""): ...
```

Add an import-time assertion:
```python
# at end of validators.py
_missing = set(SENSITIVE_PATTERNS) - set(VALIDATOR_REGISTRY)
if _missing:
    raise ImportError(
        f"SENSITIVE_PATTERNS missing validators: {_missing}"
    )
```

**Benefits**:
- Dead-code detection sees the calls (via the decorator's side-effect).
- Forgotten validators fail at import, not at runtime.
- Type checker can see the signature.

**Testing**: Add `test_validators.py::test_every_pattern_has_validator`.

**Risk**: LOW. **Work unit**: M.

---

### P4-12 — Kill module-level global mutable state

- **Files**: `config.py`, `monitor.py`, `lifecycle.py`
- **Work unit**: **L** (2 days)

**What**
11 `global X` declarations across the codebase. Globals make tests fragile, embedders impossible, and parallel execution dangerous.

**How to Fix**
Introduce `MonitorContext`:
```python
@dataclass
class MonitorContext:
    config: Config
    db: Database
    logger: Logger
    scan_state: ScanState
    live_feed: LiveFeed
    live_feed_lock: threading.Lock
    plan_info: PlanInfo

# Entry points create one and pass it down
ctx = MonitorContext.build()
start_monitoring(ctx)
```

Every handler receives `ctx` (or it's attached to the HTTP handler).

**Regression Risk**: HIGH. This is surgery across the whole package. Do after P4-01 through P4-05.

**Dependencies**: After P4-01, P4-03.

---

### P4-13 — Unify subprocess wrapping

- **Scope**: ~20 `subprocess.run` call sites
- **Work unit**: **M** (1 day)

**How to Fix**
```python
# src/claude_monitoring/shell.py
def run(cmd: list[str], *, timeout: int = 30, check: bool = False) -> SubprocessResult:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)
    except subprocess.TimeoutExpired:
        get_logger().warning("command %s timed out after %ds", cmd[0], timeout)
        raise
```
Replace every call site. Tests patch one location: `claude_monitoring.shell.run`.

**Benefits**:
- Single place to add a timeout (fixes P0-09 in one shot).
- Tests don't need per-module patches.
- One place for auditable logging of subprocess invocations.

**Testing**: `test_shell.py` replaces per-file subprocess mocks.

**Risk**: LOW. **Work unit**: M.

**Dependencies**: None. Can ship before P4-01.

---

### P4-14 — Adopt a real HTTP framework

- **Scope**: Dashboard server
- **Work unit**: **XL** (5+ days)

**What**
`BaseHTTPRequestHandler` is Python's lowest-common-denominator HTTP server. No request validation, no middleware, no dependency injection, no automatic error handling. The codebase has bolted together all of these manually, badly.

**How to Fix**
Migrate the local dashboard to **Starlette** (FastAPI without the Pydantic model overhead, since response bodies are dicts not models). Starlette gives:
- Middleware (solves P4-09)
- Built-in DI for DB sessions
- Automatic JSON encoding
- Typed routes with path params
- Pluggable auth backends (solves several P1/P2 findings)

**Risk**: VERY HIGH. Changes runtime dependency, deployment, every test. Only do this once the class split (P4-01) is done — at that point the migration is ~40 small handler rewrites.

**Dependencies**: P4-01, P4-03.

---

## 9. P5 — Code Quality & Tech Debt

| ID | Finding | File | Work unit | Priority |
|----|---------|------|-----------|----------|
| P5-01 | 100+ `except Exception: pass` — add logging | `security.py`, `supply_chain.py`, `validators.py` | M | After P4-05 |
| P5-02 | Inline imports (30+) inside function bodies | multiple | M | After P4-05 |
| P5-03 | `_process_assistant_message` is 181 lines, 5 responsibilities | `monitor.py:784-965` | M | After P4-04 |
| P5-04 | `_api_export` duplicates `report.py` logic | `monitor.py:3548-3658` | S | Anytime |
| P5-05 | `_api_supply_chain*` handlers duplicate `supply_chain.py` | `monitor.py:4110-4600` | M | After P4-03 |
| P5-06 | Dead code: `is_proxy_enabled`, `get_mcp_known_servers`, `get_full_environment` | `config.py`, `supply_chain.py` | S | Anytime |
| P5-07 | `_api_browser_ingest` swallows commit errors | `monitor.py:2426-2430` | S | With P0-03 |
| P5-08 | `get_thread_db` fan-in of 40 — no connection pooling | `db.py` + 40 callers | L | After P4-03 |
| P5-09 | CLI argparse logic embedded in `monitor.py` main | `monitor.py:4300-4440` | M | After P4-02 |
| P5-10 | Frontend JS in `dashboard.html` is a 5000-line monolith | `dashboard.html` | XL | Separate track |
| P5-11 | `constants.py:202` SENSITIVE_PATTERNS lives in constants but is domain logic | `constants.py`, `validators.py` | S | Anytime |

---

## 10. Parallel Execution Plan

### Batch 0 — Product reality gaps (URGENT)

Dispatch first. Two of these fundamentally change what the product reports; the remaining are investigations.

| ID | Description | Size | Parallel? |
|----|-------------|------|-----------|
| **P-1-01** | `run_pip_audit` scans wrong env — use `--requirement` from agent_deps | M | Yes |
| **P-1-03** | `get_brew_packages` absolute path | S | Yes |
| **P-1-04** | `get_pip_packages` use agent_deps instead of monitor venv | M | Yes |
| **P-1-05** | Dashboard auto-refresh on environment scan completion | S | Yes |
| **P-1-06** | Browser AI diagnostic counters | S | Yes |
| **P-1-02** | Startup warn when env table empty + E2E test | S | Yes |
| **P-1-07** | Investigate `is_proxy_enabled`, `get_mcp_known_servers` | S | Yes (parallel investigations) |

**Rationale**: P-1 findings affect *what the product tells the operator*. Every day these ship, the product is actively lying about the customer's security posture. These take priority over Python timing attacks because the timing attacks require an attacker; the product lies happen every time anyone uses the tool.

### Batch 1 — Immediate (parallel-safe, no dependencies)

Can dispatch to 10 parallel Claude Code agents in one message:

| ID | Description | Size |
|----|-------------|------|
| **P0-01** | Fix `sync._read_sessions` watermark | S |
| **P0-06** | `_LOGGER_CACHE` lock | S |
| **P0-08** | `scan_sensitive` truncation log | S |
| **P0-10** | Delete `DASHBOARD_PORT` constant | S |
| **P1-01** | `hmac.compare_digest` in control-plane auth | S |
| **P2-02** | `DISABLE_DASHBOARD_AUTH` loopback check | S |
| **P2-03** | `enforce_permissions` logging | S |
| **P2-04** | Remove `changeme` Postgres default | S |
| **P2-05** | Fix `mask_value` short-value masking | S |
| **P2-11** | Raw exception error-ID wrapping | S |

Parallel-safe rationale: each touches 1–2 files with no overlap.

### Batch 2 — After Batch 1 lands

| ID | Description | Size | Depends |
|----|-------------|------|---------|
| **P0-02** | Watermark semantics consistency | S | P0-01 |
| **P0-03** | Browser ingest error returns | S | — |
| **P0-04** | `_scan_state` mutation fix | S | — |
| **P0-05** | `_alert_dedup` lock | S | — |
| **P0-07** | `_runner` finally block | S | — |
| **P0-09** | Subprocess timeouts | S | — |
| **P1-02** | **Extract `build_sensitive_alert_payload`** | M | — |
| **P1-03** | Control plane dashboard auth | M | P1-01 |
| **P2-06** | Strengthen `hash_value` | S | — |
| **P2-08** | `trust_ca_cert` shlex.quote | S | — |
| **P2-09** | CORS allowlist | S | — |
| **P2-10** | Remove query-string token | S | — |

### Batch 3 — After Batch 2

| ID | Description | Size | Depends |
|----|-------------|------|---------|
| **P1-04** | SyncAgent omits snippet | S | P1-02 |
| **P1-05** | Retroactive scrub migration | M | P1-02 |
| **P2-01** | Browser extension token | M | P1-03 |
| **P2-07** | SyncAgent HTTPS enforcement | S | — |
| **P2-12** | `watch.py` dashboard auth | S | — |
| **P4-10** | Pre-compile regex | S | — |
| **P4-13** | `shell.py` subprocess wrapper | M | — |

### Batch 4 — Sequential refactor track

| ID | Description | Size | Depends |
|----|-------------|------|---------|
| **P4-02** | Split `lifecycle.py` | L | Batch 3 |
| **P4-05** | Import hierarchy + import-linter | M | P4-02 |
| **P4-04** | Extract `JSONLSessionWatcher` | L | P4-05 |
| **P4-11** | VALIDATORS registry | M | — |
| **P4-06** | Alert pipeline abstraction | M | P1-02 |
| **P4-03** | Repository pattern | XL | P4-05 |
| **P4-01** | Split `DashboardHandler` | XL | P4-03, P4-09 |
| **P4-08** | Agent strategy pattern | M | P4-04 |
| **P4-09** | Middleware pattern | M | P4-01 |
| **P4-12** | Kill globals / `MonitorContext` | L | P4-01, P4-03 |
| **P4-07** | Event bus | L | P4-03, P4-06 |
| **P4-14** | Starlette migration | XL | P4-01, P4-09 |

### Agent dispatch template

For each parallel-safe finding, dispatch an agent with this template:

```
Task: Fix finding <ID> from CODE_REVIEW_2026-04-15.md

Context:
- Read CODE_REVIEW_2026-04-15.md section for <ID>
- The fix is self-contained per the "How to Fix" section
- Work unit: <S|M|L>
- Must not touch any other finding's files

Do:
1. Read the affected file(s) from the finding
2. Apply the code change exactly as described
3. Add the tests described in "Testing"
4. Run `pytest -q tests/<relevant>` and confirm green
5. Run `pytest -q` for the full suite and confirm 1103+ passing
6. Run `ruff check src/ tests/` and `ruff format --check src/ tests/`
7. Run `bandit -r src/ -s B101,B404,B603,B607,B310 --severity-level medium`
8. If coverage drops below 72%, add targeted tests
9. Report: diff summary, test count, coverage delta

Do NOT:
- Touch files outside the finding scope
- Combine with other findings
- Introduce new dependencies without explicit mention in the finding
```

---

## 11. Testing Strategy

### Invariants that Must Hold Across All Changes

1. **Test count does not decrease.** Current floor: 1,103 passing tests. Every fix must add ≥1 test or maintain the count.
2. **Coverage does not decrease.** Current: ~72%. Target: 90%. Every new module ships at ≥90%.
3. **Ruff clean.** No lint warnings, formatted.
4. **Bandit clean.** No new medium+ findings.
5. **E2E suite green.** `tests/e2e/test_full_system.py` must pass.
6. **No skipped tests.** `pytest --co` should show zero skips.

### Per-finding Test Checklist

Every fix adds tests in the following categories:

- **Positive test**: the fix works for the golden path.
- **Negative test**: the bad case is rejected / handled.
- **Regression test**: the specific failure described in "What" is reproduced by a test BEFORE the fix and passes AFTER.
- **Edge case**: boundary conditions (empty, max, type-confused input).
- **Security test** (for P1/P2 fixes): explicit assertion that the vulnerable behavior is no longer reachable.

### Test Levels

| Level | Where | Speed | Coverage |
|-------|-------|------:|----------|
| Unit | `tests/test_<module>.py` | <100ms/test | per-function |
| Integration | `tests/test_<module>.py` with real SQLite | <1s/test | per-class |
| E2E | `tests/e2e/test_full_system.py` | <30s/test | per-user-flow |
| Security | `tests/test_security_hardening.py` | <1s/test | per-threat-model |

### Tests to Add for Each P0/P1 Finding

| Finding | New Test Files / Functions |
|---------|---------------------------|
| P0-01 | `test_sync.py::test_read_sessions_honors_last_id`, `test_sync_watermark_advances_with_rowid` |
| P0-02 | `test_sync.py::test_watermark_semantics_aligned` |
| P0-03 | `test_browser_ingest.py::test_failed_insert_reported_in_response` |
| P0-04 | `test_monitor_main.py::test_scan_state_reset_under_race` |
| P0-05 | `test_jsonl_watcher.py::test_alert_dedup_under_concurrent_access` |
| P0-06 | `test_logger.py::test_get_logger_no_duplicate_handlers_under_race` |
| P0-07 | `test_monitor_main.py::test_scan_runner_closes_db_on_error` |
| P0-08 | `test_sensitive.py::test_scan_logs_truncation`, `test_scan_flags_truncation_in_alert` |
| P0-09 | `test_watch_scan.py::test_ps_aux_timeout_handled`, `test_lsof_timeout_handled` |
| P0-10 | `test_config.py::test_dashboard_port_reads_dynamically` |
| P1-01 | `test_cp_auth.py::test_hmac_compare_digest_used`, `test_wrong_prefix_rejected` |
| P1-02 | `test_security_hardening.py::test_browser_ingest_masks_credentials`, `test_build_alert_payload_never_raw` |
| P1-03 | `test_cp_auth.py::test_fleet_routes_require_auth` × N routes |
| P1-04 | `test_sync.py::test_extract_alerts_omits_snippet` |
| P1-05 | `test_db_migration.py::test_historic_alerts_scrubbed`, `test_migration_idempotent` |

### Regression Detection

- **Before the refactor batch (P4)**: snapshot the current test output (`pytest --co --json`) and coverage report. Commit them to `tests/baseline/`.
- **After each P4 finding**: diff against baseline. Any test disappearing = regression.
- **Golden-file tests**: for every API handler, record the current response to a known DB state. Replay after refactor; assert byte-identical (or with clearly documented diffs).

---

## 12. Regression Prevention Checklist

### Before Merging Any Fix

- [ ] `pytest -q` — 1,103+ tests passing
- [ ] `pytest --cov=claude_monitoring --cov-fail-under=72` — coverage ≥72%
- [ ] `ruff check src/ tests/` — clean
- [ ] `ruff format --check src/ tests/` — clean
- [ ] `bandit -r src/ -s B101,B404,B603,B607,B310 --severity-level medium` — no new findings
- [ ] New tests added for the finding (unit + regression)
- [ ] `tests/e2e/test_full_system.py` still green
- [ ] CHANGELOG entry or commit message referencing finding ID

### Before Merging a P4 Refactor

Additionally:
- [ ] Golden-file API response snapshots match baseline (or diffs are documented)
- [ ] Import-linter (after P4-05) shows no new cycles
- [ ] Coverage for touched modules ≥90%
- [ ] Two human reviewers signed off
- [ ] Staging deployment smoke-tested
- [ ] Rollback plan documented in PR description

### CI Gates to Add

Add these to `.github/workflows/ci.yml` as part of the audit cleanup:

```yaml
- name: Enforce test floor
  run: |
    pytest --collect-only --quiet | tail -1 | grep -oE '[0-9]+ test' \
      | awk '{ if ($1 < 1103) { print "Test count regressed"; exit 1 } }'

- name: Enforce coverage floor
  run: pytest --cov=claude_monitoring --cov-fail-under=72

- name: Security lint
  run: bandit -r src/ -s B101,B404,B603,B607,B310 --severity-level medium

- name: Import hierarchy
  run: lint-imports --config .importlinter  # after P4-05

- name: Check for god file growth
  run: |
    LINES=$(wc -l src/claude_monitoring/monitor.py | awk '{print $1}')
    if [ "$LINES" -gt 5352 ]; then
      echo "monitor.py grew beyond baseline ($LINES > 5352)"
      echo "Extract functionality to a new module instead of adding here."
      exit 1
    fi
```

The last gate is particularly important: **freeze `monitor.py` at its current size until P4-01 is complete**. Every new line must go somewhere else.

---

## Appendix A — All Findings Index

### P-1 — Product Reality Gaps

| ID | Title | File | Size | Batch |
|----|-------|------|-----:|------:|
| P-1-01 | `run_pip_audit` scans wrong environment | vuln_scanner.py:51 | M | 0 |
| P-1-02 | Supply Chain "Full Environment" stale on upgrade | vuln_scanner.py:270 | S | 0 |
| P-1-03 | `get_brew_packages` needs absolute path in LaunchAgent context | supply_chain.py:633 | S | 0 |
| P-1-04 | `get_pip_packages` scans monitor venv, not agent envs | supply_chain.py:618 | M | 0 |
| P-1-05 | Dashboard doesn't auto-refresh after scan completion | dashboard.html | S | 0 |
| P-1-06 | Browser AI count stuck at 0 — add diagnostic counters | monitor.py:2315 | S | 0 |
| P-1-07 | Investigate `is_proxy_enabled` / `get_mcp_known_servers` orphans | config.py:191, 197 | S | 0 |

### P0 — Functionality

| ID | Title | File | Size | Batch |
|----|-------|------|-----:|------:|
| P0-01 | SyncAgent `_read_sessions` ignores `last_id` | sync.py:135 | S | 1 |
| P0-02 | Watermark semantics inconsistent | sync.py:95 | S | 2 |
| P0-03 | Browser ingest reports success for failed writes | monitor.py:2387 | S | 2 |
| P0-04 | `_scan_state` rebinding defeats lock | monitor.py:4460 | S | 2 |
| P0-05 | `_alert_dedup` unlocked concurrent access | monitor.py:1127 | S | 2 |
| P0-06 | `_LOGGER_CACHE` double-init race | lifecycle.py:54 | S | 1 |
| P0-07 | `_runner` leaks DB connection on raise | monitor.py:4488 | S | 2 |
| P0-08 | `scan_sensitive` silent truncation at 50KB | utils.py:34 | S | 1 |
| P0-09 | `ps aux` / `lsof` no timeout | watch.py:1493 | S | 2 |
| P0-10 | `DASHBOARD_PORT` captured at import | monitor.py:84 | S | 1 |

### P1 — Security CRITICAL + HIGH

| ID | Title | File | Size | Batch |
|----|-------|------|-----:|------:|
| P1-01 | Control-plane `!=` timing attack | control-plane/cp/auth.py:15 | S | 1 |
| P1-02 | Browser ingest stores raw credentials | monitor.py:2402 | M | 2 |
| P1-03 | Control-plane dashboard routes unauth'd | control-plane/cp/app.py:12 | M | 2 |
| P1-04 | SyncAgent forwards raw snippets | sync.py:221 | S | 3 |
| P1-05 | Retroactive scrub migration | security.py:393 | M | 3 |

### P2 — Security MEDIUM

| ID | Title | File | Size |
|----|-------|------|-----:|
| P2-01 | Browser ingest/heartbeat skip auth | monitor.py:1883 | M |
| P2-02 | `DISABLE_DASHBOARD_AUTH` no bind check | monitor.py:1775 | S |
| P2-03 | `enforce_permissions` silent failures | security.py:275 | S |
| P2-04 | Hardcoded `changeme` DB password | control-plane/cp/db.py:17 | S |
| P2-05 | `mask_value` reveals 8 chars for short | security.py:367 | S |
| P2-06 | 64-bit truncated hash | security.py:381 | S |
| P2-07 | SyncAgent over HTTP | sync.py:100 | S |
| P2-08 | `trust_ca_cert` shell injection | security.py:225 | S |
| P2-09 | Wildcard CORS | monitor.py:2162 | S |
| P2-10 | Token in URL query | monitor.py:1778 | S |
| P2-11 | Raw exceptions in responses | monitor.py:1866 | S |
| P2-12 | `watch.py` dashboard zero auth | watch.py:1400 | S |

### P3 — Security LOW + INFO

| ID | Title | File | Size |
|----|-------|------|-----:|
| P3-01 | TOCTOU file create/chmod | security.py:331 | S |
| P3-02 | Hardcoded test API key | simulate_endpoint.py:14 | S |
| P3-03 | Port not validated before subprocess | monitor.py:4363 | S |
| P3-04 | f-string SQL with nosec | monitor.py:356 | S |
| P3-05 | No rate limiting | all | M |
| P3-06 | CA private key unencrypted | security.py:163 | M |
| P3-07 | `/health` unauth (informational) | control-plane/cp/app.py:16 | INFO |
| P3-08 | Unused bcrypt hash | control-plane/cp/registry.py:39 | S |

### P4 — Modularity / Framework

| ID | Title | Size |
|----|-------|-----:|
| P4-01 | Split `DashboardHandler` | XL |
| P4-02 | Split `lifecycle.py` | L |
| P4-03 | Repository pattern | XL |
| P4-04 | Extract `JSONLSessionWatcher` | L |
| P4-05 | Import hierarchy + import-linter | M |
| P4-06 | Alert pipeline abstraction | M |
| P4-07 | Event bus | L |
| P4-08 | Agent strategy pattern | M |
| P4-09 | HTTP middleware pattern | M |
| P4-10 | Pre-compile regex | S |
| P4-11 | VALIDATORS registry protocol | M |
| P4-12 | Kill module globals | L |
| P4-13 | `shell.py` subprocess wrapper | M |
| P4-14 | Starlette migration | XL |

### P5 — Code Quality / Tech Debt

(11 items, see §9 for details)

---

## Appendix B — File × Finding Matrix

| File | Findings |
|------|----------|
| `src/claude_monitoring/monitor.py` | P0-03, P0-04, P0-05, P0-07, P0-10, P1-02, P2-01, P2-02, P2-09, P2-10, P2-11, P3-03, P3-04, P4-01, P4-04, P4-08, P4-09, P5-03, P5-04, P5-05, P5-07, P5-09 |
| `src/claude_monitoring/sync.py` | P0-01, P0-02, P1-04, P2-07 |
| `src/claude_monitoring/security.py` | P1-02, P1-05, P2-03, P2-05, P2-06, P2-08, P3-01, P3-06, P5-01 |
| `src/claude_monitoring/lifecycle.py` | P0-06, P4-02 |
| `src/claude_monitoring/watch.py` | P0-09, P2-12, P4-13 |
| `src/claude_monitoring/utils.py` | P0-08, P4-10 |
| `src/claude_monitoring/validators.py` | P4-11, P5-01 |
| `src/claude_monitoring/config.py` | P4-05, P4-12, P5-06 |
| `src/claude_monitoring/supply_chain.py` | P5-01, P5-05, P5-06 |
| `src/claude_monitoring/db.py` | P4-03, P5-08 |
| `src/claude_monitoring/constants.py` | P4-10, P5-11 |
| `src/claude_monitoring/dashboard.html` | P5-10 |
| `control-plane/cp/auth.py` | P1-01 |
| `control-plane/cp/app.py` | P1-03, P3-07 |
| `control-plane/cp/dashboard.py` | P1-03 |
| `control-plane/cp/db.py` | P2-04 |
| `control-plane/cp/registry.py` | P3-08 |
| `control-plane/test-client/simulate_endpoint.py` | P3-02 |

---

## Appendix C — Reviewer's Note on Methodology

### What I Missed and Why

The first two passes of this review produced 60 findings across security, functionality, and modularity — but **missed the entire class of orchestration/scope bugs** (P-1) that most directly affects whether the product does what it says on the box. The trigger for adding P-1 was the product owner reporting an empty "Full Environment" view in the Supply Chain tab. On investigation:

- `get_full_environment()` and `store_environment_packages()` existed in the code with tests.
- The DB table existed.
- The dashboard tab existed.
- **Nothing in any production path called them.**

My original analysis found `get_full_environment` during dead-code detection and filed it as **P5-06: delete unused code**. The correct classification was **"shipped-broken feature that needs wiring, not removal"**.

### Root Cause of the Miss

Three methodological defects, in order of how much damage they cause:

1. **Graph-based dead code detection tells you a function has no callers. It does NOT tell you why.** The graph is morally neutral — it cannot distinguish "orphan because nobody needs it" from "orphan because somebody forgot to wire it up". I treated the former as the default.

2. **Test suites certify correctness in isolation, not integration.** `test_environment.py::test_store_and_query` passed because it tested the function directly with hand-crafted input. `test_vuln_scanner.py::test_scans_all_packages` passed because it did not assert that environment data got populated. Both tests green, feature dead.

3. **I never loaded the UI against a populated DB.** The Supply Chain tab's empty-state message "No environment data. Click 'Scan now' to gather installed packages." was visible to anyone who opened the dashboard. I would have caught it in 30 seconds.

### New Heuristics Added to the Methodology

Going forward, any review of this codebase (or ones like it) must include:

**H1 — Orphan investigation, not orphan deletion**

Before filing a function as dead code:
```
For each production-code function F with 0 inbound CALLS:
  1. What feature was F clearly written to support? (grep UI, docs, config for clues)
  2. If a feature: is the feature currently broken or missing in production?
  3. If broken: file as P-1 orchestration gap.
  4. If missing entirely (no UI, no config, no docs): file as P5 dead code.
```

**H2 — Subprocess scope verification**

For every subprocess invocation or filesystem walk:
```
What tree/namespace/environment does this operate on AT RUNTIME in production?
  - Not what the test mocks it to be.
  - Not what the developer assumed when writing it.
  - Actually: under LaunchAgent, under the monitor's venv, as root, etc.
If the answer isn't "the same environment the user cares about": file as P-1 scope bug.
```

**H3 — UI / backend pairing**

Build and maintain a table (see §4, end) that pairs every dashboard tab with:
- The endpoint that feeds it
- The production code path that populates the data
- A test that asserts the end-to-end population

Any row without all three filled in is a P-1 suspect. Every new tab/feature must add a row before merge.

**H4 — Empty-state audit**

Grep the dashboard HTML for every "No data" / "No records" / "Click to populate" message. For each one, trace back the population path and verify it runs in production — not just in tests.

**H5 — "Does a customer see what the operator thinks they see?"**

At least one pass per review must be done with the mindset of a customer opening the dashboard for the first time. Every empty number, every "0 records", every "pending" is a suspect. A green CI pipeline means nothing if the dashboard shows the wrong data.

### What This Means for Ongoing Reviews

The audit process should be structured as **five passes, not three**:

| Pass | Focus | Tools | Can miss without it |
|------|-------|-------|---------------------|
| 1 | Security | graph + CVE knowledge | timing attacks, auth bypasses, secret leaks |
| 2 | Code quality / modularity | graph + metrics | god files, duplication, tight coupling |
| 3 | Functionality / concurrency | graph + manual reads | races, leaks, wrong types |
| **4** | **Product reality gaps** | **graph + UI walkthrough + config audit** | **unwired features, scope bugs, empty tabs** |
| **5** | **End-to-end customer simulation** | **run the actual product** | **any of the above that slipped through** |

Passes 4 and 5 were missing from the original review structure. They are now mandatory.

### Closing the Loop

The fact that this entire category was missed in two rigorous passes is itself a finding: **code review disciplined by graph analysis and source reading is necessary but not sufficient**. A shipping architect has to *use the product* periodically and trace anything that looks off back to the code, not the other way around.

The user catching this by running the product did my job better than my graph queries did. That is a process improvement worth preserving.

---

## Closing Notes

This review is the result of **four** audit passes over four days (originally three; P-1 added after the product-reality-gap miss was surfaced). The codebase is substantively better than most early-stage security tools, with a strong test culture (1,103 tests), a real CI pipeline, and a thoughtful approach to process lifecycle (`lifecycle.py`). The failures are in the predictable places: god files, duplicated pipelines, missing abstractions that the design has outgrown — **plus** a less predictable pattern where features are wired in pieces that never meet.

The fix list is intentionally **asymmetric**: 7 product reality gaps (P-1) and 35 small findings (P0–P3) that can be parallelized in two dispatch batches, and 14 structural findings (P4) that need sequential attention. Done in order, the batches should take roughly **3–4 weeks of focused engineering**, with the first week producing visible progress on every major issue — **especially the Supply Chain tab reporting correct numbers** — and the remaining weeks absorbed by the structural refactor track.

The single most important **cultural change** is the discipline added to the review methodology (Appendix C): every future review loads the UI against a populated DB, and every unused function is a suspect for "broken product feature" rather than "delete candidate".

The single most important **CI change** is **freezing `monitor.py` at its current size** until P4-01 completes. Without that gate, the god file will continue to absorb every new feature and the split effort will be perpetual catch-up.

**Plugins used this review**: codebase-memory-mcp (get_architecture, search_graph, search_code, query_graph, trace_call_path), superpowers:code-reviewer-style rigor applied across 4 passes, Read tool for verification, and — critically — a corrective pass driven by the product owner running the actual product and reporting a broken tab.
