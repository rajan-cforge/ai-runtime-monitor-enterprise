# CLAUDE.md — Working rules for this repo

This file tells Claude Code how to work on AI Runtime Monitor. Read it at
the start of every session. Deviations from these rules should be rare
and explained in the response.

## Repo context

- **Product**: AI Runtime Monitor — a CrowdStrike-style observability tool for
  AI coding agents (Claude Code, OpenClaw, Cursor, ChatGPT Desktop, Claude
  Desktop, Ollama, browser-based AI). Private to GoCloudForge, Inc.
- **Language**: Python 3.9+ (runs on 3.9–3.13), ~5k lines in `src/`.
- **Layout**: `src/claude_monitoring/` is the main package. `monitor.py`
  is the CLI + dashboard HTTP server, `watch.py` is the mitmproxy addon,
  `security.py` / `wizard.py` / `cleanup.py` / `status.py` are lifecycle
  helpers. `dashboard.html` is the frontend (plain JS, no framework).
- **Tests**: `tests/` is flat, ~45 files, currently 1103 passing. CI gates
  on lint + format + pytest + coverage (currently 70%, target 90%).
- **CI**: `.github/workflows/ci.yml` runs lint (ruff), test matrix
  (ubuntu/macos × 3.9/3.11/3.12/3.13), and bandit. All must be green
  before merge.

## Git rules

- **Authorship**: Commits MUST be by `Rajan Yadav <rajan.conch@gmail.com>`.
  Never add `Co-Authored-By: Claude …` or any AI co-authorship trailer.
  Set author via env vars, never touch `git config`:
  ```bash
  GIT_AUTHOR_NAME="Rajan Yadav" GIT_AUTHOR_EMAIL="rajan.conch@gmail.com" \
  GIT_COMMITTER_NAME="Rajan Yadav" GIT_COMMITTER_EMAIL="rajan.conch@gmail.com" \
  git commit -F <message-file>
  ```
- **Push env**: `HTTPS_PROXY` must be unset for `git push` (the user's shell
  sometimes has it set). Prefix with `HTTPS_PROXY= git push …`.
- **Commit style**: Explanatory. Use a short prose header, then `────`
  section breaks, then detailed "what changed and why" paragraphs. Look
  at recent commits for the pattern.
- **NEVER** add `HTTPS_PROXY` or `NODE_EXTRA_CA_CERTS` globally to `~/.zshrc`.
  The user has been burned by this — it breaks Claude Code's own API
  connectivity when mitmproxy is down. If the user needs to route their
  own `claude` CLI through the proxy, suggest a per-command alias instead:
  ```bash
  alias claude-monitored='HTTPS_PROXY=http://127.0.0.1:9080 NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem claude'
  ```

## Quality gates — don't skip

Every commit must pass locally before push:

```bash
source .venv/bin/activate

# 1. Lint + format
ruff check src/ tests/
ruff format --check src/ tests/

# 2. Tests (all must pass)
python -m pytest -q

# 3. Coverage above the CI gate
python -m pytest --cov=claude_monitoring --cov-report=term --cov-fail-under=70

# 4. Bandit (security linter)
bandit -r src/ -s B101,B404,B603,B607,B310 --severity-level medium
```

**Coverage target**: 90%. Current: ~72%. Every new module should ship at
≥90% coverage for its own code (even if the repo-wide gate is still 70%).
Raise the gate in `.github/workflows/ci.yml` when we're consistently
above it — ratchet, never slide back.

**Regression rule**: 1103 tests passing is the floor. If a change drops
the count, figure out why before committing. Don't delete tests to make
them "pass".

## Plugin contract

The user has installed several Claude Code plugins specifically so I'd
use them. Using them is NOT optional — it's how we hit the quality bar.
Each plugin has a trigger condition and a stop condition. Follow them.

### codebase-memory-mcp — BEFORE any non-trivial exploration

**Trigger**: any task that would require more than 3 Grep/Glob/Read calls
to find symbols, trace call graphs, or understand "who calls X" / "what
does X call". The repo is indexed (2293 nodes, 4881 edges).

**Use these tools instead of Grep**:
- `search_graph(name_pattern=…)` — find functions/classes by name
- `trace_call_path(function_name=…)` — "who calls X" with full transitive chain
- `search_code(pattern=…)` — grep-equivalent scoped to the indexed project
- `get_code_snippet(qualified_name=…)` — read a function by its fully-qualified name
- `get_architecture(aspects=['all'])` — high-level map of the codebase
- `query_graph(cypher=…)` — ad-hoc Cypher for cross-cutting queries

**Re-index** via `index_repository()` at the start of a session if the
codebase has changed significantly since the last index (check
`index_status()` first). Incremental re-indexes are cheap.

**When NOT to use**: reading a single known file (`Read` is fine), running
a shell command (`Bash`), or editing a file I just wrote (no need to search).

### superpowers:test-driven-development — BEFORE writing implementation code

**Trigger**: any new feature or bugfix with a spec. Write the failing
test FIRST, verify it fails for the right reason, then write the code to
make it pass.

**When NOT to use**: pure refactors with no behavior change, formatting
fixes, lint cleanups, comment updates.

### superpowers:verification-before-completion — BEFORE claiming done

**Trigger**: any claim that work is "complete", "passing", "fixed", or
"ready to commit". Requires running the actual verification command and
showing its output BEFORE making the assertion. "Evidence before
assertions."

### code-review — BEFORE every commit

**Trigger**: when the staged diff is larger than ~50 lines or touches
more than one module. Run the `code-review` plugin on the staged diff.
Fix all high-severity findings before committing. Acknowledge
medium-severity findings in the commit message if deferred.

### frontend-design:frontend-design — FOR any UI/UX work on the dashboard

**Trigger**: any change to `src/claude_monitoring/dashboard.html` that
affects visual design, layout, information density, or user flow. Also
for new dashboard tabs, new charts, new panels, or restyling existing
ones.

**Our dashboard is the product**. A Fortune 500 CISO or SOC analyst
should look at it and feel it's competitive with CrowdStrike Falcon or
Datadog Cloud Security. Use `frontend-design` to:
- Generate distinctive, production-grade components
- Avoid generic AI-looking UI (no rounded-everything, no purple gradients)
- Match the current dark theme (`--bg: #0d1117`, `--surface: #161b22`,
  `--text: #c9d1d9`, `--accent: #58a6ff`)
- Improve information density — we have 9 tabs and tons of data; the
  designer's instinct should always be "show more, smaller" not "hide
  behind a click"

**When NOT to use**: one-line fixes (typo, color tweak), bug fixes that
don't change visual design.

### playwright — FOR E2E and UI/UX tests

**Trigger**: any end-to-end test that needs to actually load the
dashboard, click a tab, trigger a fetch, verify rendered state. Also for
testing the browser extension against real claude.ai / chatgpt.com /
gemini.google.com.

**Target test locations**:
- `tests/e2e/` — pytest-driven playwright tests of the dashboard
- `tests/extension/` — playwright-driven Chrome extension tests

**Coverage goal**: every dashboard tab has at least one E2E test that
loads it and asserts key elements render. Every user flow (first-run
wizard, cleanup, status, purge) has a test that exercises it end to end.

### superpowers:executing-plans — FOR multi-step tasks with a written spec

**Trigger**: the user provides a numbered spec with multiple sections
(like this sprint's Checkpoint plan). Enforces checkpoint discipline,
test-before-code, and no-skipping-verification.

### superpowers:dispatching-parallel-agents — FOR 2+ independent tasks

**Trigger**: when a task decomposes into 2+ pieces that don't share
state or depend on each other. Dispatch in parallel via the Agent tool
instead of sequential work. Example: "add new endpoint + new test file
+ new dashboard section" can be three parallel agents.

### simplify / code-simplifier — AFTER writing code, BEFORE committing

**Trigger**: when the code I just wrote has any of these smells:
- Duplicated logic across 2+ call sites
- A function >50 lines that could split
- Nested loops / deep conditionals
- Excessive comments explaining WHAT the code does (vs WHY)

Run the simplify skill to review and refactor before committing.

### superpowers:systematic-debugging — WHEN a bug appears

**Trigger**: any unexpected test failure, CI failure, or runtime error.
Use systematic-debugging BEFORE proposing a fix. No guessing fixes.

### code-review:code-review — pre-PR review

**Trigger**: before opening a PR or before a final push at the end of
a sprint checkpoint. Runs a structured review of the diff.

## Skill-use logging

For every session, track which plugins were used for which tasks in the
response. If I'm not using them often enough, the user should be able to
see the gap at a glance. Format:

```
Plugins used this turn: codebase-memory-mcp (search_graph × 2),
  superpowers:test-driven-development, playwright
```

## Code style

- **No emojis in code or commit messages** unless the user explicitly
  asks. (The existing code does use emojis in print statements for the
  TUI — match the existing style, don't introduce more.)
- **No comments explaining WHAT code does** — well-named identifiers do
  that. Only add comments for WHY: non-obvious invariants, hidden
  constraints, workarounds, subtle edge cases.
- **Don't narrate in docstrings** — keep them short (one line preferred).
- **No `from typing import Optional`** — use `X | None` (with
  `from __future__ import annotations` for Python 3.9 compat).
- **Fail closed in security code**: any exception in a security check
  must return the safe default (e.g. "not trusted"), not raise. Never
  crash the CLI on a check failure.
- **Use `hmac.compare_digest` for token comparisons** — no `==`.
- **Mask credentials at write time**, never store plaintext in the DB.

## Testing style

- **Fixtures in `tests/conftest.py`** are shared. Don't inline the same
  setup across test files.
- **Test names**: `test_<behavior>_<condition>` — e.g.
  `test_auth_rejects_wrong_token`, not `test_auth`.
- **Parametrize** when testing many values of the same behavior
  (`@pytest.mark.parametrize`).
- **One logical assertion per test** is the ideal. Multiple is OK when
  they're verifying facets of the same behavior.
- **Never mock the database in tests** — use `init_db()` with a tmp path.
  We were burned before by tests passing on mocks but failing on real
  migrations. Integration tests hit a real SQLite file.
- **Auth in tests**: set `DISABLE_DASHBOARD_AUTH=1` env var in the
  fixture. The auth machinery itself is tested separately in
  `tests/test_security_hardening.py`.
- **Time-relative tests**: use `datetime.now() - timedelta(...)`, never
  hardcoded dates. Hardcoded dates become time bombs.

## UI/UX goals (frontend-design plugin)

When touching `dashboard.html`:

1. **Information density over whitespace**. A SOC analyst wants to see
   30 sessions at a glance, not 3. Use tight padding, small type,
   alternating row backgrounds for scannability.
2. **Status is everything**. Every row should communicate its state in
   under 100ms of eye-travel. Use color hierarchy: red > orange > yellow
   > green > gray.
3. **No modals for primary actions**. Inline expansion is faster.
   Modals are for destructive confirmations (purge) only.
4. **Live updates must be visible but not jarring**. Fade in new rows,
   don't flash the whole table. The Live Feed tab is the model.
5. **Match the existing dark theme**. New components must use the CSS
   custom properties (`--bg`, `--surface`, `--surface2`, `--text`,
   `--text2`, `--border`, `--accent`, `--red`, `--orange`, `--green`).
6. **Accessibility is not optional**. Every interactive element has a
   visible focus state. Color is never the only signal.

## Coverage roadmap

Current state:
```
sync.py             0%    ← biggest hole
watch.py           56%    ← mitmproxy code paths
vuln_scanner.py    62%
monitor.py         72%    ← huge file, dashboard handlers
security.py        79%
supply_chain.py    82%
db.py              84%
threat_intel.py    86%
utils.py           95%
validators.py      99%
report.py         100%
```

Target order (next tests to write, per session):
1. `sync.py` — zero coverage, one module, small. Easy win.
2. `watch.py` mitmproxy addon paths — requires mock mitmproxy flow
   objects. High impact.
3. `vuln_scanner.py` — needs mocked OSV API responses.
4. `monitor.py` dashboard handlers — big but split into per-endpoint
   tests.

Each session should move at least one module toward 90%. Track in commit
messages with "coverage: X% → Y% (+N%)".

## Don't

- Don't add files without being asked (no README.md, CHANGELOG.md,
  CONTRIBUTING.md unless requested).
- Don't add comments marking what you removed ("// removed toggleReveal").
- Don't leave backwards-compat shims for dead code. If it's gone, delete it.
- Don't add feature flags for scenarios that can't happen.
- Don't validate internal call sites — trust Python. Validate at the
  boundary (HTTP body, CLI arg, file input).
- Don't write "as requested", "as specified", "as per the user's
  instructions" in code or commit messages. The PR / issue / conversation
  is authoritative — don't rot the code with references to ephemeral
  context.
