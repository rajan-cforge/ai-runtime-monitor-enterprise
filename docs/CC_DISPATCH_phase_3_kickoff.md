# Phase 2 → Phase 3 Dispatch

You stopped at Phase 2 with 10 questions. Here are the answers plus
additional instructions. Read this whole document, then proceed.

## Q1-Q10 answers

**Q1 — Quality Gates triage.** Accept the Q1/Q2/Q3 split as proposed
by the prior session. Q1 ships this sprint, Q2 next week, Q3 post-launch.

**Q2 — Lane D scope.** Option (b) split. D1 = polish dashboard.html in
place this sprint (security fixes + visual cleanup, no framework change).
D2 = React migration post-launch as its own week. The C2 XSS fix lands
in dashboard.html's escape pipeline now; D2 inherits a hardened pipeline.

**Q3 — Lane A (Tauri).** Defer to post-launch v0.3. Ship CLI + Homebrew
tap this sprint. Apple notarization queue, signing cert work, and
auto-update infrastructure cost 2-3 days that buy you nothing brew
doesn't already give power users. Tauri ships with its own launch
moment in v0.3.

**Q4 — Lane B home.** Confirm `src/claude_monitoring/extension_scanner/`.
Fits the existing flat layout.

**Q5 — Lane C (brand site).**
- Product name: **Vigil**
- Domain: **vigil.gocloudforge.com** (subdomain under existing
  Squarespace-managed gocloudforge.com — no domain registration today)
- Tagline: "Endpoint security for the AI developer"
- CLI binary name: `vigil`
- Brew tap: `gocloudforge/tap/vigil` (verify availability before
  publishing)
- PyPI package name: `vigil-monitor` (verify availability; `vigil`
  alone is almost certainly taken on PyPI)
- Local path: `/Users/rajanyadav/code/airuntimemonitor-site`
  (rename later, internal-only for now)
- Brand site hosting: Vercel, pointed at vigil.gocloudforge.com via
  Squarespace DNS CNAME (user handles DNS step manually outside
  this session)
- Stripe Payment Link: not yet created. Use placeholder env var
  `STRIPE_PRO_LINK` in Lane C and skip the live checkout until
  launch day

Update CC_PROMPT_02_brand_site.md and any draft launch copy to use
"Vigil" everywhere a customer would see the name. Do NOT rename:
- The repo (`ai-runtime-monitor-enterprise`)
- The Python package (`claude_monitoring`)
- Any internal docs (AGENTS.md, BRANCHING.md, etc.)

Rename is customer-surface only. Internal stays as-is to avoid a
giant rename PR.

**Q6 — Critical fixes.** Four separate branches:
- `security/c1-bcrypt`
- `security/c2-xss-esc`
- `security/c3-sync-fail-open`
- `security/c4-osascript-injection`

Each ships as its own PR with its own CI run. Independent revert
capability is worth the extra PR overhead.

**Q7 — Co-Authored-By: Claude trailers.** Option (c) defer
signed-commits gate to post-launch (Q3 of quality gates). Create
`docs/COMMIT_HISTORY_EXCEPTIONS.md` documenting the three pre-policy
SHAs (`8f07f9e`, `770eef2`, `7a8d712`) as historical exceptions. New
policy applies prospectively from the next commit forward.

**Q8 — Antfooding.** Yes. Install the latest build on the dev machine
today. Create `docs/ANTFOODING_LOG.md` with a Day 0 entry. If the
current build is unstable enough to disrupt development, that is the
most important antfooding finding of the sprint — document it.

**Q9 — Lane B API routes.** Wire inline into
`monitor.py::DashboardHandler`. Do NOT create `api/` subpackage in
this sprint. Tag every new handler method with:

```python
# TODO(M6): extract to api/extension_routes.py during monitor.py split
```

The monitor.py split is audit finding M6, already on the post-launch
roadmap. Doing the split now inverts the planned order and adds
two days. Sprint speed > architectural purity here.

**Q10 — Dev dependencies.** Add both to `pyproject.toml [project.optional-dependencies.dev]`:
- `pytest-asyncio>=0.23` (required for async scanner service tests)
- `python-Levenshtein>=0.25` (R008 typosquat detection runs against
  top-100 popular extensions on every scan; difflib at that scale
  spikes CPU — do NOT use difflib fallback)

## Phase 3.0 — Plugin integration audit (NEW, runs before Phase 3A)

Budget: 30 minutes. Branch: `infra/plugin-integration`.

The 6 plugins discovered in Phase -1 (code-review, feature-dev,
security-guidance, frontend-design, playwright, superpowers) overlap
with custom subagent/skill definitions in
`CC_PROMPT_00_multi_agent_harness.md`. Reconcile before dispatching
specialists.

Procedure:

1. For each plugin listed in `docs/TOOLING.md`, enumerate the tools/
   skills it exposes.
2. Check for overlap with custom definitions in CC_PROMPT_00:
   - Does the `code-review` plugin supersede the `code-reviewer.md`
     custom subagent?
   - Does the `feature-dev` plugin provide the TDD-loop workflow that
     `.claude/skills/tdd-loop/SKILL.md` encodes?
   - Does the `security-guidance` plugin supersede the
     `security-reviewer.md` custom subagent?
   - Does the `frontend-design` plugin overlap with the
     `design-system-curator.md` custom subagent?
3. For each overlap:
   - If the plugin tool is at least as capable as the custom definition,
     delete the custom definition and reference the plugin in the
     relevant rubric.
   - If the custom definition has unique capability the plugin lacks,
     keep it and document the rationale in `docs/TOOLING.md`.
4. Update all four lane rubrics (`.claude/rubrics/lane-*.md`) to
   reference the resolved capability map.
5. Update `docs/TOOLING.md` with the overlap notes.
6. Commit and PR.

Exit gate:
- No duplicate capability between plugins and custom subagents
- Rubrics reference the resolved capability set
- PR merged with green CI

## Phase 3A — Critical security fixes (C1-C4)

Entry gate: Phase 3.0 merged. Q1-Q10 answers above noted in
`docs/RECONCILIATION_LOG.md`.

For each critical, follow strict TDD:
1. Write the regression test first
2. Run it. Confirm it fails against current code.
3. Write the minimal fix.
4. Run the test. Confirm it passes.
5. `git stash` the fix. Run the test again. Confirm it fails again.
   (This proves the test is not a tautology.)
6. `git stash pop`. Run the test. Confirm it passes again.
7. Run the full test suite. Confirm no regression.
8. Commit on the appropriate branch with conventional commit message
   referencing the audit ID.
9. Open PR with the audit doc link and the before/after evidence.

The four branches can be worked in parallel (different modules, no
file overlap). Use git worktrees if running parallel Claude Code
sessions.

### C1 — `security/c1-bcrypt`

**File:** `tests/integration/test_control_plane_auth.py`

```python
def test_password_check_calls_bcrypt_checkpw(monkeypatch):
    """If current code uses == comparison, bcrypt.checkpw is never
    called, the mock records 0 calls, and this test fails."""
    calls = []
    monkeypatch.setattr(bcrypt, "checkpw",
        lambda pw, h: calls.append((pw, h)) or False)
    response = client.post("/login",
        json={"username": "admin", "password": "anything"})
    assert response.status_code == 401
    assert len(calls) == 1, "bcrypt.checkpw must be called"


def test_password_check_constant_time_against_timing_attack():
    """100 attempts with first-char-matching password vs 100 with
    no-char-matching. Stdev of timing diff < 5ms within noise. == 
    comparison early-exits on first mismatch and leaks timing."""
    # ... measure timings, assert stdev bound


def test_password_hash_uses_minimum_12_rounds(stored_hash):
    """Parse bcrypt $2b$XX$ prefix; assert XX >= 12."""
    prefix = stored_hash.split(b"$")
    cost = int(prefix[2])
    assert cost >= 12, f"bcrypt cost {cost} below minimum 12"


def test_password_hash_salt_is_unique_per_user():
    """Register two users with same password; assert hashes differ
    because salt is embedded per-user."""
    h1 = hash_password("samepass")
    h2 = hash_password("samepass")
    assert h1 != h2, "salt must be unique per hash"
```

**Fix:** Replace whatever the current code does with
`bcrypt.checkpw(password.encode(), stored_hash)`. Bump rounds to 12
if lower (`bcrypt.gensalt(rounds=12)`). Verify salt generated
per-user.

### C2 — `security/c2-xss-esc`

**File:** `tests/integration/test_dashboard_xss.py`

```python
@pytest.fixture
def xss_payloads():
    """Load tests/fixtures/xss_payloads.txt — populate from audit
    findings."""
    return Path("tests/fixtures/xss_payloads.txt").read_text().splitlines()


def test_attribute_context_escapes_quotes():
    """Field rendered in attribute context. Payload contains:
    " onmouseover=alert(1) "
    Assert: rendered HTML does not contain unescaped " in attribute
    context. Assert: rendered HTML does not contain onmouseover=
    If esc() only handles HTML body context, this fails."""
    payload = '" onmouseover=alert(1) "'
    rendered = render_session_card({"name": payload})
    assert ' onmouseover=' not in rendered
    assert payload not in rendered  # raw payload must not appear


def test_html_body_context_escapes_angle_brackets():
    payload = "<script>alert(1)</script>"
    rendered = render_session_body({"text": payload})
    assert "&lt;script&gt;" in rendered
    assert "<script>" not in rendered


def test_js_string_context_escapes_backslash_and_quote():
    """Field used inside a JS string literal containing:
    \"; alert(1); //
    Assert: rendered JS does not break out of the string literal."""
    payload = '\\"; alert(1); //'
    rendered = render_js_inline({"value": payload})
    # parse rendered JS, confirm payload is contained within string


def test_url_context_escapes_javascript_scheme():
    payload = "javascript:alert(1)"
    rendered = render_link_href({"href": payload})
    assert 'href="javascript:' not in rendered.lower()


def test_xss_payloads_from_audit_fixtures(xss_payloads):
    """For every payload in audit's XSS list, assert no script
    execution path in rendered output."""
    for payload in xss_payloads:
        for context_fn in [render_session_card, render_session_body,
                          render_js_inline, render_link_href]:
            rendered = context_fn({"field": payload})
            # context-specific assertions per context
```

**Fix:** Replace single `esc()` with four context-aware helpers:
`escHtml()`, `escAttr()`, `escJs()`, `escUrl()`. Every template
insertion picks the right one based on its position. Create
`tests/fixtures/xss_payloads.txt` with payloads from audit C2 detail.

### C3 — `security/c3-sync-fail-open`

**File:** `tests/integration/test_sync_sanitize.py`

```python
def test_sanitize_returns_empty_on_unicode_error():
    """Bytes that fail .decode() must return "" not raw input."""
    bad = b"\xff\xfe\xff\xfe"
    result = _sanitize_string(bad)
    assert result == "", "must fail closed, not return raw bytes"


def test_sanitize_returns_empty_on_oversized_input():
    """10MB input above limit must be truncated or rejected."""
    huge = "A" * (10 * 1024 * 1024)
    result = _sanitize_string(huge)
    assert len(result) < len(huge), "must not return full input"


def test_sanitize_returns_empty_on_control_characters():
    """\\x00, \\x07, \\x1b must be stripped or input rejected."""
    bad = "hello\x00\x07\x1bworld"
    result = _sanitize_string(bad)
    assert "\x00" not in result
    assert "\x07" not in result
    assert "\x1b" not in result


def test_sanitize_logs_failures_for_observability(caplog):
    """Warning logged on fail path. Do NOT log raw input."""
    _sanitize_string(b"\xff")
    assert any("sanitize" in r.message.lower()
               for r in caplog.records if r.levelname == "WARNING")
    # confirm raw bad input not in logs
    assert "\\xff" not in caplog.text


def test_all_callers_handle_empty_return():
    """Audit every call site of _sanitize_string. Empty-string return
    must be treated as rejection, not silent passthrough."""
    # for each caller (use codebase-memory-mcp find references),
    # static-analyze: does it check the return value?
```

**Fix:** Change `except: return input` to
`except Exception as e: logger.warning("sanitize failed: %s", type(e).__name__); return ""`.
Audit all callers (use codebase-memory-mcp `search_graph` or
`trace_call_path`) to confirm empty-return is handled as rejection
upstream. The riskier part of the fix is the caller audit, not the
function change.

### C4 — `security/c4-osascript-injection`

**File:** `tests/integration/test_notifications.py`

```python
def test_notification_does_not_use_shell_true(monkeypatch):
    """Record subprocess.run calls; assert shell kwarg is False or absent."""
    calls = []
    real_run = subprocess.run
    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return real_run(["true"], **{k: v for k, v in kwargs.items() if k != "shell"})
    monkeypatch.setattr(subprocess, "run", spy)
    notify("test title", "test body")
    assert all(not kw.get("shell", False) for _, kw in calls)
    assert all(isinstance(args[0], list) for args, _ in calls), \
        "argv must be a list, not a single string"


def test_notification_blocks_shell_metacharacters_in_title(monkeypatch):
    """Confirm subprocess.run argv does NOT contain shell metacharacters
    in a position that could escape the AppleScript string."""
    calls = []
    monkeypatch.setattr(subprocess, "run",
        lambda *a, **kw: calls.append((a, kw)))
    notify('"; do shell script "rm -rf ~"', "body")
    # extract the -e argument, verify the bad string is escaped within
    # AppleScript quoting, not breaking out of it
    for args, _ in calls:
        argv = args[0]
        e_arg = argv[argv.index("-e") + 1] if "-e" in argv else ""
        assert 'do shell script' not in e_arg or e_arg.startswith('display notification')


def test_notification_blocks_shell_metacharacters_in_body(monkeypatch):
    """Same as title, applied to body parameter."""


def test_notification_handles_unicode_safely():
    """Unicode in title and body must succeed without encoding errors."""
    notify("🔥 Critical 안녕하세요", "Unicode body مرحبا")
```

**Fix:** Replace
`subprocess.run(f'osascript -e \'display notification ...\'', shell=True)`
with
`subprocess.run(["osascript", "-e", applescript_string], shell=False)`.
Add helper `escape_applescript_string(s)` that escapes `"` and `\` for
AppleScript string literals (this is NOT bash escaping — do NOT use
`shlex.quote`). AppleScript escaping rules: `"` becomes `\"`, `\`
becomes `\\`.

## Discipline reminders

- Every PR runs through CI before merge
- Every commit follows conventional commits (`security(C1): ...`)
- Every regression test must be proven to fail without the fix
  (steps 5-6 of the TDD procedure)
- No Co-Authored-By: Claude trailers on new commits
- Update `docs/RECONCILIATION_LOG.md` if any discrepancy surfaces
- Update `docs/SPRINT_ONE_WEEK.md` at every phase transition
- Daily entry to `docs/ANTFOODING_LOG.md` (per Q8)

## After Phase 3A completes

Stop and report. Provide:
1. The 4 PR links (one per critical)
2. Confirmation each regression test fails without the fix
3. Full test suite results post-merge
4. Updated `docs/AUDIT_2026-05-21.md` with C1-C4 marked as resolved
   and linked to the fix commits

Do not auto-start Phase 3B (Quality Gates Q1). Wait for explicit
go-ahead. I will triage based on what surfaces during Phase 3A.

## Proceed now

Start Phase 3.0 (plugin integration audit). Then dispatch the four
C1-C4 lanes in parallel via worktrees.
