# Claude Code Sprint Prompt — Track 0: Multi-Agent Harness

## Mission

Before any feature work begins, set up the `.claude/` directory so every subsequent track runs inside a deterministic, evaluator-gated, worktree-isolated multi-agent harness. This is Anthropic's own pattern stack: orchestrator-worker, evaluator-generator, hooks as gates, skills for repeatable workflows, model stacking.

This prompt runs **once, on Day 0**, in the main `ai-runtime-monitor` repo. After this lands, every track prompt becomes shorter because the harness does the heavy lifting.

## Branch

```
git checkout -b infra/multi-agent-harness
```

## Files to Create

```
ai-runtime-monitor/
├── AGENTS.md                              # multi-agent project brain
├── CLAUDE.md                              # single-session quick reference
├── .claude/
│   ├── settings.json                      # hooks + permissions
│   ├── agents/
│   │   ├── orchestrator.md
│   │   ├── code-reviewer.md
│   │   ├── security-reviewer.md
│   │   ├── test-writer.md
│   │   ├── doc-writer.md
│   │   ├── file-explorer.md
│   │   ├── tauri-rust-engineer.md
│   │   ├── extension-scanner-specialist.md
│   │   ├── threat-intel-scout.md
│   │   ├── brand-copywriter.md
│   │   └── design-system-curator.md
│   ├── skills/
│   │   ├── tdd-loop/SKILL.md
│   │   ├── security-review/SKILL.md
│   │   ├── brand-voice-check/SKILL.md
│   │   ├── release-tag/SKILL.md
│   │   └── worktree-dispatch/SKILL.md
│   ├── rubrics/
│   │   ├── lane-A-tauri.md
│   │   ├── lane-B-scanner.md
│   │   ├── lane-C-site.md
│   │   └── lane-D-ui.md
│   ├── hooks/
│   │   ├── pre-tool-use.sh
│   │   ├── post-tool-use.sh
│   │   ├── stop.sh
│   │   ├── session-start.sh
│   │   └── user-prompt-submit.sh
│   └── README.md                          # how the harness works
└── docs/
    └── SPRINT_ONE_WEEK.md                 # sprint state, owned by orchestrator
```

## AGENTS.md (root)

```markdown
# AI Runtime Monitor — Multi-Agent Project Brain

This file is read by the lead orchestrator on every session start.
Sub-agents pull only the slices they need.

## Project North Star

Endpoint security for the AI developer. Real-time visibility into the
network traffic, file access, package installs, and editor extensions
of every AI coding tool running on a developer's laptop.

Free open-source core. Pro tier at $29/dev/mo. Enterprise tier with
fleet management. Apple-grade UX, signed and notarized.

## Current Sprint

See `docs/SPRINT_ONE_WEEK.md` for live sprint state. The orchestrator
updates that file at session end; subagents read it on session start.

Four lanes run in parallel worktrees:
- Lane A: Tauri desktop shell           (.worktrees/lane-A)
- Lane B: Editor extension scanner      (.worktrees/lane-B)
- Lane C: Brand site (separate repo)    (../airuntimemonitor-site)
- Lane D: Dashboard UI polish           (.worktrees/lane-D)

## Lane Dispatch Rules

The orchestrator never writes lane code directly. It dispatches:

| Lane | Specialist subagent              | Reviewer subagent      |
|------|----------------------------------|------------------------|
| A    | tauri-rust-engineer              | security-reviewer      |
| B    | extension-scanner-specialist     | security-reviewer      |
| C    | brand-copywriter                 | code-reviewer          |
| D    | design-system-curator            | code-reviewer          |

Every lane completion goes through a grader subagent against the
lane's rubric (`.claude/rubrics/lane-X-*.md`) in a fresh context
window before the orchestrator accepts the work.

## Worktree Discipline

Specialist subagents declare `isolation: worktree` in their YAML
frontmatter. The harness creates a temporary worktree on the lane's
branch. No two specialists touch the same files at the same time.

Subagents commit frequently inside their worktree. The lead merges
to the lane branch after the grader signs off. Lanes merge to `main`
only at integration time (Day 5).

## Model Stacking

| Role                  | Model         | Why                                    |
|-----------------------|---------------|----------------------------------------|
| Lead orchestrator     | claude-opus-4-7 | Routing, judgment, integration calls |
| Lane specialists      | claude-sonnet-4-6 | Implementation                     |
| Test writers          | claude-sonnet-4-6 | Test quality matters               |
| Grader/reviewer       | claude-sonnet-4-6 | Adversarial review                 |
| File explorers, docs  | claude-haiku-4-5  | Cheap, fast, read-only             |

Reserve Opus for the orchestrator and final-gate judgment only.

## Non-Negotiables (enforced by hooks)

1. Every change ships with tests. PostToolUse hook runs pytest on
   any `.py` edit in a `claude_monitoring/` directory.
2. No `rm -rf`, no `git push --force`, no `chmod 777`, no edits to
   `.env*` or `secrets/`. PreToolUse hook blocks.
3. Stop hook runs the full test suite. The session does not end
   until tests pass.
4. Every PR runs through the lane's grader subagent before merge.
   No grader sign-off, no merge.

## Communication Protocol

Subagents communicate via:
- `docs/SPRINT_ONE_WEEK.md` for sprint state
- `docs/lane-*/HANDOFF.md` for lane-internal handoffs
- Git commit messages for permanent record
- The lead orchestrator's session for cross-lane coordination

Never embed coordination in code comments. Code comments explain the
code, not the project.

## Reference Reading (read once, then operate)

- https://www.anthropic.com/research/building-effective-agents
- https://www.anthropic.com/engineering/harness-design-long-running-apps
- https://docs.claude.com/en/docs/claude-code/sub-agents
- https://docs.claude.com/en/docs/claude-code/hooks
- https://docs.claude.com/en/docs/claude-code/skills
```

## CLAUDE.md (root, for single-session work)

```markdown
# AI Runtime Monitor — Quick Reference

For multi-agent / sprint work, read AGENTS.md first.
This file is the cheat sheet for single-session edits.

## Stack
- Backend: Python 3.12, FastAPI, mitmproxy, SQLCipher
- Desktop shell: Tauri v2, Rust, React 19, Tailwind v4
- Dashboard: React 19, Vite, TanStack Table, shadcn/ui
- Tests: pytest, vitest, Playwright

## Critical Paths
- `claude_monitoring/monitor.py` — daemon entry point
- `claude_monitoring/dashboard/` — FastAPI + React dashboard
- `desktop/src-tauri/` — Tauri Rust shell
- `claude_monitoring/extension_scanner/` — Track B subsystem

## Style
- Python: type hints required, ruff + black formatted
- Rust: cargo fmt + clippy clean
- TypeScript: strict mode, no `any`, ESLint clean
- Commits: conventional commits style, present tense, no emoji
- Docs: active voice, no em-dashes, no emoji, no exclamation marks

## Common Commands
- `make test` runs pytest + vitest
- `make lint` runs ruff + clippy + eslint
- `make build` builds dashboard + Tauri
- `make dev` runs daemon + dashboard hot-reload

## Before Every Commit
1. `make test` passes (1015+ tests, no skips, no xfails)
2. `make lint` clean
3. `git diff --stat` shows only intended files
4. Commit message follows conventional commits
```

## Subagent Definitions

Each subagent is a markdown file with YAML frontmatter. Format:

### `.claude/agents/orchestrator.md`

```markdown
---
name: orchestrator
description: Lead orchestrator. Reads AGENTS.md, decomposes work into lane
  tasks, dispatches specialist subagents, integrates results. Never writes
  lane code directly. Uses Opus 4.7.
model: claude-opus-4-7
tools: [Read, Glob, Grep, Task, TodoWrite, Bash]
---

You are the lead orchestrator for the AI Runtime Monitor sprint.

Your job:
1. Read AGENTS.md and docs/SPRINT_ONE_WEEK.md at session start.
2. Identify the next ready-to-start task across the four lanes.
3. Dispatch the appropriate specialist subagent via Task tool with a
   focused, complete brief.
4. When the specialist returns, dispatch a grader subagent with the
   lane's rubric and the artifact.
5. If the grader rejects, dispatch back to the specialist with
   targeted feedback. Max 3 iterations.
6. If the grader accepts, merge the worktree to the lane branch and
   update SPRINT_ONE_WEEK.md.

Never write production code yourself. Your job is routing, not
implementation. If you find yourself reaching for the Edit tool,
stop and dispatch instead.

Update SPRINT_ONE_WEEK.md at every state transition. Format:

```
## Lane B: Extension Scanner
- [x] Inventory module          (dispatched: extension-scanner-specialist)
                                (graded: passed, 87% coverage)
                                (merged: lane-B at 14:32)
- [>] Risk scorer                (dispatched: extension-scanner-specialist)
                                (in worktree .worktrees/lane-B-scorer)
- [ ] Threat intel client
- [ ] Scanner service
```
```

### `.claude/agents/code-reviewer.md`

```markdown
---
name: code-reviewer
description: Adversarial code reviewer. Reads only the diff and rubric in
  a fresh context window. Cannot edit files. Produces a pass/fail verdict
  with specific feedback. Used as the grader in evaluator-generator loops.
model: claude-sonnet-4-6
tools: [Read, Glob, Grep]
isolation: worktree
---

You are an adversarial code reviewer.

Your context is intentionally clean. You have NOT seen how the code was
produced or the reasoning behind it. You see only:
- The diff or changed files
- The lane's rubric in `.claude/rubrics/lane-X-*.md`
- Adjacent code for context (read-only)

Your output is a strict pass/fail verdict against each rubric criterion.

Format:

```
## Verdict: PASS | FAIL

## Per-criterion scores

### Criterion 1: <verbatim from rubric>
Status: PASS | FAIL
Evidence: <file:line references>
Feedback: <specific, actionable if FAIL>

### Criterion 2: ...
```

Be skeptical. If a test exists, did it actually exercise the code path?
If coverage is reported, did you verify it? If a claim is made in a
commit message, did the code deliver it?

You cannot fix anything. You can only report.
```

### `.claude/agents/security-reviewer.md`

```markdown
---
name: security-reviewer
description: Adversarial security reviewer for security-sensitive changes.
  Read-only. Looks for auth bypass, injection, secret exposure, unsafe
  defaults, cert handling errors.
model: claude-sonnet-4-6
tools: [Read, Glob, Grep, Bash]
isolation: worktree
---

You review code from an attacker's perspective.

Always check:
1. Authentication: bypass on any endpoint, timing attacks, session fixation
2. Authorization: permissions checked at every layer, no IDOR
3. Input validation: every external input sanitized, no injection sinks
4. Secrets: no hardcoded keys, no secrets in logs, no .env in git
5. Crypto: constant-time comparison for tokens, modern algorithms only
6. Certs: pinning where applicable, proper trust chain, no MITM gaps
7. Subprocess: no shell=True, no unsanitized args to bash
8. File I/O: no path traversal, no unsafe pickling, no zip slip
9. Network: no requests to untrusted hosts, TLS verify always on
10. Logging: PII redacted, secrets never logged

For this product specifically:
- Custom CA must have Name Constraints
- mitmproxy config must not log request bodies by default
- SQLCipher key derivation must use proper KDF iterations
- Dashboard auth must use constant-time comparison
- LaunchAgent plist must not run as root

Report findings as:

```
## SEVERITY: critical | high | medium | low
File: path/to/file.py:42
Issue: <one-line summary>
Evidence: <code excerpt>
Impact: <what an attacker could do>
Fix: <specific remediation>
```

Cannot edit. Reports only.
```

### `.claude/agents/extension-scanner-specialist.md`

```markdown
---
name: extension-scanner-specialist
description: Implements the editor extension scanner subsystem for Track B.
  Knows the layout of VS Code, Cursor, JetBrains, Xcode, Sublime, Neovim,
  Zed, Claude Code extension directories. Implements inventory, risk
  scoring, threat intel pulls, scanner service.
model: claude-sonnet-4-6
tools: [Read, Write, Edit, Glob, Grep, Bash, Task]
isolation: worktree
---

You implement the extension scanner under `claude_monitoring/extension_scanner/`.

Read these before writing any code:
- AGENTS.md
- docs/SPRINT_ONE_WEEK.md (your tasks under Lane B)
- claude_monitoring/monitor.py (daemon entry point you will register with)
- claude_monitoring/alerts/dispatcher.py (existing alert dispatcher contract)

Your work follows the TDD loop skill at `.claude/skills/tdd-loop/SKILL.md`.

When you finish a unit of work:
1. Run `pytest tests/extension_scanner/ -v --cov=claude_monitoring.extension_scanner`
2. Verify ≥85% coverage
3. Run `make lint` clean
4. Commit with conventional commit message
5. Return control to the orchestrator with a one-paragraph summary

Do not merge to the lane branch. The orchestrator merges after grader sign-off.
```

### `.claude/agents/tauri-rust-engineer.md`

```markdown
---
name: tauri-rust-engineer
description: Tauri v2 specialist. Builds the desktop shell under
  desktop/src-tauri/. Knows Apple notarization, code signing, Sparkle-style
  updaters, menu bar tray patterns.
model: claude-sonnet-4-6
tools: [Read, Write, Edit, Glob, Grep, Bash, Task]
isolation: worktree
---

You implement the Tauri desktop shell under `desktop/`.

Stack: Tauri v2, Rust, React 19, Tailwind v4, shadcn/ui.

Read before writing any code:
- AGENTS.md
- docs/SPRINT_ONE_WEEK.md (your tasks under Lane A)
- The four track prompts in /home/claude/prompts/ if available

Hard requirements:
- DMG must be signed with Developer ID Application certificate
- Notarization passes spctl --assess --type install
- Memory footprint < 60 MB at idle
- Tray icon updates within 5 seconds of daemon state change
- Setup wizard completes end-to-end without errors

Use cargo clippy --all-targets --all-features -- -D warnings.
Use cargo fmt --check.
```

### Remaining agents (abbreviated, follow the same pattern)

Create the following with appropriate frontmatter, tool scopes, and
instructions:

- `test-writer.md` (Sonnet, can Read/Write/Edit/Bash, no isolation)
- `doc-writer.md` (Haiku, can Read/Write/Edit, scoped to docs/)
- `file-explorer.md` (Haiku, read-only Read/Glob/Grep)
- `threat-intel-scout.md` (Sonnet, can Bash for curl/jq, scoped to threat_intel.py)
- `brand-copywriter.md` (Sonnet, scoped to airuntimemonitor-site/, must follow brand voice rules)
- `design-system-curator.md` (Sonnet, scoped to dashboard/app/components/ + styles/)

## Skills

### `.claude/skills/tdd-loop/SKILL.md`

```markdown
---
name: tdd-loop
description: The red-green-refactor TDD loop. Use this whenever
  implementing a new function or fixing a bug. Prevents the "trust me,
  it works" failure mode.
---

# TDD Loop

## When to use
Any code change that adds behavior or fixes a bug.

## Procedure

1. **RED**: Write a failing test that exercises the desired behavior.
   - Test file lives in `tests/` mirroring the module path.
   - Use real fixtures from `tests/fixtures/` when possible.
   - Run the test, confirm it fails for the right reason.

2. **GREEN**: Write the minimal implementation that passes the test.
   - No premature optimization.
   - No additional features.
   - Run the test, confirm it passes.

3. **REFACTOR**: Improve the code without changing behavior.
   - Extract helpers if a function exceeds 30 lines.
   - Name variables for what they mean, not what they are.
   - Run the full test suite, confirm nothing broke.

4. **COMMIT**: One conventional commit per RED-GREEN-REFACTOR cycle.

## Anti-patterns to avoid

- Writing the implementation first and the test after
- Skipping tests because "the code is obviously correct"
- Mocking everything (mocks are for I/O boundaries, not logic)
- Writing tests that just exercise getters/setters
- Marking tests xfail or skip without explaining in a comment

## Hard rule

If the test suite has any failing or skipped tests at the end of your
session, you do not commit. You either fix the test, or you revert
your changes and ask the orchestrator for help.
```

### `.claude/skills/security-review/SKILL.md`

```markdown
---
name: security-review
description: How to invoke the security-reviewer subagent on a diff.
---

# Security Review Skill

After implementing any code that:
- Handles authentication or authorization
- Touches certificates, TLS, or crypto
- Spawns subprocesses
- Reads user-supplied input
- Writes to filesystem paths constructed from input

...you must invoke the security-reviewer subagent via the Task tool
before requesting orchestrator merge:

```
Task(
  subagent_type="security-reviewer",
  description="Review diff for <feature>",
  prompt=f"""
  Review the diff at HEAD against the security checklist.
  Focus areas: {focus_areas}
  Fixture inputs that exercised this code: {fixture_paths}
  """
)
```

If the reviewer returns any critical or high findings, fix them and
re-invoke. Do not merge with critical or high open.
```

### `.claude/skills/brand-voice-check/SKILL.md`

```markdown
---
name: brand-voice-check
description: Brand voice rules for all user-facing text on the website,
  in product UI, and in marketing copy.
---

# Brand Voice Rules

## Always

- Active voice. "We detect malicious extensions" not "Malicious extensions are detected".
- Short declarative sentences. Aim for 12 to 18 words per sentence.
- Concrete nouns. "Cursor installed three extensions" not "the editor ecosystem grew".
- Specific numbers where they exist.

## Never

- Em-dashes ( — ). Use periods or commas.
- Emojis in production copy. Internal docs are fine.
- Exclamation marks.
- The phrases "leverage", "synergy", "best-in-class", "world-class",
  "cutting-edge", "next-generation", "revolutionary", "game-changing".
- Salesy hyperbole. The product speaks for itself.
- Long lists of feature claims. Three claims max in any paragraph.

## Examples

| Bad                                            | Good                                                |
|------------------------------------------------|-----------------------------------------------------|
| "We leverage best-in-class AI to detect..."    | "We catch malicious npm packages in real time."     |
| "Next-gen endpoint protection for AI devs!"    | "Endpoint security for the AI developer."          |
| "Get unparalleled visibility — like never before" | "See what your AI tools actually do on your machine." |
```

## Hooks (`.claude/settings.json`)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": ".claude/hooks/pre-tool-use.sh",
        "block_on_failure": true
      },
      {
        "matcher": "Edit|Write",
        "command": ".claude/hooks/pre-edit.sh",
        "block_on_failure": true
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "command": ".claude/hooks/post-edit.sh",
        "block_on_failure": false
      }
    ],
    "Stop": [
      {
        "command": ".claude/hooks/stop.sh",
        "block_on_failure": true
      }
    ],
    "SessionStart": [
      {
        "command": ".claude/hooks/session-start.sh"
      }
    ],
    "UserPromptSubmit": [
      {
        "command": ".claude/hooks/user-prompt-submit.sh"
      }
    ]
  },
  "permissions": {
    "deny": [
      "Bash:rm -rf /*",
      "Bash:rm -rf ~/*",
      "Bash:git push --force*",
      "Bash:chmod 777*",
      "Bash:curl * | bash",
      "Bash:curl * | sh"
    ],
    "ask": [
      "Bash:git push*",
      "Bash:cargo publish*",
      "Bash:npm publish*",
      "Bash:pip publish*"
    ]
  }
}
```

### `.claude/hooks/pre-tool-use.sh`

```bash
#!/usr/bin/env bash
# Reject dangerous bash commands beyond what permissions.deny catches
set -e
command="$CLAUDE_HOOK_BASH_COMMAND"

# Block edits to sensitive files
if echo "$command" | grep -E "\.env|secrets/|credentials" >/dev/null; then
  echo "BLOCKED: Will not touch secret files" >&2
  exit 1
fi

# Block force-pushes regardless of branch
if echo "$command" | grep -E "git push.*-f|git push.*--force" >/dev/null; then
  echo "BLOCKED: Force push not allowed" >&2
  exit 1
fi

exit 0
```

### `.claude/hooks/post-edit.sh`

```bash
#!/usr/bin/env bash
# Auto-format and lint on every edit
set -e
file="$CLAUDE_HOOK_EDITED_FILE"

case "$file" in
  *.py)    ruff format "$file" && ruff check "$file" --fix ;;
  *.rs)    rustfmt "$file" ;;
  *.ts|*.tsx) prettier --write "$file" && eslint --fix "$file" ;;
esac
```

### `.claude/hooks/stop.sh`

```bash
#!/usr/bin/env bash
# Refuse to release control until tests pass
set -e
echo "Running test suite before session end..."

if ! make test >/dev/null 2>&1; then
  echo "BLOCKED: Tests failing. Fix before ending session." >&2
  make test 2>&1 | tail -20
  exit 1
fi

if ! make lint >/dev/null 2>&1; then
  echo "BLOCKED: Lint failing. Fix before ending session." >&2
  exit 1
fi

echo "All checks passed. Session can end."
exit 0
```

### `.claude/hooks/session-start.sh`

```bash
#!/usr/bin/env bash
echo "================================"
echo "AI Runtime Monitor Sprint"
echo "================================"
echo ""
echo "Active worktrees:"
git worktree list
echo ""
echo "Last 3 commits:"
git log --oneline -3
echo ""
echo "Sprint state:"
head -30 docs/SPRINT_ONE_WEEK.md 2>/dev/null || echo "(no sprint doc yet)"
```

## Rubrics

### `.claude/rubrics/lane-B-scanner.md`

```markdown
# Lane B: Extension Scanner Rubric

The grader evaluates the lane's PR against each criterion in a fresh
context window. Pass = all PASS. Any FAIL = revise.

## Criterion 1: Inventory coverage
PASS iff `scan_all_editors()` returns extensions from at least 4 editors
on a machine with VS Code, Cursor, JetBrains, and Xcode installed.

## Criterion 2: Risk rules implemented
PASS iff all 9 risk rules (R001 through R009) exist as separately testable
functions with at least one positive and one negative test each.

## Criterion 3: Test coverage
PASS iff `pytest --cov` reports ≥85% line coverage on
`claude_monitoring/extension_scanner/`.

## Criterion 4: Real-world fixture detection
PASS iff the GlassWorm fixture is flagged with severity=critical and
the legit Prettier fixture has zero findings.

## Criterion 5: API contract
PASS iff `/api/extensions` and `/api/extensions/{id}` return responses
matching the OpenAPI schema, and `/api/extensions/scan` triggers a
synchronous rescan within 30 seconds.

## Criterion 6: No regression
PASS iff the full repo test suite passes with zero new failures.

## Criterion 7: Security review
PASS iff the security-reviewer subagent reports zero critical or
high findings on the diff.

## Criterion 8: Documentation
PASS iff `claude_monitoring/extension_scanner/README.md` exists and
explains: what it scans, how to add a new editor, how risk scores
combine, how threat intel is refreshed.
```

(Create equivalent rubrics for lanes A, C, D following this format.)

## SPRINT_ONE_WEEK.md (initial state)

```markdown
# AI Runtime Monitor — One-Week Sprint

Started: <date>
Target ship: <date + 7>
Lead: orchestrator (Claude Code main session)

## Lane A: Tauri Desktop Shell (.worktrees/lane-A)
Status: NOT STARTED
Specialist: tauri-rust-engineer
Rubric: .claude/rubrics/lane-A-tauri.md
Tasks:
- [ ] Tauri v2 scaffold
- [ ] Menu bar tray icon with state machine
- [ ] LaunchAgent supervisor
- [ ] Setup wizard inside Tauri window
- [ ] Auto-update with tauri-plugin-updater
- [ ] DMG packaging with create-dmg
- [ ] Code sign + notarize CI workflow

## Lane B: Extension Scanner (.worktrees/lane-B)
Status: NOT STARTED
Specialist: extension-scanner-specialist
Rubric: .claude/rubrics/lane-B-scanner.md
Tasks:
- [ ] Data models + Editor enum
- [ ] Inventory for all 9 editor types
- [ ] 9 risk rules (R001-R009)
- [ ] Threat intel client (GHSA + OpenVSX + Snyk)
- [ ] Scanner service with FS watch
- [ ] API routes /api/extensions/*
- [ ] Tests at 85% coverage

## Lane C: Brand Site (../airuntimemonitor-site)
Status: NOT STARTED
Specialist: brand-copywriter
Rubric: .claude/rubrics/lane-C-site.md
Tasks:
- [ ] Domain registered, Vercel project linked
- [ ] Next.js 15 scaffold with brand tokens
- [ ] Hero, FeatureGrid, PricingTable components
- [ ] Five pages (home, features, pricing, download, blog)
- [ ] Lighthouse ≥95 all routes
- [ ] OG cards rendered

## Lane D: Dashboard UI Polish (.worktrees/lane-D)
Status: BLOCKED (needs Lane B's /api/extensions)
Specialist: design-system-curator
Rubric: .claude/rubrics/lane-D-ui.md
Tasks: (will populate after Lane B unblocks)

## Integration Day (Day 5)
- [ ] Merge lanes A, B, D to main
- [ ] Smoke test: install DMG, run end-to-end
- [ ] Sign + notarize release build
- [ ] Tag v0.2.0, push to GitHub Releases
- [ ] latest.json published for auto-updater
- [ ] Deploy brand site to production domain

## Launch Day (Day 6-7)
- [ ] HN "Show HN" post drafted and ready
- [ ] Product Hunt scheduled
- [ ] LinkedIn launch post drafted
- [ ] r/netsec and r/cybersecurity cross-posts
- [ ] Email to 12 design partners
```

## Verification Checklist (for this Track 0 prompt)

```bash
# 1. Directory structure exists
find .claude -type f | wc -l    # should be ≥ 25

# 2. AGENTS.md and CLAUDE.md at root
test -f AGENTS.md && test -f CLAUDE.md && echo OK

# 3. Hooks are executable
test -x .claude/hooks/stop.sh && echo OK

# 4. Settings.json validates
python -m json.tool .claude/settings.json >/dev/null && echo OK

# 5. Subagent frontmatter parses
for f in .claude/agents/*.md; do
  python -c "import frontmatter; frontmatter.load('$f')" || echo "FAIL: $f"
done

# 6. Lead orchestrator can list subagents
claude /agents 2>&1 | grep -c "extension-scanner-specialist"
# expect: 1

# 7. Hook fires on test bash
echo "rm -rf /" | .claude/hooks/pre-tool-use.sh
# expect: BLOCKED message and exit code 1

# 8. Sprint doc exists
test -f docs/SPRINT_ONE_WEEK.md && echo OK
```

## First Commit

```
chore(harness): set up multi-agent harness for one-week sprint

- .claude/agents/ with 11 specialist subagents
- .claude/skills/ with 5 reusable workflows
- .claude/rubrics/ with 4 lane rubrics
- .claude/hooks/ with 5 deterministic gates
- AGENTS.md as multi-agent project brain
- CLAUDE.md as single-session quick reference
- docs/SPRINT_ONE_WEEK.md with lane breakdown

Based on Anthropic's published patterns: orchestrator-worker,
evaluator-generator (via grader subagents), worktree isolation,
hooks as gates, model stacking (Haiku/Sonnet/Opus by role).

Refs:
- https://www.anthropic.com/research/building-effective-agents
- https://www.anthropic.com/engineering/harness-design-long-running-apps
```
