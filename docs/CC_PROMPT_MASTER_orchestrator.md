# Claude Code Master Orchestrator Prompt

You are the lead orchestrator for the AI Runtime Monitor one-week sprint.
All sprint planning documents are in `docs/`. The actual codebase is at
the repo root. Your job is to drive the sprint to completion, but only
after reconciling every prompt against repo reality.

## Behavior contract (do not deviate)

These rules override anything written in the prior prompts.

1. NEVER execute a phase whose assumptions you have not verified against
   the actual repo. The code is the source of truth, not the prompts.
2. When a prompt's assumption disagrees with the code, STOP and surface
   the disagreement as a question to the user. Do not patch the prompt
   yourself. Do not invent a workaround.
3. The quality-gates prompt was just rewritten into Q1/Q2/Q3 sprints by
   the prior Claude Code session because half its assumptions were
   wrong. Apply the same scoping discipline to every other prompt you
   read in `docs/`.
4. Recoveries from discrepancies go into `docs/RECONCILIATION_LOG.md`,
   not back into the original prompt files. Originals stay as audit
   trail. The log is the canonical record of what actually got built.
5. If you find yourself uncertain about a design choice, STOP and ask.
   Never guess on architecture.
6. If a test you wrote passes immediately without ever failing, delete
   it and write one that actually exercises the code path.
7. For any file longer than 200 lines, prefer the code-intelligence MCP
   server (codebase-memory-mcp, already connected) over plain Read.
   Grep and Glob miss indirect references and inheritance. Use
   symbol-aware lookups.
8. Every change goes through a branch. No direct commits to main. The
   branching strategy below is non-negotiable.

## Phase -1: Tooling foundation (run BEFORE Phase 0)

This phase sets up two foundations the rest of the sprint depends on.
Skip this and Phase 0 reads will be incomplete and branching will drift.

### A. Use the already-connected code-intelligence MCPs

The repo is large: 1000+ tests, `monitor.py` is 4800 lines. Plain Grep
and Glob cannot navigate it safely. Symbol-aware lookups are required.

The user already has these connected in Claude Code (verify with `/mcp`):

```
codebase-memory-mcp        connected. Use for code understanding.
security-guidance          plugin. Use for security review questions.
superpowers                plugin. Use for spec-driven workflows.
```

Do NOT install serena, sourcegraph, or any other code-intel MCP. The
existing stack is already wired and the user does not want duplicate
tooling.

First action of Phase -1: discover the actual tools exposed by
codebase-memory-mcp and the two plugins by running:

```
/mcp
```

Then list each connected MCP server's tools and read its description
inline before using it. Document the actual tool names and one-line
purposes in `docs/TOOLING.md` so subsequent phases reference correct
identifiers.

Discipline for the rest of the sprint:

| Task                                          | Approach                              |
|-----------------------------------------------|---------------------------------------|
| Read a file under 200 lines whole             | plain Read                            |
| Read a file over 200 lines                    | codebase-memory-mcp first, drill in   |
| "What does function X do?"                    | codebase-memory-mcp symbol lookup     |
| "Who calls function X?"                       | codebase-memory-mcp referencing query |
| "Find this pattern across the codebase"       | codebase-memory-mcp semantic search   |
| Security review of changed code               | security-guidance plugin              |
| Spec-driven feature work (TDD loop)           | superpowers plugin                    |
| Repo-level operations (issues, PRs, releases) | github CLI (`gh`) until GitHub MCP is added |
| Quick text grep across small files            | plain Grep                            |

If a tool fails or returns surprising results, prefer falling back to
plain Read for the affected files rather than fighting the tool.
Document the failure in `docs/TOOLING.md` so the user can decide
whether to file an issue against the MCP server.

GitHub MCP is optional. If the user wants it later, the install is a
single block in `.claude/mcp.json`. For now, `gh` CLI from bash is
sufficient for the sprint operations needed.


### B. Branching strategy

No commits to main. Every change goes through a branch with a PR.
Branch naming and lifecycle below are enforced by the PR template and
(in Q3 of quality gates) by branch protection.

#### Naming

```
main                  protected. signed commits enforced post-Q3. linear history.
audit/*               adversarial audits (audit/adversarial-self-audit)
security/*            security fixes (security/audit-criticals, security/c1-bcrypt)
fix/*                 non-security bug fixes (fix/openclaw-proxy-inheritance)
feature/*             new features outside the lane sprint
infra/*               tooling, CI, build harness (infra/quality-gates-q1)
lane-A | lane-B |     four-lane sprint, used as worktree branches.
lane-C | lane-D       cut from main, merge via PR after grader sign-off.
release/*             release prep (release/v0.2.0)
hotfix/*              emergency post-release fixes
```

#### Lifecycle

- Cut from main. Always rebase, never merge from main back into a
  feature branch.
- Maximum 5 calendar days before rebasing onto latest main.
- Squash-merge to main by default. Rebase-merge only if the branch
  has multiple genuinely separable commits worth preserving.
- Delete the branch immediately after merge.
- Long-lived branches are forbidden except `main`.

#### Commit conventions

- Conventional commits: `<type>(<scope>): <subject>`
- Types: feat, fix, security, perf, refactor, test, docs, chore, ci, build
- For audit criticals, use the audit ID as scope:
  `security(C1): bcrypt.checkpw constant-time comparison`
- No `Co-Authored-By: Claude` trailers. The 3 existing trailers
  from the audit must be addressed per the user's answer to Q7.
- Subject under 72 chars. Body wraps at 80.

#### PR template

Create `.github/pull_request_template.md`:

```markdown
## Summary
<one paragraph: what changed and why>

## Audit / Issue links
<links to docs/AUDIT_2026-05-21.md sections, GitHub issues>

## How to verify
<commands a reviewer can run locally>

## Test plan
<tests added, coverage delta, expected mutation score>

## Risk
<what could break, blast radius>

## Checklist
- [ ] make ci-local passes locally
- [ ] New code has tests
- [ ] Tests fail without the fix (proves they exercise the code)
- [ ] No Co-Authored-By: Claude trailer in commits
- [ ] Conventional commit messages
- [ ] Updated docs/RECONCILIATION_LOG.md if any assumption shifted
- [ ] Grader subagent verdict attached (for sprint-lane PRs)
```

#### Worktree pattern

The four-lane sprint uses git worktrees for parallel work without
merge conflicts:

```
ai-runtime-monitor/                  main worktree. lead orchestrator.
.worktrees/lane-A/  → lane-A branch  Tauri specialist subagent.
.worktrees/lane-B/  → lane-B branch  Extension scanner specialist.
.worktrees/lane-D/  → lane-D branch  UI polish specialist.
../airuntimemonitor-site/            separate repo. brand site (Lane C).
```

Create worktrees on Day 0 of Phase 3E (lane execution), not now.
Commands when the time comes:

```bash
git worktree add .worktrees/lane-A -b lane-A
git worktree add .worktrees/lane-B -b lane-B
git worktree add .worktrees/lane-D -b lane-D
```

#### Exit gate for Phase -1

- `/mcp` shows codebase-memory-mcp connected. security-guidance and
  superpowers plugins enabled.
- `docs/TOOLING.md` exists with the actual tool names exposed by each
  connected MCP and plugin, and a one-line note for each on when to use it.
- `.github/pull_request_template.md` exists and is committed via a
  trivial infra branch (e.g., `infra/pr-template`) merged to main via
  a real PR (this is the dogfood test of the branching policy itself).
- A `docs/BRANCHING.md` file mirrors this section so contributors
  outside this prompt can find it.

## Phase 0: Read everything

Read these files in this order. Do not skim. Each one informs the next.

```
docs/AUDIT_2026-05-21.md
docs/CC_PROMPT_AUDIT_adversarial_self_audit.md
docs/CC_PROMPT_QUALITY_GATES.md
docs/CC_PROMPT_00_multi_agent_harness.md
docs/CC_PROMPT_01_extension_scanner.md
docs/CC_PROMPT_02_brand_site.md
docs/CC_PROMPT_03_tauri_shell.md
docs/CC_PROMPT_04_ui_polish.md
docs/EXECUTION_PLAYBOOK_one_week.md
```

Then read the actual repo state (use codebase-memory-mcp for big files):

```
tree -L 3 -I '__pycache__|node_modules|.git|.venv|*.egg-info'
cat pyproject.toml
cat README.md
ls -la .github/workflows/ 2>/dev/null
ls -la .claude/ 2>/dev/null
find src -maxdepth 3 -type f -name '*.py' | head -30
find tests -maxdepth 3 -type f -name '*.py' | head -30
wc -l src/claude_monitoring/monitor.py 2>/dev/null || find src -name 'monitor.py' -exec wc -l {} \;
git log --oneline -20
git status
git branch -a
```

For `monitor.py` (4800 lines per the prior session), do NOT cat it
or read it whole. Use codebase-memory-mcp to get a symbol outline
first, then drill into specific symbols only as needed. The exact
tool names depend on the codebase-memory-mcp version; discover them
via `/mcp` at the start of Phase -1 and record them in
`docs/TOOLING.md`.

Do not start Phase 1 until you have actually run these commands and
read the outputs.

## Phase 1: Reconciliation report

Write `docs/RECONCILIATION_LOG.md` with this exact structure:

```markdown
# Reconciliation Log — <today's date>

## How to read this
For each prior prompt, this log captures every assumption that
disagrees with the repo, and the proposed path. The original prompts
are preserved as the audit trail. This log is the canonical record
of what actually gets built.

## CC_PROMPT_00_multi_agent_harness
| Assumption | Reality | Proposed adjustment |
|---|---|---|
| ... | ... | ... |

## CC_PROMPT_01_extension_scanner
| Assumption | Reality | Proposed adjustment |
|---|---|---|
| ... | ... | ... |

## CC_PROMPT_02_brand_site
(separate repo — note whether it exists yet)

## CC_PROMPT_03_tauri_shell
(greenfield — note whether the prereqs exist)

## CC_PROMPT_04_ui_polish
(this is the big one — original assumed React dashboard,
 reality is dashboard.html)

## CC_PROMPT_QUALITY_GATES
Already triaged into Q1/Q2/Q3 by the prior session.
See the Q1/Q2/Q3 cut at the bottom of this document.

## Audit critical findings (C1-C4) status
| ID | Title                       | Est fix | Tests needed              |
|----|-----------------------------|---------|---------------------------|
| C1 | control-plane bcrypt theatre| 4h      | regression: timing + bypass |
| C2 | dashboard.html quote-XSS    | 3h      | XSS payload fixture       |
| C3 | sync.py _sanitize_string fail-open | 2h | malformed input tests   |
| C4 | osascript shell=True        | 1h      | injection attempt test    |

## Scope changes that need user approval
1. ...
2. ...

## Execution order proposal
Phase 3A: critical fixes C1-C4
Phase 3B: Quality Gates Q1 cut
Phase 3C: Multi-agent harness (adjusted to reality)
Phase 3D: Quality Gates Q2
Phase 3E: Lane execution (per user's answers to Q1-Q8)
Phase 3F: Audit Highs batch fix
Phase 3G: Quality Gates Q3
Phase 3H: Launch
```

## Phase 2: Stop and ask

After the reconciliation report is written, STOP. Present the report
inline (the headings and table contents, not the whole file). Then ask
these eight questions exactly. Do not start any work until every
question has a clear answer.

Q1. Quality gates Q1/Q2/Q3 split as triaged by the prior session.
    Acceptable? Adjustments?

Q2. Lane D (dashboard UI). The original prompt assumed an existing
    React dashboard. Reality is a static dashboard.html. The work is
    now "migrate dashboard.html to React, then polish." Pick one:
    a. Keep Lane D in this sprint but extend by 3-4 days
    b. Split: Lane D1 (polish existing HTML) this sprint,
       Lane D2 (React migration) post-launch
    c. Defer Lane D entirely; ship with current dashboard.html

Q3. Lane A (Tauri shell). Greenfield. Confirm you still want Tauri
    versus shipping CLI plus Homebrew first and adding Tauri post-launch.

Q4. Lane B (extension scanner). Confirm `src/claude_monitoring/extension_scanner/`
    as the home. Confirm fit with the flat module layout (no api/,
    services/, etc.).

Q5. Lane C (brand site). Confirm the domain name and Vercel project.
    Confirm you want Lane C in parallel with Lane B from Day 1.

Q6. Criticals C1-C4. Single branch `security/audit-criticals` or four
    separate branches? Separate branches let CI validate each in
    isolation. Single branch ships faster.

Q7. Co-Authored-By: Claude trailers. The audit found 3 commits with
    these. Signed-commits gate (when it lands in Q3) will reject them.
    Pick one:
    a. Rewrite those 3 commits to remove the trailer (force-push)
    b. Allowlist Claude as a co-author signer
    c. Defer signed-commits gate to post-launch

Q8. Antfooding. Confirm you want to install your own latest build on
    your dev machine and use it during the sprint. Confirm the build
    is stable enough that this will not disrupt development.

Optional questions (ask only if relevant):
- Any C1-C4 fix that needs design discussion before coding
- Any audit High that should be promoted to Critical on second look
- Any lane reordering implied by the reconciliation

## Phase 3: Execute

Once Q1-Q8 are answered, execute these phases in order. Each phase has
an entry gate (must be true to start) and an exit gate (must be true
to declare done). Update `docs/SPRINT_ONE_WEEK.md` at every transition.

### Phase 3A — Critical security fixes (C1-C4)

Entry gate: Q6 answered.
Branch strategy: per Q6.
Procedure for each critical:
- Write the regression test first. Confirm it fails.
- Write the minimal fix. Confirm the test passes.
- Refactor for clarity. Confirm all tests still pass.
- Commit with conventional message referencing the audit:
  `fix(C1): bcrypt.checkpw constant-time comparison`
  Body includes: link to docs/AUDIT_2026-05-21.md#C1 and the
  before/after behavior.
Exit gate:
- 4 fix commits + 4 regression test commits exist
- `pytest tests/` runs green
- For each critical, git stash the fix, confirm test fails,
  unstash, confirm test passes (proves the test is not a tautology)

### Phase 3B — Quality Gates Sprint Q1

Entry gate: Phase 3A merged.
Build only what the prior session triaged as Q1-ready:
- Makefile scoping only what exists (no Rust, no Tauri, no Next.js)
- .pre-commit-config.yaml: hygiene + ruff + bandit (no mypy yet,
  no Rust/TS hooks, no shellcheck unless `brew install shellcheck`)
- detect-secrets baseline + pre-commit hook
- .github/workflows/ci-security.yml: pip-audit + bandit + secrets
- scripts/coverage_ratchet.py with baseline at current 72%
- scripts/check_functional_coverage.py adapted to src/ layout
  (default to --warn mode, --strict later)
- scripts/check_file_size.py and check_function_size.py with
  thresholds set above current monitor.py size so it ratchets down
- .github/workflows/ci-supply-chain.yml: SBOM via cyclonedx-py
- docs/QUALITY_GATES.md with branch protection plan (not applied yet)

Defer to Q2/Q3 (do NOT build now):
- import-linter (layers don't exist yet)
- mypy --strict (would produce thousands of errors on flat py39 code)
- Full ruff strict ruleset (stage in Q2)
- Mutation testing (needs higher coverage first)
- Rust/TS/Next.js workflows (no code exists)
- Signed commits (needs gitsign rollout first)

Exit gate:
- `pre-commit install --install-hooks` succeeds
- `pre-commit run --all-files` passes
- `make ci-fast` passes
- A test PR runs the new CI workflows green

### Phase 3C — Multi-agent harness (adjusted)

Entry gate: Phase 3B merged. Q1-Q5 answered.
Adapt CC_PROMPT_00_multi_agent_harness to reality:
- Drop subagent definitions for code that does not exist
- Update AGENTS.md project tree to reflect src/ layout
- Hooks delegate to Phase 3B make targets, do NOT invent checks
- Update SPRINT_ONE_WEEK.md based on Q1-Q5 answers
- Skills get a `## Gotchas` section each (Anthropic measured this
  improves accuracy)

Exit gate:
- `.claude/` installed with verified subagents, skills, rubrics, hooks
- A trivial `Task(subagent_type="code-reviewer", ...)` call succeeds
- Hook on Stop blocks session end when `make ci-fast` fails
  (verify with an intentional lint failure)

### Phase 3D — Quality Gates Sprint Q2

Entry gate: Phase 3C merged.
Work:
- Rewrite importlinter.cfg against actual modules. Start with one rule:
  `control-plane cannot import claude_monitoring internals`.
  Add more rules only as new layers are introduced.
- Add mypy in non-strict mode. Get to a clean baseline. Do not chase
  --strict yet.
- Expand ruff in 2-3 staged PRs, each adding 4-5 categories.
  Order: bugbear (B), then security (S), then simplifications (SIM).
- Add interrogate for docstring coverage, threshold 60% initially.

Exit gate:
- `lint-imports` passes
- `mypy` non-strict passes
- Expanded ruff passes
- `interrogate` at 60%+ on src/

### Phase 3E — Lane execution

Entry gate: Phases 3A-3D merged. Q2-Q5 answered.
Follow EXECUTION_PLAYBOOK_one_week.md with Q1-Q8 adjustments applied.

Critical sequencing:
- Lanes B and C in parallel first
- Lane A starts Day 2 only if Q3 confirmed Tauri
- Lane D per Q2 answer

Each lane runs in its own worktree. Each lane's specialist runs the
TDD loop. Each lane's PR runs the grader subagent against its rubric
in `.claude/rubrics/`.

Exit gate:
- Each in-scope lane's rubric passes
- Integration smoke test passes
- DMG signed and notarized (if Lane A in scope)
- Brand site deployed and Lighthouse Performance >= 95

### Phase 3F — Audit Highs batch fix

Entry gate: Phase 3E complete OR concurrent with Lane work that does
not touch the same modules.
Work: Triage the 22 audit High findings into three buckets:
- Single-line fixes: batch into one PR per category
- Real refactors: one PR each
- Deferred to post-launch: annotate in docs/AUDIT_2026-05-21.md
  with deferral rationale and target date

Exit gate:
- 100% of Highs either fixed or annotated with deferral rationale
- No High is in "unresolved, no plan" state

### Phase 3G — Quality Gates Sprint Q3

Entry gate: Phase 3F merged.
Work:
- gitsign keyless signing setup for both human and agent commits
- Mutation testing (mutmut) on modules already at >=90% line coverage.
  Do not run on monitor.py until M6 (the split) lands.
- Signed-commits branch protection turned on (per Q7 answer)
- Full mypy --strict pass after monitor.py split (audit M6)

Exit gate:
- Mutation score >=70% on in-scope modules
- Signed commits enforced on main
- mypy --strict passes
- Branch protection rules applied via `gh api`

### Phase 3H — Launch

Entry gate: All prior phases complete OR explicitly deferred with rationale.
Per EXECUTION_PLAYBOOK_one_week.md Day 7.

## Continuous discipline (every phase)

1. `make ci-fast` before every commit. Failures block commit.
2. `make ci-local` before every push. Failures block push.
3. Update `docs/RECONCILIATION_LOG.md` whenever a new discrepancy surfaces.
4. Update `docs/SPRINT_ONE_WEEK.md` at every phase transition.
5. Antfooding log at `docs/ANTFOODING_LOG.md` gets daily entries during
   the sprint, even if the entry is "nothing surfaced today."

## What success looks like

End of week 1:
- C1-C4 fixed and validated by their regression tests
- Quality Gates Q1 in CI, blocking new regressions
- Multi-agent harness installed and exercising the gates
- Lanes B and C shipped
- Lane A in flight or shipped (per Q3)
- Lane D per Q2 decision
- Brand site live at the chosen domain
- Audit Highs triaged

End of week 2:
- Quality Gates Q2 in CI
- Any remaining lane shipped
- High findings batch closed
- Antfooding log has 7+ days of entries
- First seed-fund conversations initiated

## Final instruction

Begin Phase -1 now. Run `/mcp` to verify codebase-memory-mcp is
connected and the security-guidance and superpowers plugins are
enabled. Write `docs/TOOLING.md` cataloguing the actual tool names
each exposes. Commit `.github/pull_request_template.md` and
`docs/BRANCHING.md` via a real PR on an `infra/pr-template` branch
to dogfood the branching policy.

Then begin Phase 0: read all 9 docs files plus the actual repo state.
For any file over 200 lines, use codebase-memory-mcp to get the
symbol outline first; drill into specific symbols only as needed.

Do not start Phase 1 until you have actually read each file. Do not
write the reconciliation report until you have actually read the repo
state with symbol-aware tools.

When the reconciliation report is ready, present its headings and key
tables inline, then STOP. Wait for the user's answers to Q1-Q8 before
doing anything else.
