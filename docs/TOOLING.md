# Tooling — connected MCPs, plugins, and when to use each

Phase -1 exit-gate doc. Captures the actual tools available in this
Claude Code workspace as of 2026-05-21, so subsequent sprint phases
reference correct identifiers rather than guessing.

Verify any time with `/mcp` and `/plugin`.

## codebase-memory-mcp (MCP server)

Symbol-aware code intelligence over the indexed repo. Use this for any
file longer than 200 lines (e.g. `monitor.py` at ~4800 LOC). Grep and
Glob miss indirect references and inheritance.

| Tool                                              | Use for                                                    |
|---------------------------------------------------|------------------------------------------------------------|
| `mcp__codebase-memory-mcp__index_status`          | Check whether the project is indexed and how fresh         |
| `mcp__codebase-memory-mcp__index_repository`      | (Re-)index this repo                                       |
| `mcp__codebase-memory-mcp__detect_changes`        | What's changed since last index — drives incremental re-index |
| `mcp__codebase-memory-mcp__list_projects`         | Which projects this server knows about                     |
| `mcp__codebase-memory-mcp__delete_project`        | Drop an indexed project                                    |
| `mcp__codebase-memory-mcp__get_architecture`      | High-level map (aspects=['all']) — start of a new session  |
| `mcp__codebase-memory-mcp__search_code`           | Grep-equivalent scoped to the indexed project              |
| `mcp__codebase-memory-mcp__search_graph`          | Find functions/classes by name pattern                     |
| `mcp__codebase-memory-mcp__get_code_snippet`      | Read a function/class by fully-qualified name              |
| `mcp__codebase-memory-mcp__trace_call_path`       | "Who calls X" with full transitive chain                   |
| `mcp__codebase-memory-mcp__query_graph`           | Ad-hoc Cypher for cross-cutting queries                    |
| `mcp__codebase-memory-mcp__get_graph_schema`      | What node/edge types the graph supports                    |
| `mcp__codebase-memory-mcp__manage_adr`            | Architectural decision records                             |
| `mcp__codebase-memory-mcp__ingest_traces`         | Runtime trace ingestion                                    |

## Plugins (skills)

### superpowers (v5.1.0)
Spec-driven workflow skills. Triggered explicitly by user (`/skill-name`)
or proactively when the situation matches.

| Skill                              | Trigger                                                 |
|------------------------------------|---------------------------------------------------------|
| `test-driven-development`          | Before writing implementation for any feature/bugfix    |
| `verification-before-completion`   | Before claiming "done", "passing", "fixed"              |
| `systematic-debugging`             | Any unexpected failure                                  |
| `executing-plans`                  | Multi-step spec with numbered sections                  |
| `dispatching-parallel-agents`      | 2+ independent tasks that don't share state             |
| `using-git-worktrees`              | Setting up the four-lane sprint                         |
| `writing-plans`                    | Designing implementation before code                    |
| `requesting-code-review`           | Asking another agent to review                          |
| `receiving-code-review`            | Acting on review feedback                               |
| `finishing-a-development-branch`   | Wrapping a branch for merge                             |
| `brainstorming`                    | Open-ended exploration                                  |
| `subagent-driven-development`      | Delegating a slice of work to a sub-agent               |
| `writing-skills` / `using-superpowers` | Meta-skills for skill authoring                     |

### security-guidance
Provides a hook (`security_reminder_hook.py`) that surfaces relevant
guidance during security-sensitive edits. Used by audit critical fixes
(C1–C4) and any change in the security/* lane.

### code-review (commands-based plugin)
Structured code review. Invoke before opening a PR larger than ~50 LOC
or touching more than one module.

### frontend-design
Distinctive component generation for the dashboard. Triggered by any
substantive change to `src/claude_monitoring/dashboard.html` (visual
design, info density, new tabs/panels).

### playwright
E2E + extension testing. Triggered by any user-flow that needs to load
the real dashboard / claude.ai / chatgpt.com.

### feature-dev (sub-agents)
Three specialist sub-agents available via `Task(subagent_type=...)`:
- `feature-dev:code-architect` — implementation blueprints from existing patterns
- `feature-dev:code-explorer`  — trace execution paths, map architecture
- `feature-dev:code-reviewer`  — bug/security/quality review with confidence filtering

## Decision matrix

| Task                                          | Approach                              |
|-----------------------------------------------|---------------------------------------|
| Read a file under 200 lines whole             | plain Read                            |
| Read a file over 200 lines                    | codebase-memory-mcp first, drill in   |
| "What does function X do?"                    | codebase-memory-mcp `get_code_snippet` |
| "Who calls function X?"                       | codebase-memory-mcp `trace_call_path`  |
| "Find this pattern across the codebase"       | codebase-memory-mcp `search_code`      |
| Security review of changed code               | security-guidance plugin + code-review |
| Spec-driven feature work (TDD loop)           | superpowers (`test-driven-development`) |
| Repo-level operations (issues, PRs, releases) | github CLI (`gh`)                      |
| Quick text grep across small files            | plain Grep                            |
| Dashboard visual change                       | frontend-design plugin                |
| Browser E2E or extension test                 | playwright plugin                     |
| Multi-step adversarial review                 | superpowers (`verification-before-completion`) |

## Fallback policy

If an MCP tool fails or returns surprising results, fall back to plain
Read/Grep for the affected files. Note the failure in this file's
"Known issues" section so the user can decide whether to file an issue
against the MCP server.

## Known issues

(none yet)

---

## Phase 3.0 capability map — plugins vs CC_PROMPT_00 custom subagents/skills

`docs/CC_PROMPT_00_multi_agent_harness.md` specifies 11 custom subagents
and 5 custom skills under `.claude/`. Phase 3.0 audit (run 2026-05-22)
compared them against the 6 connected plugins to eliminate duplicate
capability before Phase 3C installs `.claude/`.

### Subagents

| Custom (CC_PROMPT_00) | Plugin equivalent | Decision | Rationale |
|---|---|---|---|
| `code-reviewer.md` | `feature-dev:code-reviewer` agent + `code-review` plugin `/code-review` command | **DROP custom** | Plugin agent does confidence-scored bug/quality/security review with 0-100 filtering — exactly what the custom def specified, with more discipline. Plugin command handles PR-level reviews via `gh`. |
| `security-reviewer.md` | `security-guidance` plugin (PreToolUse hook) | **KEEP custom** | Hook is passive in-editor reminder. Adversarial reviewer subagent is a separate role for diff review by fresh-context agent. Different lifecycles. Hook complements, doesn't replace. |
| `file-explorer.md` | `feature-dev:code-explorer` | **DROP custom** | Plugin agent traces execution paths and maps architecture — identical purpose. |
| `design-system-curator.md` | `frontend-design` plugin | **KEEP custom** | Plugin generates distinctive components; curator is the Lane D specialist that integrates them into dashboard.html context. Custom workflow CALLS the plugin's skill. |
| `tauri-rust-engineer.md` | (none) | **DROP** | Lane A deferred to v0.3 per Q3. Re-evaluate when Tauri lane opens. |
| `extension-scanner-specialist.md` | (none) | **KEEP custom** | Lane B domain specialist for `src/claude_monitoring/extension_scanner/`. |
| `threat-intel-scout.md` | (none) | **DROP** | Reconciliation log already marked unused. Threat-intel work happens inside extension-scanner-specialist and existing `threat_intel.py`. |
| `brand-copywriter.md` | (none) | **KEEP custom** | Lane C specialist; brand voice rules are project-specific. |
| `test-writer.md` | (none direct) | **KEEP custom** | Project-specific test fixtures + conventions. Prompt should reference `superpowers:test-driven-development` for procedure. |
| `doc-writer.md` | (none) | **KEEP custom** | Scoped writes to `docs/` only. |
| `orchestrator.md` | (none — superpowers `dispatching-parallel-agents` covers parts) | **KEEP custom** | Project-specific routing logic over AGENTS.md and SPRINT_ONE_WEEK.md. |

Net: 11 custom subagents → 4 dropped (`code-reviewer`, `file-explorer`, `tauri-rust-engineer`, `threat-intel-scout`) → **7 to install in Phase 3C.**

### Skills

| Custom (CC_PROMPT_00) | Plugin equivalent | Decision | Rationale |
|---|---|---|---|
| `tdd-loop/SKILL.md` | `superpowers:test-driven-development` | **DROP custom** | Superpowers skill is exactly the red-green-refactor procedure, gets version updates. |
| `worktree-dispatch/SKILL.md` | `superpowers:using-git-worktrees` | **DROP custom** | Superpowers handles worktree setup canonically. |
| `security-review/SKILL.md` | `security-guidance` (PreToolUse) + `code-review` `/code-review` command | **DROP custom** | Workflow merges into security-guidance for inline reminders + `/code-review` for handoff. |
| `brand-voice-check/SKILL.md` | (none) | **KEEP custom** | Project-specific brand rules; no plugin equivalent. |
| `release-tag/SKILL.md` | (none) | **KEEP custom** | Adapted for CLI + Homebrew flow per Q3 (no Tauri DMG signing this sprint). |

Net: 5 custom skills → 3 dropped → **2 to install in Phase 3C.**

### Implications for Phase 3C harness install

When `.claude/` is installed in Phase 3C, ship:
- 7 subagents (not 11)
- 2 skills (not 5)
- 5 hooks (unchanged from CC_PROMPT_00)
- Lane rubrics A/B/C/D: rubric A becomes "deferred — see Q3"; rubrics
  B/C/D reference the resolved capability set above.

The 3 generally-useful plugin agents (`feature-dev:code-reviewer`,
`feature-dev:code-explorer`, `feature-dev:code-architect`) are invoked
directly via `Task(subagent_type="feature-dev:code-reviewer", ...)`
without local re-definition.
