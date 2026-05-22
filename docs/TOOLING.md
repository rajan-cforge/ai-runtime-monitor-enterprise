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
