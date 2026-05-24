# Branching policy

Mirrors Phase -1B of `docs/CC_PROMPT_MASTER_orchestrator.md` so
contributors and tooling can find the policy without reading the
orchestrator prompt.

## Rule of thumb

No commits to `main`. Every change goes through a branch with a PR.
The PR template enforces the checklist. Branch protection enforces CI.

## Branch naming

| Prefix      | Purpose                                                  |
|-------------|----------------------------------------------------------|
| `main`      | Protected. Signed commits enforced post-Q3. Linear history. |
| `audit/*`   | Adversarial audits (e.g. `audit/adversarial-self-audit`) |
| `security/*`| Security fixes (e.g. `security/c1-bcrypt`)               |
| `fix/*`     | Non-security bug fixes                                   |
| `feature/*` | New features outside the lane sprint                     |
| `infra/*`   | Tooling, CI, build harness                               |
| `lane-A`..`lane-D` | Four-lane sprint worktrees. Cut from main, merged via PR after grader sign-off. |
| `release/*` | Release prep (`release/v0.2.0`)                          |
| `hotfix/*`  | Emergency post-release fixes                             |
| `docs/*`    | Docs-only changes                                        |

## Lifecycle

- Cut from `main`. **Always rebase**, never merge `main` back in.
- Maximum **5 calendar days** before rebasing onto latest `main`.
- Delete the branch immediately after merge.
- Long-lived branches are forbidden except `main`.
- For the full merge-strategy decision tree (squash vs rebase, when each
  applies, gh CLI examples, `--subject` convention), see the [Merge
  strategy](#merge-strategy) section below.

## Commit conventions

Conventional commits: `<type>(<scope>): <subject>`

| Type     | When                                                    |
|----------|---------------------------------------------------------|
| feat     | New user-visible feature                                |
| fix      | Bug fix                                                 |
| security | Security fix (use audit ID as scope: `security(C1):`)   |
| perf     | Performance improvement                                 |
| refactor | Internal restructure, no behaviour change               |
| test     | Tests only                                              |
| docs     | Docs only                                               |
| chore    | Tooling, repo housekeeping                              |
| ci       | CI/CD changes                                           |
| build    | Build system / dependencies                             |

Rules:
- Subject under 72 chars. Body wraps at 80.
- **No** `Co-Authored-By: Claude` trailers. Authored by the human
  signing the commit (env vars, never `git config`).
- For audit fixes, reference the section:
  `security(C1): bcrypt.checkpw constant-time comparison`
  with `Refs docs/AUDIT_2026-05-21.md#C1` in the body.

## Merge strategy

GitHub repo allows two strategies: squash-merge (default) and
rebase-merge (opt-in). Merge commits are disabled.

### Squash-merge (default, ~90% of PRs)

Use when:
- The PR has a single commit (squash and 1-commit-rebase are identical)
- The PR's commits are iterative development (incremental progress on
  one concern, fixup commits, work-in-progress that landed together)
- The PR represents one atomic change regardless of how many commits
  it took to get there

The PR title becomes the commit message. The PR body becomes the
commit body. The original commits on the feature branch are discarded
when the branch is deleted.

### Rebase-merge (opt-in, ~10% of PRs)

Use when:
- The PR has multiple commits, each self-contained and independently
  revertable
- Future code archaeology benefits from seeing the commits separately
- Multi-step refactors where each step is deliberate
- Security audit batches where each fix is independent

Example: the Phase 3A C1-C4 merge used rebase-merge because each of
the four security fixes was a self-contained change that should remain
visible in main's history as a separate commit.

### Decision rule for graders and humans

If ALL commits in the PR are self-contained and independently
revertable AND there are at least 2 of them, prefer rebase-merge.
Otherwise, squash-merge.

When in doubt, squash. Squash is always safe. Rebase requires that
the commits actually be worth preserving.

### Never use merge commits

Disabled at the repo level. Linear history required.

### gh CLI commands

```bash
# Squash (default for ~90% of PRs):
PR_TITLE=$(HTTPS_PROXY= gh pr view N --json title --jq '.title')
HTTPS_PROXY= gh pr merge N --squash --delete-branch \
  --subject "$PR_TITLE (#N)"

# Rebase (when commits are independently revertable):
HTTPS_PROXY= gh pr merge N --rebase --delete-branch

# Merge commit: never. Repo setting disables it.
```

### `--subject` convention for squash merges

Always pass `--subject "$PR_TITLE (#N)"` on squash merges. Without it,
`gh pr merge --squash` may take the subject from the branch's single
commit message instead of the PR title, leaving the `(#N)` suffix off
the resulting commit on main.

Why it matters: `git log --oneline | grep "(#"` then becomes a
reliable "find the PR that introduced this commit" query.

The GitHub web UI's "Squash and merge" button always appends `(#N)`
correctly; only the CLI needs the explicit `--subject`.

### Stating intended merge strategy in PR body

Every PR body should include a one-line note under "Test plan" or
"Risk":

```
Merge strategy: squash (single-purpose change)
```

or

```
Merge strategy: rebase (N independently-revertable commits worth preserving)
```

The grader subagent validates this against the decision rule above.

## Worktree pattern (four-lane sprint)

```
ai-runtime-monitor-enterprise/    main worktree (lead orchestrator)
.worktrees/lane-A/  → lane-A      Tauri specialist
.worktrees/lane-B/  → lane-B      Extension scanner specialist
.worktrees/lane-D/  → lane-D      UI polish specialist
../airuntimemonitor-site/         separate repo (Lane C — brand site)
```

Create with:

```bash
git worktree add .worktrees/lane-A -b lane-A
git worktree add .worktrees/lane-B -b lane-B
git worktree add .worktrees/lane-D -b lane-D
```

## Push hygiene

The user's shell sometimes has `HTTPS_PROXY` set for mitmproxy work.
Always unset on push:

```bash
HTTPS_PROXY= git push origin <branch>
```

## When the policy starts

Effective from PR #2 (`infra/pr-template`) onward. Commits
`5e67e8e`, `b82b4fb` predate the policy and stand as the last direct
docs commits to main.
