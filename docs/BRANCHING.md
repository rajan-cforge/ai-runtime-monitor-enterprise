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
- **Squash-merge** by default. Rebase-merge only when multiple commits
  are genuinely separable and worth preserving.
- Delete the branch immediately after merge.
- Long-lived branches are forbidden except `main`.

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
