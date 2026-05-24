# Pre-PR review loop

Before opening any PR with substantive changes (anything beyond a one-line docs fix), the orchestrator runs the three reviewer agents against the **local** diff and folds the fixes back into the same commit. The PR you push to GitHub is the validated final state, not an iteration in progress.

This document is the source-of-truth for the procedure. Future Claude Code sessions follow the same flow.

## The loop

1. **Implementation complete.** All local tests pass; lint and format are clean. If they aren't, fix them before running the loop — the reviewers shouldn't burn cycles on mechanical issues that `make ci-fast` already catches.

2. **Capture the workspace.** Run `scripts/dev/pre_pr_review.sh`. It creates `~/.vigil-pre-pr-review/<timestamp>/` with `diff.patch`, `files.txt`, and `meta.txt`. The script exits non-zero if there's nothing to review (no commits ahead of `origin/main` and no working-tree changes).

3. **Dispatch three reviewers in parallel** (one message, three Agent tool calls):
   - `code-reviewer` (the grader) — mechanical rubric, brevity-bound.
   - `architect-reviewer` in **local mode** — pass the workspace path; it reads `diff.patch` and the working-tree files, writes `architect-verdict.md` into the workspace.
   - `performance-reviewer` in **local mode** — same pattern, writes `performance-verdict.md`.

   Each local-mode reviewer tags findings as `FIX-BEFORE-MERGE`, `DEFER-TO-FOLLOWUP`, or `INFORMATIONAL`.

4. **Read all three verdicts** from the workspace. Count the `FIX-BEFORE-MERGE` findings across all three reports.

5. **Decide based on the count:**
   - **0 findings** — proceed to step 8.
   - **1–5 findings** — proceed to step 6, the fix loop.
   - **>5 findings** — pause and ping the user. More than five fix-before-merge items in one PR usually signals that the implementation needs rethinking, not patching. Don't try to plough through it.

6. **Fix loop.** For each `FIX-BEFORE-MERGE` finding:
   - Apply the suggested fix in the working tree.
   - Run the targeted test for the fix area (single test file or specific test class — not the full suite).
   - If the test passes: continue to the next finding.
   - If the test fails: revert the fix, downgrade the finding to `DEFER-TO-FOLLOWUP`, continue.

7. **Verify with a second pass.** Re-dispatch all three reviewers against the now-patched working tree. **Fix cycles are capped at 2** — if the second pass introduces new `FIX-BEFORE-MERGE` findings, downgrade them to `DEFER-TO-FOLLOWUP` and document in the commit message. The cap exists so a stubborn reviewer can't trap the orchestrator in an infinite loop.

8. **Run `make ci-fast`** one more time to confirm lint + format + the smallest test gate still pass after the fixes.

9. **Stage everything and commit as ONE commit.** All the original work plus all the local fixes go into a single commit. The PR's git log on GitHub should read as if the engineer got it right the first time — because the iterations happened locally, before the public commit existed.

   **Commit-message convention:**

   ```
   <type>(<scope>): <subject>

   <body — what changed and why>

   Pre-PR review cycle:
     architect:   PASS | PASS_WITH_NOTES (N fixes applied locally)
     performance: PASS | WATCH (N fixes applied locally)
     grader:      PASS | REVISE (N fixes applied locally)

   Fixes applied locally before push:
     - <file>:<line> — <one-line description>
     - ...

   Deferred to follow-up:
     - <file>:<line> — <what was deferred and why>
     - ... (or "none")
   ```

10. **Push the branch** with `HTTPS_PROXY= git push -u origin <branch>`.

11. **Open the PR** (`gh pr create ...`). Include the consolidated review summary in the PR body — it's the audit trail.

12. **PR-time reviewers run as final verification.** Because the local cycle already fixed `FIX-BEFORE-MERGE` items, the GitHub-side reviewers should return PASS or PASS_WITH_NOTES with only `INFORMATIONAL` items. If they surface a new `FIX-BEFORE-MERGE` that the local cycle missed, that's a reviewer-quality signal — note it for rubric refinement.

13. **Ping the user** with the consolidated one-liner (today's format), plus a "fixes applied locally" line.

## What this changes vs. dispatch-on-PR-open

- **Review moves left.** The cost of fixing a finding drops because there's no force-push, no CI re-run, no public revision history.
- **Commits are clean.** A PR that previously had "first commit + fix commit + merge" now has one squash-merged commit.
- **CI runs once per PR.** Across a sprint this is real time saved.

## What this does NOT change

- **Reviewers still need explicit dispatch.** This is procedural, not mechanical. A different maintainer or future session who skips the loop falls back to dispatch-on-PR-open with no degradation in correctness — just a slower cycle.
- **The GitHub App is still the eventual answer.** A bot that auto-runs the loop on PR open is the mechanical end-state; Phase 3G work after launch.
- **Not every finding has a 5-minute fix.** Architectural decisions, breaking changes, and large refactors get tagged `DEFER-TO-FOLLOWUP` and acknowledged in the commit message rather than forced into the PR.

## When to skip the loop

- Pure docs PRs (one file, prose-only).
- One-line typo fixes.
- Reverting a known-bad commit.

For any PR that touches `.py`, `.yml`, `.toml`, `.json`, or `Makefile`, run the loop.

## Workspace hygiene

`~/.vigil-pre-pr-review/` accumulates one directory per loop run. Old workspaces are kept for forensics — if you ever need to see why a previous PR was deemed clean, the verdicts are there. Prune manually when the directory gets large; nothing auto-deletes.

The directory is outside the repo and never committed.
