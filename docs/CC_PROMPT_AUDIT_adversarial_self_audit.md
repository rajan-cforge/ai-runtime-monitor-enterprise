# Claude Code Sprint Prompt — Adversarial Self-Audit (Run First)

## Why this exists

Before adding any new feature or starting the four-lane sprint, we need an
honest read on the current state of `ai-runtime-monitor`. This audit uses
Boris Cherny's two-wave adversarial pattern: the first wave finds issues,
the second wave actively tries to falsify the first wave's findings. What
survives is real.

The output of this prompt is a single markdown file at
`docs/AUDIT_$(date +%Y-%m-%d).md` that becomes the input to the harness
sprint plan.

## Branch

```
git checkout main
git pull
git checkout -b audit/adversarial-self-audit
```

## Wave One: Three independent finder subagents

The orchestrator dispatches three subagents in parallel via the Task tool,
each with its own scope. They run in read-only worktrees so they cannot
interfere with each other.

### Finder 1: Style and consistency

```
Subagent: code-reviewer (Sonnet, read-only)
Scope:    Entire repository
Mission:  Find inconsistencies in coding style, naming, structure, and
          conventions. Look specifically for:

          - Type hints missing on public functions in Python code
          - Mixed snake_case and camelCase in the same module
          - Inconsistent error handling (some functions raise, others
            return None, others return tuples)
          - Public functions without docstrings
          - Modules with no __all__
          - Test files that don't follow the test_* convention
          - Magic numbers and strings that should be constants
          - Functions exceeding 50 lines
          - Files exceeding 500 lines

          Output: docs/audit/wave1-style.md with file:line citations.
          Do not propose fixes. Just enumerate findings.
```

### Finder 2: Bug-hunter

```
Subagent: code-reviewer (Sonnet, read-only)
Scope:    Entire repository
Mission:  Find actual bugs. Read the code, not just the tests. Look for:

          - Race conditions in async code (await without lock)
          - Resource leaks (open files, subprocesses, threads not joined)
          - Off-by-one errors in loops and slicing
          - None-handling bugs (assuming non-None without check)
          - Exceptions caught too broadly (except: pass)
          - Mutable default arguments
          - Time-of-check to time-of-use bugs (TOCTOU) in file ops
          - SQL injection sinks (string-formatted queries)
          - Subprocess calls with shell=True or unsanitized args
          - Hardcoded paths that break on other machines
          - Tests that test the mock, not the code

          Output: docs/audit/wave1-bugs.md with file:line citations
          and a hypothesized impact for each.
```

### Finder 3: History combiner

```
Subagent: file-explorer (Haiku, read-only, has Bash for git)
Scope:    Git history of the last 60 days
Mission:  Comb commit history for signal:

          - Commits that touch the same file 5+ times in a week (churn)
          - Commits that revert previous commits (instability signal)
          - Commits with empty or "wip" messages
          - Files added then removed within 7 days (dead code)
          - Features mentioned in commits but not in the README
          - TODOs and FIXMEs older than 30 days
          - Files in .gitignore that were ever committed (potential
            secret leaks; check git log -- file)
          - Branches that diverged > 30 days ago (likely stale)

          Run: git log, git blame, git log --diff-filter=D, git diff,
               git rev-list, ripgrep over the working tree.

          Output: docs/audit/wave1-history.md with commit hashes,
          file paths, and a one-line interpretation per finding.
```

All three finders run in parallel. Expected wall-clock: 30 to 45 minutes.

## Wave Two: Five adversarial falsifier subagents

When all three finders complete, the orchestrator dispatches five
falsifier subagents *whose explicit job is to break the first wave's
findings*. Each falsifier runs in a fresh context window with only the
finders' output and read-only access to the code.

The framing for every falsifier is:

> "Wave One produced these findings. Your job is to falsify them. For
> each finding, your goal is to demonstrate why the finding is wrong,
> incomplete, or overstated. Counter-evidence beats agreement. If you
> cannot find counter-evidence, mark the finding CONFIRMED. If you can,
> mark it FALSIFIED with the specific evidence."

### Falsifier 1: Counter-style

```
Subagent: code-reviewer (Sonnet, read-only)
Scope:    docs/audit/wave1-style.md + code
Mission:  For every Wave-1 style finding, find counter-evidence that
          the convention is actually intentional. Examples:
          - "This function is 80 lines, but the linear flow is more
            readable than splitting it"
          - "These two casing styles are correct: one is the public
            API (snake), one is the wire protocol (camel)"
          - "This magic number is a hardware-defined constant"

          Output: docs/audit/wave2-style-counter.md
```

### Falsifier 2: Counter-bug

```
Subagent: code-reviewer (Sonnet, read-only)
Scope:    docs/audit/wave1-bugs.md + code + tests
Mission:  For every Wave-1 bug, find counter-evidence:
          - "This is not a TOCTOU because the file is owned by the
            process and no other writer exists"
          - "This broad except is intentional, paired with a re-raise
            three lines later that the finder missed"
          - "The race condition the finder claims is gated by the lock
            on line 142, which they didn't see"

          For each bug, ALSO check: does any existing test catch this?
          If yes, the bug is partially mitigated. If no, the bug is
          unmitigated.

          Output: docs/audit/wave2-bugs-counter.md
```

### Falsifier 3: Counter-history

```
Subagent: file-explorer (Haiku, read-only, has Bash)
Scope:    docs/audit/wave1-history.md + git history
Mission:  Falsify the history finder. Examples:
          - "This 5-times-in-a-week churn was an intentional refactor
            sprint, not instability"
          - "This revert was a Friday rollback that was re-landed
            cleanly on Monday"
          - "These TODOs are tracking issues already filed in GitHub"

          Output: docs/audit/wave2-history-counter.md
```

### Falsifier 4: Severity-falsifier

```
Subagent: security-reviewer (Sonnet, read-only)
Scope:    All confirmed findings from Wave Two
Mission:  For each confirmed finding, challenge its severity. The
          finder said critical/high/medium. Argue the opposite.

          - Could a critical finding actually be low-impact in
            practice? (e.g., the code path isn't reachable)
          - Could a low finding actually be critical? (e.g., the
            finder missed a chain of three small issues that compound)

          Output: docs/audit/wave2-severity-counter.md
```

### Falsifier 5: Completeness-falsifier

```
Subagent: code-reviewer (Sonnet, read-only)
Scope:    All Wave-1 output + the actual repo
Mission:  Find what Wave One MISSED. The first wave is incomplete.
          Look specifically in areas the first wave gave a clean bill:

          - If wave-1-bugs found nothing in claude_monitoring/proxy/,
            go re-read claude_monitoring/proxy/ and find what they
            missed.
          - If wave-1-history found no concerning churn, re-check the
            top 10 files by line count.
          - If wave-1-style flagged 50 issues, ask "what categories
            of style issues did they not look for?" and check those.

          Output: docs/audit/wave2-completeness.md with new findings.
```

All five falsifiers run in parallel. Expected wall-clock: 30 to 45 minutes.

## Synthesis: orchestrator produces final audit

Lead orchestrator (Opus 4.7) reads all eight wave outputs and produces:

```
docs/AUDIT_<date>.md
```

Structure:

```markdown
# AI Runtime Monitor — Adversarial Self-Audit (<date>)

## Methodology
Two-wave adversarial subagent audit. Wave 1: 3 independent finders.
Wave 2: 5 falsifiers. Only findings that survived Wave 2 are reported.

## Summary
- Total findings raised in Wave 1: <N>
- Findings falsified in Wave 2: <M>
- Confirmed findings: <N - M>
- New findings from completeness-falsifier: <K>
- Final tally: <N - M + K>

## Critical findings (must fix before launch)
1. <finding>
   - File: ...
   - Confirmed by: <falsifier name>
   - Effort to fix: <S/M/L>
   - Suggested approach: ...

2. ...

## High findings (fix in launch week)
...

## Medium findings (track post-launch)
...

## Style and consistency issues (defer or fix in batch)
...

## Dead code and stale TODOs
...

## What looks healthy
- <areas where audit found nothing concerning>
- <test coverage by area>
- <areas with good documentation>

## Next steps (orchestrator recommendation)
1. ...
2. ...
3. ...
```

## After the audit

Do not start the four-lane sprint until the audit's critical findings are
addressed. Some of those findings may invalidate Lane scope. For example,
if the audit finds the alert dispatcher has structural bugs, Lane B's
extension scanner cannot ship through it.

The orchestrator updates `docs/SPRINT_ONE_WEEK.md` with audit-driven
changes before Day 1 of the sprint.

## Gotchas

(Encoding this here so the audit doesn't repeat known failure modes.)

- The first wave will be too noisy. Expect 100 to 300 findings across
  three finders. The point of Wave 2 is to compress that to 20 to 40
  real issues. Do not try to make Wave 1 more selective. Make Wave 2
  more rigorous.

- Falsifiers will sometimes invent counter-evidence. Read their
  citations. If a falsifier says "the lock at line 142 mitigates this
  race," go look at line 142 yourself.

- Coverage numbers lie. A function with 100% line coverage can still
  be wrong if the tests assert nothing meaningful. The bug-finder
  should call out tests that test the mock instead of the code.

- The completeness falsifier is the most important one and the most
  expensive to run. Do not skip it to save time.

- Audit findings can themselves contain bugs. The orchestrator should
  not blindly accept the synthesis. If you read a finding and disagree,
  push back. The audit is a tool, not an oracle.

## Verification Checklist

```bash
# 1. All wave files exist
test -f docs/audit/wave1-style.md && \
test -f docs/audit/wave1-bugs.md && \
test -f docs/audit/wave1-history.md && \
test -f docs/audit/wave2-style-counter.md && \
test -f docs/audit/wave2-bugs-counter.md && \
test -f docs/audit/wave2-history-counter.md && \
test -f docs/audit/wave2-severity-counter.md && \
test -f docs/audit/wave2-completeness.md && \
echo "All wave files present"

# 2. Final audit synthesized
ls docs/AUDIT_*.md

# 3. Critical findings count is honest
grep -c "^### " docs/AUDIT_*.md | head -1
# If this is 0, the audit was too gentle. If this is >50, the audit
# wasn't filtered enough.

# 4. Every critical finding has a file:line citation
grep "^### " docs/AUDIT_*.md | wc -l
# Compare against grep "File: " docs/AUDIT_*.md | wc -l
# They should match within ±10%

# 5. Commit
git add docs/audit/ docs/AUDIT_*.md
git commit -m "audit: adversarial two-wave self-audit"
```

## Commit and PR

```
audit: adversarial two-wave self-audit

Run via Boris Cherny pattern: 3 wave-1 finders + 5 wave-2 falsifiers.
Final tally: <N> confirmed findings.

See docs/AUDIT_<date>.md for the synthesized report.
Wave outputs preserved under docs/audit/ for reproducibility.

This is the audit referenced in our one-week sprint plan. The four
feature lanes do not start until critical findings are addressed.
```
