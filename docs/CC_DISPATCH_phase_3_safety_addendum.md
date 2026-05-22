# Phase 3A Safety Guardrails (addendum to CC_DISPATCH_phase_3_kickoff.md)

Add these five guardrails BEFORE dispatching the four C1-C4 specialists.
They cost maybe 90 minutes of setup and prevent the "every PR was green
but main is broken" failure mode.

## Guardrail 1: Smoke test workflow (15 min)

Add `.github/workflows/smoke.yml`. Runs on every PR and on push to main.
Starts the actual daemon, hits the dashboard, confirms the product
boots end-to-end.

```yaml
name: Smoke
on:
  pull_request:
  push:
    branches: [main]

jobs:
  e2e-boot:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -e ".[dev]"
      - name: Start daemon in background
        run: |
          python -m claude_monitoring.monitor &
          echo $! > /tmp/daemon.pid
          sleep 3
      - name: Confirm dashboard responds
        run: |
          curl -fsS http://localhost:9081/api/stats > /tmp/stats.json
          test -s /tmp/stats.json
      - name: Confirm dashboard HTML loads
        run: |
          curl -fsS http://localhost:9081/ > /tmp/dash.html
          grep -q "<title>" /tmp/dash.html
          # If C2 broke dashboard rendering, this catches it
      - name: Confirm extension scanner endpoint (post-Lane-B)
        run: |
          # Only assert if endpoint exists yet — graceful degradation
          curl -fsS http://localhost:9081/api/extensions || true
      - name: Confirm no errors logged
        run: |
          if grep -i "ERROR\|TRACEBACK\|Exception" /tmp/daemon.log; then
            echo "FAIL: errors in daemon log"
            exit 1
          fi
      - name: Cleanup
        if: always()
        run: kill $(cat /tmp/daemon.pid) || true
```

This is what catches "C2 broke the dashboard." The unit tests would
pass; this fails because the HTML doesn't render.

## Guardrail 2: Integration branch before main (30 min)

Do NOT merge C1, C2, C3, C4 directly to main. Use an integration
branch.

```
main
  ↑ merge (after smoke + manual antfooding pass)
integration/phase-3a
  ↑ merge each ↑ merge each ↑ merge each ↑ merge each
security/c1   security/c2   security/c3   security/c4
```

Flow:
1. Each Cx PR targets `integration/phase-3a`, not `main`.
2. Each Cx PR runs CI + Smoke independently.
3. When all four are merged into integration, CI + Smoke run again on
   the combined state.
4. If integration is green and smoke passes, open ONE PR from
   integration/phase-3a to main.
5. Main gets a single, validated, all-four-fixes commit (or four
   commits if you preserve them via rebase-merge instead of squash).

This is the missing staging environment. Integration branch IS the
staging environment for this sprint.

Bonus: if Cx broke something Cy fixes by accident, you discover it
when merging Cy into integration, not after both are in main.

## Guardrail 3: Caller-audit gate for C3 (15 min)

Before C3's fix merges to integration, an automated step must verify
every call site of `_sanitize_string` handles empty-string return as
rejection.

Add to C3's PR template:

```markdown
## C3 caller audit (REQUIRED before merge)

Run:
\`\`\`bash
# List every caller of _sanitize_string
codebase-memory-mcp.search_graph(symbol="_sanitize_string", direction="callers")
\`\`\`

For each caller, paste:
- File:line
- Snippet showing how the return value is used
- Verdict: HANDLES_EMPTY (treats "" as rejection) or PASSES_THROUGH
  (uses the result without checking)

If ANY caller is PASSES_THROUGH, fix that caller in the same PR.
Do not merge until every caller is HANDLES_EMPTY.
```

This is the only critical that has caller-contract change risk. The
other three are local. C3 needs the explicit gate.

## Guardrail 4: Antfooding ratchet (10 min)

Q8 said yes to antfooding. Make it actually work as a guardrail:

1. Install the pre-C1-C4 build right now (before Phase 3A dispatches)
2. Note the working baseline behavior in `docs/ANTFOODING_LOG.md`:
   - Dashboard loads at http://localhost:9081/
   - Sessions populate as Claude Code runs
   - Alerts fire on synthetic test triggers
   - No errors in `~/.ai-runtime-monitor/logs/daemon.log`
3. After integration/phase-3a is built (Guardrail 2), install THAT
   build on the dev machine and confirm:
   - Same dashboard loads
   - Same sessions populate
   - Same alerts fire
   - Same baseline behavior
4. Only THEN merge integration to main.

The antfooding log entry becomes mandatory evidence on the
integration → main PR. Without it, the merge waits.

## Guardrail 5: Easy rollback (5 min)

Before Phase 3A dispatches, tag the current main as the last-known-good
release candidate:

```bash
git tag -a pre-c1c4 -m "Last known good before C1-C4 fix series"
git push origin pre-c1c4
```

If anything goes catastrophically wrong post-merge:

```bash
git revert <integration-merge-sha>
# OR, nuclear option:
git checkout pre-c1c4 && git push -f origin main
```

Add to `docs/RUNBOOK.md`:

```markdown
# Emergency rollback
1. Identify the bad merge SHA: `git log --oneline -10`
2. Revert: `git revert <sha>` (creates a revert commit, preserves history)
3. Or nuclear: `git checkout pre-c1c4 && git push --force-with-lease origin main`
4. Notify in Slack/wherever and write an incident note in
   docs/incidents/<date>.md
```

The runbook should exist before you need it.

## Updated execution order

```
Now (90 min total):
  1. Tag pre-c1c4 on main
  2. Commit smoke.yml workflow (infra/smoke-test branch, PR, merge)
  3. Create integration/phase-3a branch from main
  4. Install pre-C1-C4 build on dev machine, write baseline antfooding entry
  5. Commit RUNBOOK.md with rollback procedure

Then (Phase 3A, 4-5 hours wall-clock):
  6. Dispatch C1-C4 specialists in worktrees
  7. Each PR targets integration/phase-3a, NOT main
  8. C3 PR additionally requires the caller-audit table

After all four C PRs merge to integration:
  9. CI + Smoke run on integration/phase-3a
  10. Install integration build on dev machine
  11. Antfood it for 30 minutes: real Claude Code sessions, dashboard,
      alerts
  12. Write antfooding evidence in docs/ANTFOODING_LOG.md
  13. Open integration → main PR with antfooding evidence
  14. Merge to main only after CI + Smoke green AND antfood passed

Catastrophic break recovery:
  - git revert the integration merge from main
  - Or git reset --hard pre-c1c4 and force-push
```

## Why this matters

Without these guardrails, you have:
- 4 PRs that each individually pass CI
- A combined main that may have subtle integration bugs (C2 + C3
  interaction, dashboard rendering regression, sanitize-empty cascade)
- No way to know until you manually try the product
- No fast rollback if it's broken

With these guardrails, you have:
- 4 PRs validated independently
- 1 integration PR validated as a unit
- Real boot-and-render smoke test on every state
- Manual antfooding pass as merge gate
- Pre-tagged rollback point if everything goes sideways

Cost: 90 minutes of setup before Phase 3A dispatches.
Saves: potentially a full day of "why is main broken" debugging.

## Proceed

Add these five guardrails first. Then dispatch the original Phase 3A
plan with the modification that PRs target integration/phase-3a, not
main.
