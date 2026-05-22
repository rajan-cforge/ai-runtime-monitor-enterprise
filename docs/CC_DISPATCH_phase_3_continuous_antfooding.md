# Phase 3 Complete Dispatch — Continuous Antfooding Mode

User has selected the "always running on latest validated code" workflow.
Implement all six guardrails BEFORE dispatching the Phase 3A specialists.

This supersedes CC_DISPATCH_phase_3_kickoff.md for orchestration.
Q1-Q10 answers and the C1-C4 test plans from that document still apply.

## The contract

User wants three things simultaneously:
1. Every change visible as a PR on GitHub
2. CI green before anything reaches main
3. AI Monitor (Vigil) running on their dev machine the whole time,
   on the latest VALIDATED code (not work-in-progress)

"Latest validated" = whatever has passed CI + Smoke and reached
`integration/phase-3a` or `main`. Specialist work-in-progress branches
are NOT for the dev machine.

## Setup phase (90 min, runs ONCE before Phase 3A dispatches)

### Step 1: Tag last-known-good

```bash
git checkout main
git pull
git tag -a pre-c1c4 -m "Last known good before C1-C4 fix series. Rollback target."
git push origin pre-c1c4
```

### Step 2: Create integration branch

```bash
git checkout -b integration/phase-3a
git push -u origin integration/phase-3a
```

All four C1-C4 PRs target this branch, NOT main. After all four
merge here AND smoke passes AND user-confirmed antfood passes, ONE
PR from integration/phase-3a to main.

### Step 3: Smoke test workflow

Branch: `infra/smoke-test`. Create `.github/workflows/smoke.yml`:

```yaml
name: Smoke
on:
  pull_request:
  push:
    branches: [main, integration/phase-3a]

jobs:
  e2e-boot:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -e ".[dev]"
      - name: Start daemon
        run: |
          python -m claude_monitoring.monitor > /tmp/daemon.log 2>&1 &
          echo $! > /tmp/daemon.pid
          for i in {1..10}; do
            curl -fsS http://localhost:9081/api/stats > /dev/null && break
            sleep 1
          done
      - name: Dashboard responds
        run: curl -fsS http://localhost:9081/api/stats > /tmp/stats.json && test -s /tmp/stats.json
      - name: Dashboard HTML renders
        run: |
          curl -fsS http://localhost:9081/ > /tmp/dash.html
          grep -q "<title>" /tmp/dash.html
          test $(wc -c < /tmp/dash.html) -gt 1000
      - name: Extension scanner endpoint (graceful, may not exist yet)
        run: curl -fsS http://localhost:9081/api/extensions || echo "endpoint not yet present (expected pre-Lane-B)"
      - name: No errors in daemon log
        run: |
          if grep -iE "(ERROR|TRACEBACK|^Exception)" /tmp/daemon.log; then
            echo "FAIL: errors in daemon log"
            cat /tmp/daemon.log
            exit 1
          fi
      - name: Cleanup
        if: always()
        run: kill $(cat /tmp/daemon.pid) 2>/dev/null || true
```

### Step 4: Install the auto-pull-and-restart loop on dev machine

Create `scripts/antfood-loop.sh`:

```bash
#!/usr/bin/env bash
# Continuous antfooding loop.
# Polls integration/phase-3a + main. Pulls when CI+Smoke are green.
# Restarts daemon on new validated commits. Rolls back on boot failure.

set -uo pipefail

REPO_DIR="${REPO_DIR:-$HOME/code/ai-runtime-monitor-enterprise}"
WATCH_BRANCHES=("main" "integration/phase-3a")
POLL_INTERVAL=300  # 5 minutes
ROLLBACK_TAG="pre-c1c4"
DAEMON_HEALTHCHECK="http://localhost:9081/api/stats"
LOG="$HOME/.vigil-antfood.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

current_branch() { git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD; }
current_sha() { git -C "$REPO_DIR" rev-parse --short HEAD; }

ci_green() {
  local branch="$1"
  local sha="$(git -C "$REPO_DIR" rev-parse origin/"$branch")"
  local conclusions
  conclusions=$(gh -R rajan-cforge/ai-runtime-monitor-enterprise run list \
    --branch "$branch" --commit "$sha" --limit 10 \
    --json conclusion --jq '[.[].conclusion] | unique')
  # All conclusions must be success or skipped
  echo "$conclusions" | grep -qE '"failure"|"cancelled"' && return 1
  echo "$conclusions" | grep -q '"success"' && return 0
  return 1
}

start_daemon() {
  pkill -f "claude_monitoring.monitor" 2>/dev/null || true
  sleep 2
  cd "$REPO_DIR"
  source venv/bin/activate
  pip install -e ".[dev]" --quiet
  nohup python -m claude_monitoring.monitor > "$HOME/.vigil-daemon.log" 2>&1 &
  echo $! > "$HOME/.vigil-daemon.pid"
  # Wait up to 30s for healthcheck
  for i in {1..30}; do
    curl -fsS "$DAEMON_HEALTHCHECK" > /dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

rollback() {
  log "ROLLBACK: daemon failed to boot. Reverting to $ROLLBACK_TAG"
  git -C "$REPO_DIR" checkout "$ROLLBACK_TAG"
  start_daemon
}

# Initial start
log "Starting antfood loop. Repo: $REPO_DIR"
cd "$REPO_DIR"
git fetch --all --tags
start_daemon || { rollback; exit 1; }
log "Initial daemon running on $(current_sha) ($(current_branch))"

# Watch loop
while true; do
  sleep "$POLL_INTERVAL"
  git -C "$REPO_DIR" fetch --all --quiet

  for branch in "${WATCH_BRANCHES[@]}"; do
    local_sha=$(current_sha)
    remote_sha=$(git -C "$REPO_DIR" rev-parse --short "origin/$branch" 2>/dev/null) || continue

    if [ "$local_sha" = "$remote_sha" ]; then continue; fi

    log "New commits on $branch: $local_sha → $remote_sha"

    if ! ci_green "$branch"; then
      log "CI not green on $branch yet. Skipping."
      continue
    fi

    log "CI green. Pulling and restarting on $branch."
    git -C "$REPO_DIR" checkout "$branch"
    git -C "$REPO_DIR" pull --ff-only

    if ! start_daemon; then
      log "Daemon failed to start on $remote_sha. Rolling back."
      rollback
      continue
    fi

    log "Now running $branch $(current_sha). All systems normal."
    break  # only pull from first branch that has new validated work this tick
  done
done
```

Install:

```bash
chmod +x scripts/antfood-loop.sh
# Run in a dedicated terminal tab (or via launchd for daemon mode):
./scripts/antfood-loop.sh
```

Optional: wrap in launchd so it survives reboots and is restartable:

```xml
<!-- ~/Library/LaunchAgents/com.gocloudforge.vigil-antfood.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>com.gocloudforge.vigil-antfood</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/rajanyadav/code/ai-runtime-monitor-enterprise/scripts/antfood-loop.sh</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Users/rajanyadav/.vigil-antfood.out</string>
  <key>StandardErrorPath</key><string>/Users/rajanyadav/.vigil-antfood.err</string>
</dict>
</plist>
```

Load: `launchctl load ~/Library/LaunchAgents/com.gocloudforge.vigil-antfood.plist`

### Step 5: Caller-audit gate for C3

Update the PR template (`.github/pull_request_template.md`) to add a
conditional section that fires when the PR title contains "C3":

```markdown
## C3-specific: caller audit (required if this PR touches _sanitize_string)

Run via codebase-memory-mcp:
- Tool: search_graph or trace_call_path
- Symbol: _sanitize_string
- Direction: callers

For each caller, document below:
| File:line | How return value is used | Verdict |
|---|---|---|
| ... | ... | HANDLES_EMPTY / PASSES_THROUGH |

If any caller is PASSES_THROUGH, fix it in this same PR before merge.
```

### Step 6: Runbook

Create `docs/RUNBOOK.md`:

```markdown
# Vigil Operations Runbook

## Emergency rollback

If main breaks post-merge:

1. Identify the bad SHA:
   git log --oneline -10

2. Soft revert (preserves history):
   git revert <sha>
   git push origin main

3. Nuclear (force-push):
   git checkout pre-c1c4
   git push --force-with-lease origin main

4. Antfood loop on dev machine auto-detects and pulls within 5 min.

5. Write incident note: docs/incidents/<date>-<title>.md

## Restart antfood loop

If the auto-pull loop dies:

  pkill -f antfood-loop.sh
  ./scripts/antfood-loop.sh &

Or via launchd:

  launchctl unload ~/Library/LaunchAgents/com.gocloudforge.vigil-antfood.plist
  launchctl load ~/Library/LaunchAgents/com.gocloudforge.vigil-antfood.plist

## Check what's running

  ps aux | grep claude_monitoring
  tail -50 ~/.vigil-daemon.log
  tail -50 ~/.vigil-antfood.log
  cd ~/code/ai-runtime-monitor-enterprise && git log --oneline -1

## Force re-pull (manual override)

  cd ~/code/ai-runtime-monitor-enterprise
  git fetch --all
  git checkout integration/phase-3a
  git pull
  pkill -f claude_monitoring.monitor
  source venv/bin/activate
  pip install -e ".[dev]"
  python -m claude_monitoring.monitor &
```

### Setup exit gate

Confirm all six before dispatching Phase 3A:

- [ ] `pre-c1c4` tag exists on origin
- [ ] `integration/phase-3a` branch exists on origin
- [ ] `infra/smoke-test` PR merged to main, smoke.yml running green
- [ ] `scripts/antfood-loop.sh` running on dev machine, daemon healthy
- [ ] PR template includes C3 caller-audit section
- [ ] `docs/RUNBOOK.md` committed

## Phase 3A dispatch (after setup complete)

Per CC_DISPATCH_phase_3_kickoff.md Phase 3A test plans, with ONE
modification: all four C1-C4 PRs target `integration/phase-3a`, not
`main`.

Branches (unchanged from kickoff):
- `security/c1-bcrypt` → PR to integration/phase-3a
- `security/c2-xss-esc` → PR to integration/phase-3a
- `security/c3-sync-fail-open` → PR to integration/phase-3a (with caller audit)
- `security/c4-osascript-injection` → PR to integration/phase-3a

Each PR runs CI + Smoke. Each must be green before merging to
integration.

The antfood loop on the dev machine will NOT auto-pull from these
specialist branches. It only watches `integration/phase-3a` and `main`.
This is intentional: the user runs validated code only.

## Integration merge gate (after all four C PRs merged to integration)

Once `integration/phase-3a` has all four fixes:

1. CI + Smoke run on integration with combined state. Must be green.
2. Antfood loop on dev machine pulls integration automatically and
   restarts the daemon. Confirms boot.
3. User manually antfoods for 30 minutes:
   - Open dashboard at http://localhost:9081/
   - Confirm all tabs render (no XSS regression from C2)
   - Confirm sessions populate from real Claude Code runs
   - Confirm alerts fire on synthetic triggers
   - Confirm login still works (no bcrypt regression from C1)
   - Confirm sync still works (no fail-open regression from C3)
   - Confirm notifications fire (no osascript regression from C4)
4. User writes antfooding evidence in `docs/ANTFOODING_LOG.md`
5. User opens PR: `integration/phase-3a` → `main`
6. PR body includes the antfooding evidence
7. Merge only after green CI + Smoke + antfooding evidence

## Continuous mode summary

```
You see on GitHub:                    Running on your machine:
─────────────────                    ──────────────────────
security/c1-bcrypt PR  (green CI)   (not running — WIP)
security/c2-xss-esc PR (green CI)   (not running — WIP)
security/c3-sync-fail-open PR       (not running — WIP)
security/c4-osascript-injection PR  (not running — WIP)
       ↓ all merge to ↓
integration/phase-3a (green CI + Smoke) ─→ AUTO-PULLED, daemon restarted
       ↓ user antfoods ↓
       ↓ user opens PR ↓
integration/phase-3a → main (green CI + Smoke) ─→ AUTO-PULLED, daemon restarted
```

The dev machine never runs a specialist's work-in-progress. It runs
exactly what is on `integration/phase-3a` or `main`, both of which
have passed CI + Smoke.

## Proceed

1. Complete Setup steps 1-6 (90 min).
2. Verify setup exit gate.
3. Dispatch Phase 3A per CC_DISPATCH_phase_3_kickoff.md with PRs
   targeting integration/phase-3a.
4. Monitor antfood loop log at ~/.vigil-antfood.log on the dev machine.
5. Stop and report after each Cx PR merges to integration. Stop and
   wait for explicit user go-ahead before the integration → main PR.
