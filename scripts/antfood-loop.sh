#!/usr/bin/env bash
# Continuous antfooding loop for Vigil / AI Runtime Monitor.
#
# Polls integration/phase-3a + main on the GitHub origin. When a watched
# branch advances AND its head commit's CI+Smoke runs are all green,
# pulls the new commit and restarts the local daemon on it.
#
# On boot failure, rolls back to ROLLBACK_TAG and starts that. The user's
# dashboard at http://localhost:9081 is never blank for long.
#
# Designed for a SEPARATE clone (e.g. ~/code/ai-runtime-monitor-enterprise)
# distinct from any editing clone — the antfooded copy is what's
# running, not your work-in-progress.
#
# Per docs/CC_DISPATCH_phase_3_continuous_antfooding.md Step 4.

set -uo pipefail

REPO_DIR="${REPO_DIR:-$HOME/code/ai-runtime-monitor-enterprise}"
WATCH_BRANCHES=("main" "integration/phase-3a")
POLL_INTERVAL="${POLL_INTERVAL:-300}"  # 5 minutes
ROLLBACK_TAG="${ROLLBACK_TAG:-pre-c1c4}"
DAEMON_HEALTHCHECK="${DAEMON_HEALTHCHECK:-http://localhost:9081/api/stats}"
LOG="${LOG:-$HOME/.vigil-antfood.log}"
GH_REPO="${GH_REPO:-rajan-cforge/ai-runtime-monitor-enterprise}"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

current_branch() { git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD; }
current_sha()    { git -C "$REPO_DIR" rev-parse --short HEAD; }

# Returns 0 if the head of $branch on origin has at least one successful
# CI run and no failed/cancelled runs. In-progress runs count as "wait,
# not green yet" — return 1.
ci_green() {
  local branch="$1"
  local sha
  sha="$(git -C "$REPO_DIR" rev-parse "origin/$branch")"
  local runs_json
  runs_json=$(HTTPS_PROXY= gh -R "$GH_REPO" run list \
    --branch "$branch" --commit "$sha" --limit 10 \
    --json status,conclusion 2>/dev/null) || return 1

  # Any in-progress, failure, or cancelled → not green
  if echo "$runs_json" | python3 -c '
import json, sys
runs = json.load(sys.stdin)
if not runs:
    sys.exit(1)
statuses = {r.get("status") for r in runs}
conclusions = {r.get("conclusion") for r in runs}
if "in_progress" in statuses or "queued" in statuses:
    sys.exit(1)
if "failure" in conclusions or "cancelled" in conclusions or "timed_out" in conclusions:
    sys.exit(1)
sys.exit(0)
' 2>/dev/null; then
    return 0
  fi
  return 1
}

start_daemon() {
  pkill -f "claude_monitoring.monitor" 2>/dev/null || true
  sleep 2
  cd "$REPO_DIR" || return 1

  # Use .venv (project convention) — fall back to venv for legacy clones
  if [ -d ".venv" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
  elif [ -d "venv" ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
  else
    log "ERROR: no .venv or venv in $REPO_DIR — create one with python3 -m venv .venv"
    return 1
  fi

  pip install -e ".[dev]" --quiet || {
    log "ERROR: pip install failed"
    return 1
  }

  # Daemon mode needs the setup marker; antfooded clone may be a fresh
  # checkout that's never been through the wizard.
  mkdir -p "$HOME/claude_watch_output"
  touch "$HOME/claude_watch_output/.setup_complete"

  nohup ai-monitor --start --daemon > "$HOME/.vigil-daemon.log" 2>&1 &
  echo $! > "$HOME/.vigil-daemon.pid"

  for _ in $(seq 1 30); do
    if curl -fsS "$DAEMON_HEALTHCHECK" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback() {
  log "ROLLBACK: daemon failed to boot. Reverting to $ROLLBACK_TAG"
  git -C "$REPO_DIR" fetch --tags --quiet
  git -C "$REPO_DIR" checkout "$ROLLBACK_TAG" 2>&1 | tee -a "$LOG"
  if ! start_daemon; then
    log "FATAL: rollback target $ROLLBACK_TAG also failed to boot. Manual intervention required."
    return 1
  fi
  log "Rollback successful. Running $ROLLBACK_TAG ($(current_sha))"
}

# Initial start
log "Starting antfood loop. Repo: $REPO_DIR. Poll: ${POLL_INTERVAL}s."

if [ ! -d "$REPO_DIR/.git" ]; then
  log "ERROR: $REPO_DIR is not a git repo. Clone it first."
  exit 1
fi

git -C "$REPO_DIR" fetch --all --tags --quiet

if ! start_daemon; then
  log "Initial start failed on $(current_sha). Attempting rollback."
  rollback || exit 1
fi
log "Initial daemon running on $(current_sha) ($(current_branch))"

# Watch loop
while true; do
  sleep "$POLL_INTERVAL"
  git -C "$REPO_DIR" fetch --all --quiet

  for branch in "${WATCH_BRANCHES[@]}"; do
    local_sha=$(current_sha)
    remote_sha=$(git -C "$REPO_DIR" rev-parse --short "origin/$branch" 2>/dev/null) || continue

    if [ "$local_sha" = "$remote_sha" ]; then
      continue
    fi

    log "Update on $branch: local=$local_sha remote=$remote_sha"

    if ! ci_green "$branch"; then
      log "CI/Smoke not green yet on $branch@$remote_sha. Will recheck next tick."
      continue
    fi

    log "CI+Smoke green. Pulling $branch and restarting daemon."
    git -C "$REPO_DIR" checkout "$branch" 2>&1 | tee -a "$LOG"
    git -C "$REPO_DIR" pull --ff-only 2>&1 | tee -a "$LOG"

    if ! start_daemon; then
      log "Daemon failed to start on $remote_sha. Rolling back."
      rollback
      continue
    fi

    log "Now running $branch $(current_sha). All systems normal."
    break  # only pull from first branch that has new validated work this tick
  done
done
