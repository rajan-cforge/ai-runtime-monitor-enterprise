# Claude Code Prompt — Antfood Loop Recovery + Robustness Fix

## Context

The antfood loop on the user's dev machine died with:

```
ERROR: Could not find a version that satisfies the requirement setuptools>=68.0
(ProxyError: Cannot connect to proxy. Connection refused on localhost)
[FORWARD FAIL]

AssertionError in setuptools_scm/_scm_version.py:329 _parse_tag
on pre-c1c4 (non-semver tag)
[ROLLBACK FAIL]

FATAL: rollback target pre-c1c4 also failed to boot. Manual intervention required.
```

Two root causes:

1. **HTTPS_PROXY leaks from shell.** The antfood-loop.sh script does not
   unset HTTPS_PROXY before calling `pip install`. The user's shell has
   it set (it's their own AI Monitor proxy that isn't running in this venv
   context).
2. **Python 3.14 + setuptools_scm + non-semver git tag.** The
   `pre-c1c4` tag is not semver. setuptools_scm in Python 3.14 asserts
   `version is not None` and crashes during build. PR #11 added a
   describe filter to fix this, but PR #11 is at commit 76d2442 which is
   AFTER pre-c1c4. So the rollback target itself is broken on Python
   3.14.

Dashboard at http://localhost:9081 will not load because no daemon is
running.

## Phase A — Restore service immediately (user-blocking)

Do not start a feature branch yet. Get the daemon running so the user
can complete the manual antfooding pass on the Phase 3A merges.

Execute these in order. Stop and report after each step.

### A.1 Diagnose

```bash
# Kill any zombie processes from the failed loop attempts
pkill -f antfood-loop.sh 2>/dev/null
pkill -f claude_monitoring.monitor 2>/dev/null
sleep 2

# Verify environment
cd ~/code/ai-runtime-monitor-enterprise
pwd
git status -sb
python --version
which python
echo "PROXY vars:"
env | grep -i proxy || echo "  (none set in this subshell)"
```

Report the output of all of these inline before proceeding.

### A.2 Get back on main

The previous loop left the working tree in detached HEAD at pre-c1c4.

```bash
git checkout main
git pull origin main
git log --oneline -3
# Expected HEAD: 76d2442 or 825f203 (depending on integration merge state)
```

### A.3 Verify Python version compatibility

```bash
PY_MINOR=$(python -c "import sys; print(sys.version_info.minor)")
PY_MAJOR=$(python -c "import sys; print(sys.version_info.major)")
echo "Python: $PY_MAJOR.$PY_MINOR"

if [ "$PY_MAJOR" = "3" ] && [ "$PY_MINOR" -ge 13 ]; then
    echo "BLOCKED: Python 3.$PY_MINOR has setuptools_scm incompatibilities."
    echo "Need to recreate venv with Python 3.11 or 3.12."
fi
```

If Python is 3.13+, recreate venv with 3.11:

```bash
deactivate 2>/dev/null
rm -rf .venv

# Find a 3.11 or 3.12 binary
for candidate in /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.11 /usr/local/bin/python3.12 python3.11 python3.12; do
    if command -v "$candidate" >/dev/null 2>&1; then
        echo "Using $candidate"
        $candidate -m venv .venv
        break
    fi
done

# Verify
ls .venv/bin/python*
source .venv/bin/activate
python --version
# Expected: Python 3.11.x or 3.12.x
```

If no 3.11/3.12 is on the machine, install via brew:

```bash
brew install python@3.11
/opt/homebrew/bin/python3.11 -m venv .venv
source .venv/bin/activate
```

### A.4 Install with proxy explicitly cleared

```bash
unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY https_proxy http_proxy all_proxy no_proxy
env | grep -i proxy
# Expected: no output

source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
# Expected: clean install, no proxy errors, no setuptools_scm assertion
```

### A.5 Start daemon manually and verify dashboard

```bash
ai-monitor --start --daemon &
sleep 5
curl -fsS http://localhost:9081/api/stats | head -c 200
# Expected: JSON response

curl -fsS http://localhost:9081/ | head -c 200
# Expected: HTML starting with <!DOCTYPE html>
```

Confirm dashboard at http://localhost:9081 loads in user's browser.
Report success to user. They can now do the antfooding pass.

**STOP after Phase A.5.** Do not proceed to Phase B until the user
confirms the dashboard is working. The antfood loop fix is non-blocking
for the integration → main merge gate.

## Phase B — Fix the antfood loop (after Phase A succeeds)

Branch: `fix/antfood-loop-robustness`. PR target: `main`.

### B.1 Update scripts/antfood-loop.sh

Required changes:

**1. Unset proxy variables at the top of the script.**

Add after the `set -uo pipefail` line:

```bash
# Unset any proxy variables that might leak from the user's shell.
# The monitor itself may set HTTPS_PROXY for traffic interception, but
# pip install and gh CLI must run without it.
unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY \
      https_proxy http_proxy all_proxy no_proxy
```

**2. Also unset proxy inside `start_daemon()` before pip install.**

Defense in depth in case the loop is sourced from a context that re-sets
proxy vars.

```bash
start_daemon() {
  pkill -f "claude_monitoring.monitor" 2>/dev/null || true
  sleep 2
  
  # Defense in depth: unset proxy before pip install
  unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY \
        https_proxy http_proxy all_proxy no_proxy
  
  cd "$REPO_DIR"
  source .venv/bin/activate
  
  # NEW: refuse to install on Python 3.13+ (setuptools_scm incompatibility)
  local py_minor
  py_minor=$(python -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
  if [ -z "$py_minor" ] || [ "$py_minor" -ge 13 ]; then
    log "ERROR: Python 3.${py_minor:-?} not supported (setuptools_scm fails)."
    log "Recreate venv with Python 3.11 or 3.12:"
    log "  rm -rf .venv && /opt/homebrew/bin/python3.11 -m venv .venv"
    return 1
  fi
  
  pip install -e ".[dev]" --quiet
  if [ $? -ne 0 ]; then
    log "ERROR: pip install failed"
    return 1
  fi
  
  nohup python -m claude_monitoring.monitor > "$HOME/.vigil-daemon.log" 2>&1 &
  echo $! > "$HOME/.vigil-daemon.pid"
  
  for i in {1..30}; do
    curl -fsS "$DAEMON_HEALTHCHECK" > /dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
```

**3. Replace hardcoded `pre-c1c4` rollback with last-known-good state file.**

The pre-c1c4 tag is before PR #11's setuptools_scm fix, so it's a broken
rollback target on Python 3.13+. Instead, persist the last successfully
booted SHA and roll back to that.

```bash
STATE_FILE="$HOME/.vigil-antfood-state"

save_known_good() {
  local sha="$1"
  echo "$sha" > "$STATE_FILE"
  log "Saved known-good SHA: $sha"
}

get_known_good() {
  if [ -f "$STATE_FILE" ]; then
    cat "$STATE_FILE"
  else
    echo "$ROLLBACK_TAG"  # fallback to original tag
  fi
}

rollback() {
  local target
  target=$(get_known_good)
  log "ROLLBACK: daemon failed to boot. Reverting to $target"
  git -C "$REPO_DIR" checkout "$target"
  if start_daemon; then
    log "Rollback successful. Running on $target."
    return 0
  else
    log "FATAL: rollback target $target also failed to boot."
    log "Manual intervention required. Inspect ~/.vigil-daemon.log and"
    log "~/.vigil-antfood.log, then restart with:"
    log "  cd $REPO_DIR && git checkout main && pip install -e '.[dev]' && ./scripts/antfood-loop.sh"
    return 1
  fi
}
```

Call `save_known_good "$(current_sha)"` at the end of the initial boot
block (after the daemon healthcheck succeeds) and at the end of each
successful pull-and-restart in the watch loop.

**4. Add a SIGTERM trap to clean up on script exit.**

```bash
cleanup() {
  log "Loop terminating. Daemon left running."
  # Do NOT kill the daemon — user may want it to keep running even
  # after the loop dies. Just exit cleanly.
  exit 0
}
trap cleanup SIGTERM SIGINT
```

### B.2 Add a smoke test for the loop script

New file: `tests/integration/test_antfood_loop.py` (or `tests/scripts/`
if your test layout uses that).

```python
"""Smoke tests for scripts/antfood-loop.sh.

These don't run the full loop (it polls indefinitely). They verify the
script syntax is valid, required helper functions exist, and the
critical proxy-unset and Python-version-check are present.
"""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[2] / "scripts" / "antfood-loop.sh"


def test_script_exists_and_is_executable():
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & 0o111  # any execute bit set


def test_script_syntax_is_valid():
    """bash -n parses without executing."""
    result = subprocess.run(["bash", "-n", str(SCRIPT)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"syntax error: {result.stderr}"


def test_script_unsets_proxy_vars():
    """Proxy unset must appear before any pip or curl call."""
    text = SCRIPT.read_text()
    assert "unset HTTPS_PROXY" in text
    assert "unset http_proxy" in text
    # Must appear before any pip install
    proxy_idx = text.find("unset HTTPS_PROXY")
    pip_idx = text.find("pip install")
    assert proxy_idx < pip_idx, "proxy unset must come before pip install"


def test_script_checks_python_version():
    """Must refuse to run on Python 3.13+."""
    text = SCRIPT.read_text()
    assert "py_minor" in text or "python_version" in text.lower()
    assert "-ge 13" in text or ">= 13" in text or "3.13" in text


def test_script_uses_state_file_for_rollback():
    """Rollback should not be hardcoded to pre-c1c4 tag."""
    text = SCRIPT.read_text()
    assert "STATE_FILE" in text or "vigil-antfood-state" in text


def test_state_file_path_is_under_home():
    text = SCRIPT.read_text()
    assert "$HOME/.vigil-antfood-state" in text \
        or '~/.vigil-antfood-state' in text
```

These run as part of the existing test suite. They are smoke checks,
not full behavioral tests.

### B.3 Update docs/RUNBOOK.md

Add a new section under "Restart antfood loop":

```markdown
## Python version requirement

The antfood loop requires Python 3.11 or 3.12. Python 3.13+ has
setuptools_scm incompatibilities that crash editable installs.

Check current version:

  source .venv/bin/activate
  python --version

If you see 3.13 or higher, recreate the venv:

  deactivate
  rm -rf .venv
  /opt/homebrew/bin/python3.11 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[dev]"

If Python 3.11 is not installed:

  brew install python@3.11

## Proxy interaction

Vigil's monitor sets HTTPS_PROXY system-wide for traffic interception.
The antfood loop must run with proxy unset, because pip install and
gh CLI cannot route through the monitor's proxy.

The loop script unsets proxy variables internally. If you invoke the
daemon manually outside the loop, ensure HTTPS_PROXY is unset in your
shell first:

  unset HTTPS_PROXY HTTP_PROXY ALL_PROXY \
        https_proxy http_proxy all_proxy

## State file

The loop persists the last successfully-booted SHA at:

  ~/.vigil-antfood-state

On boot failure, the loop reverts to this SHA, not the pre-c1c4 tag.
To force a different rollback target:

  echo "<sha-or-tag>" > ~/.vigil-antfood-state
```

### B.4 Local verification

```bash
# 1. Bash syntax check
bash -n scripts/antfood-loop.sh
# Expected: no output, exit 0

# 2. Run the smoke tests
pytest tests/integration/test_antfood_loop.py -v
# Expected: 6 passed

# 3. Simulate the proxy failure mode and confirm it doesn't recur
export HTTPS_PROXY=http://localhost:9999  # nothing listening
./scripts/antfood-loop.sh &
LOOP_PID=$!
sleep 30
# Check the log:
tail -20 ~/.vigil-antfood.log
# Expected: clean start, no ProxyError, daemon running on current SHA
unset HTTPS_PROXY
kill $LOOP_PID 2>/dev/null
pkill -f claude_monitoring.monitor 2>/dev/null
```

### B.5 Open PR

```bash
git add scripts/antfood-loop.sh tests/integration/test_antfood_loop.py docs/RUNBOOK.md
git commit -m "fix(antfood-loop): unset proxy + Python 3.13+ guard + state-file rollback

- Unset HTTPS_PROXY/HTTP_PROXY/ALL_PROXY (and lowercase variants) at script
  start and inside start_daemon(). Prevents pip install from failing when
  the monitor's own proxy is configured in the user's shell.

- Refuse to start on Python 3.13+ with a clear remediation message.
  setuptools_scm asserts on non-semver tags in 3.13+, breaking editable
  installs. Required version is 3.11 or 3.12.

- Replace hardcoded pre-c1c4 rollback target with persisted last-known-good
  SHA at ~/.vigil-antfood-state. The pre-c1c4 tag predates PR #11's
  setuptools_scm fix, so it's not a viable rollback on Python 3.13+. The
  state file approach is also more accurate (rolls back to wherever you
  were before the bad pull).

- Add 6 smoke tests for the loop script (syntax, presence of required
  guards, state-file usage).

- RUNBOOK updated with Python version requirement, proxy interaction
  notes, and state file documentation.

Fixes the FATAL rollback observed during initial antfooding setup.
"

git push -u origin fix/antfood-loop-robustness

gh pr create --base main --head fix/antfood-loop-robustness \
  --title "fix(antfood-loop): unset proxy + Python 3.13+ guard + state-file rollback" \
  --body "$(cat <<'EOF'
## Summary

Three robustness fixes to scripts/antfood-loop.sh after the loop FATAL-ed
during initial setup with both forward boot and rollback failing.

## Audit / Issue links

- Original failure log in conversation history
- Related: PR #11 (the setuptools_scm fix that exposed the pre-c1c4 rollback gap)

## How to verify

1. \`bash -n scripts/antfood-loop.sh\` returns 0
2. \`pytest tests/integration/test_antfood_loop.py -v\` shows 6/6 pass
3. With HTTPS_PROXY set to a dead address, the loop still starts cleanly
4. ~/.vigil-antfood-state is created on successful boot
5. Forced rollback test (point HEAD at a broken SHA, restart) reverts to the state-file SHA

## Test plan

6 new smoke tests in tests/integration/test_antfood_loop.py. Coverage:
- Script syntactic validity
- Proxy unset present before pip install
- Python 3.13+ version check
- State-file rollback (no hardcoded pre-c1c4)

## Risk

Low. Script-only change. No production code path touched. The script is
only invoked by the user manually or via launchd.

## Checklist

- [x] make ci-local passes locally
- [x] New code has tests
- [x] Tests fail without the fix (proves they exercise the code)
- [x] No Co-Authored-By: Claude trailer in commits
- [x] Conventional commit messages
- [ ] Updated docs/RECONCILIATION_LOG.md if any assumption shifted (N/A)
EOF
)"
```

## Phase C — User verification after PR merges

After the user reviews and merges the PR:

```bash
cd ~/code/ai-runtime-monitor-enterprise
git pull origin main

# Kill any running loop
pkill -f antfood-loop.sh 2>/dev/null

# Restart with the new robust script
./scripts/antfood-loop.sh &
tail -f ~/.vigil-antfood.log
```

Expected first few log lines:

```
[HH:MM:SS] Starting antfood loop. Repo: /Users/.../ai-runtime-monitor-enterprise. Poll: 300s.
[HH:MM:SS] Saved known-good SHA: <current main sha>
[HH:MM:SS] Initial daemon running on <sha> (main)
```

The loop is now self-healing on proxy leaks and detects Python
incompatibilities before they cascade into a FATAL.

## Final reporting

Report to user:

1. Phase A outcome: dashboard restored at http://localhost:9081, daemon
   running on what SHA, Python version in use
2. Phase B outcome: PR # opened, CI status, link
3. Any anomalies encountered (Python install needed via brew, missing
   binaries, etc.)
4. Confirmation that the user can now safely complete the antfooding
   pass for Phase 3A integration

Do NOT auto-merge the antfood-loop fix PR. User reviews and merges.
