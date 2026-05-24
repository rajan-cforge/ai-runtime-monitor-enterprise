# Vigil operations runbook

Operational procedures for the AI Runtime Monitor / Vigil project.
Per Step 6 of `docs/CC_DISPATCH_phase_3_continuous_antfooding.md`.

---

## Emergency rollback

If `main` breaks post-merge — daemon won't boot, dashboard blank,
sessions stop populating:

### 1. Identify the bad SHA

```bash
git log --oneline -10
# Find the suspicious merge SHA (usually the most recent one)
```

Cross-check by running the smoke workflow locally, or
`ai-monitor --start --daemon` and `curl http://localhost:9081/api/stats`.

### 2. Soft revert (preferred — preserves history)

```bash
git revert <bad-sha>
HTTPS_PROXY= git push origin main
```

Creates a revert commit. The antfood loop on the dev machine
auto-detects within 5 min, pulls the revert, and restarts the
daemon on a known-good state.

### 3. Nuclear (only if revert fails)

If the merge introduced state that `git revert` can't cleanly undo:

```bash
git fetch origin --tags
git checkout pre-c1c4
git log --oneline -1   # verify
HTTPS_PROXY= git push --force-with-lease origin pre-c1c4:main
```

**Never** use `--force` without `--with-lease`. Re-verify with
`git log origin/main -3` immediately after.

### 4. Antfood loop self-heals

The continuous loop polls every 5 min and re-pulls the corrected
state automatically. No manual intervention on the dev machine
needed unless you can't wait 5 min.

### 5. Incident note

Real-credential incidents and operational records go in **local private
notes** (`~/Documents/vigil-notes/incidents/<YYYY-MM-DD>-<slug>.md`),
not in the public repo. Only aggregated, value-free learnings come
into the repo — for example, "on Day 1 we detected N exposures across
M categories" — never the credential values, vendor names, or
session identifiers.

A non-credential public-repo incident (e.g. a CI regression, a build
break) may still go under `docs/incidents/<YYYY-MM-DD>-<slug>.md`
with this template:

```markdown
# Incident: <short title> — <date>

## Symptom
What broke. Screenshot if applicable.

## Cause
The merge SHA and the line of code at fault.

## Recovery
What was done (revert / reset). Time to recovery.

## Prevention
What guardrail would have caught this. File the follow-up.
```

---

## Restart antfood loop

If the auto-pull loop dies or you want to restart it manually:

```bash
# Plain script invocation:
pkill -f antfood-loop.sh
~/code/ai-runtime-monitor-enterprise/scripts/antfood-loop.sh &
```

Or via launchd (if installed via the plist template):

```bash
launchctl unload ~/Library/LaunchAgents/com.gocloudforge.vigil-antfood.plist
launchctl load ~/Library/LaunchAgents/com.gocloudforge.vigil-antfood.plist
```

---

## Python version requirement

The antfood loop requires **Python 3.11 or 3.12**. Python 3.13+ has a
`setuptools_scm` incompatibility with non-semver tags (e.g. `pre-c1c4`)
that crashes editable installs with an `AssertionError` deep in
`vcs_versioning/_scm_version.py`. The loop script refuses to run on
3.13+ and prints a remediation message.

Check current version:

```bash
cd ~/code/ai-runtime-monitor-enterprise
source .venv/bin/activate
python --version
```

If you see 3.13 or higher, recreate the venv:

```bash
deactivate
rm -rf .venv
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

If Python 3.12 is not installed:

```bash
brew install python@3.12
```

---

## Proxy interaction

Vigil's monitor sets `HTTPS_PROXY` system-wide for traffic interception.
The antfood loop must run with proxy **unset**, because `pip install`
and `gh` cannot route through the monitor's proxy (the proxy is what
the loop is restarting; if it's down, the install fails with a
`ProxyError: Cannot connect to proxy` and the rollback also fails).

The loop script unsets proxy variables internally — both at the top
and again inside `start_daemon()` (defense in depth). If you invoke
the daemon manually outside the loop, unset proxy first in your
shell:

```bash
unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY \
      https_proxy http_proxy all_proxy no_proxy
```

---

## State file

The loop persists the last successfully-booted SHA at:

```
~/.vigil-antfood-state
```

On boot failure, the loop reverts to this SHA, NOT the `pre-c1c4` tag.
The original tag predates the `setuptools_scm` install fix (PR #11)
so it's no longer a viable rollback target on Python 3.13+ machines.
The state file approach is also more accurate — it rolls back to
whatever was running before the bad pull, not an arbitrary historical
checkpoint.

To force a different rollback target:

```bash
echo "<sha-or-tag>" > ~/.vigil-antfood-state
```

If no state file exists yet (first run on a clean machine), the loop
falls back to `$ROLLBACK_TAG` (default: `pre-c1c4`).

---

## Check what's running

```bash
ps aux | grep claude_monitoring
tail -50 ~/.vigil-daemon.log
tail -50 ~/.vigil-antfood.log
cd ~/code/ai-runtime-monitor-enterprise && git log --oneline -1
```

---

## Force re-pull (manual override)

If the antfood loop is waiting on CI to clear but you want to pull
right now (e.g. to test a fresh integration before CI catches up):

```bash
cd ~/code/ai-runtime-monitor-enterprise
git fetch --all --tags
git checkout integration/phase-3a   # or main
git pull --ff-only
pkill -f claude_monitoring.monitor
source .venv/bin/activate            # repo convention; legacy clones use venv/
pip install -e ".[dev]" --quiet
touch ~/claude_watch_output/.setup_complete
ai-monitor --start --daemon
```

---

## Known-good tags

| Tag        | Commit on   | Meaning                                          |
|------------|-------------|--------------------------------------------------|
| `pre-c1c4` | `4275dc4`   | Last known good main before C1-C4 fix series.    |

Add a new entry here whenever a new release milestone lands on `main`.

---

## Integration branch workflow (Phase 3A onwards)

```
main
  ↑ one PR after CI + Smoke + manual antfood pass
integration/phase-3a
  ↑ each Cx PR runs CI + Smoke independently
security/c1-bcrypt   security/c2-xss-esc   security/c3-sync-fail-open   security/c4-osascript-injection
```

Rules:
1. Each `security/cN-*` PR targets `integration/phase-3a`, **not** `main`.
2. Each PR's CI + Smoke must be green to merge into integration.
3. When all four are merged: CI + Smoke run again on the combined
   integration state. The antfood loop auto-pulls and restarts.
4. User manually antfoods for ~30 min, writes evidence in
   `docs/ANTFOODING_LOG.md`.
5. Only then open ONE PR from `integration/phase-3a` → `main`. That PR
   carries the antfooding evidence in its body.
6. After main merge: delete `integration/phase-3a`.

---

## C3 caller-audit requirement

PRs that touch `src/claude_monitoring/sync.py::_sanitize_string` must
fill in the caller-audit table in the PR template (under the
"C3-specific" section). Empty-return is the failure sentinel; every
caller must treat `""` as rejection, not a valid sanitized value.

Use codebase-memory-mcp's `trace_call_path` to enumerate callers; do
not rely on grep alone, which misses indirect references and
inheritance.

---

## Test isolation

Tests for CLI scripts must NOT use module-level `importlib.exec_module`
on the script under test. The script's import-time side effects
(`sys.modules` mutation, `cwd` changes, env reads) execute during
pytest's collection phase and silently perturb the import resolution
of unrelated tests collected later in the session.

The failure mode is non-obvious: tests still pass individually, the
total pass/skip counts match, but cumulative coverage drops in modules
the test doesn't touch — because some other test's `import` now
resolves to a different code path. We hit this on the coverage-ratchet
PR itself: `tests/test_coverage_ratchet.py` exec'd
`scripts/coverage_ratchet.py` at module load, and `wizard.py` lost
49 hits, with smaller drops in `monitor.py` / `security.py` /
`status.py`. Same denominator, same skip count — pure pollution.

Use `subprocess.run([sys.executable, str(SCRIPT), ...])` to invoke
scripts in an isolated process. If you genuinely need to call an
internal function rather than exercise the CLI surface, wrap the
`exec_module` call in a fixture that snapshots and restores
`sys.modules` (and any other mutated state) around it — never at
module top-level.

---

## Coverage ratchet scope

The ratchet (`scripts/coverage_ratchet.py`, run on every PR via
`.github/workflows/ci.yml`) gates on **per-file** coverage drops of
files the PR modifies under `src/`, not overall suite coverage. The
overall delta is reported for visibility but only fails the gate if it
exceeds 5% (catastrophic regression).

Reason: two consecutive pytest invocations in the same CI job
(once on the base branch, once on the PR branch) can produce
deterministic, non-test-related coverage shifts of ~1% on unrelated
modules. We observed `wizard.py` losing 49 hits on the PR side of
every PR even when the PR didn't touch `src/` at all — likely a
coverage instrumentation quirk specific to switching git refs mid-job.

Per-file gating sidesteps this entirely: an unrelated phantom drop
on a file the PR didn't modify can't block a merge. If the PR
genuinely regresses coverage on a file it touches, the gate fires
as intended.
