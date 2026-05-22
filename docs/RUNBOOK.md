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

Write `docs/incidents/<YYYY-MM-DD>-<short-slug>.md`:

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
