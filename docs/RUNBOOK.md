# Runbook

Operational procedures for the AI Runtime Monitor / Vigil project. Live
document — append as new procedures land.

---

## Emergency rollback

If a merge to `main` lands and the daemon is broken, the dashboard
won't load, or sessions stop populating:

### Step 1 — identify the bad merge

```bash
git log --oneline -10
# Find the suspicious merge SHA (usually the most recent one)
```

Cross-check by running `make smoke` locally if available, or
`pip install -e ".[dev]" && ai-monitor --start --daemon` and curl
`http://localhost:9081/api/stats`.

### Step 2 — revert (preserves history, preferred)

```bash
git revert <bad-sha>
HTTPS_PROXY= git push origin main
```

This creates a revert commit. Audit trail intact. Subsequent fixes can
re-cherry-pick anything safe from the bad merge.

### Step 3 — nuclear (only if revert fails)

If the merge introduced corrupted state that `git revert` can't cleanly
undo (e.g. binary file conflict that revert mishandles):

```bash
# 1. Identify the last known good tag — for the C1-C4 series this is `pre-c1c4`
git fetch origin --tags
git checkout pre-c1c4
git log --oneline -1
# Verify it's the right commit

# 2. Force-with-lease push — refuses if main moved since you checked
HTTPS_PROXY= git push --force-with-lease origin pre-c1c4:main
```

**Never** use `--force` without `--with-lease`. Always re-verify with
`git log origin/main -3` immediately after.

### Step 4 — incident note

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

## Known-good tags

| Tag        | Commit on   | Meaning                                          |
|------------|-------------|--------------------------------------------------|
| `pre-c1c4` | `4275dc4`   | Last known good main before C1-C4 fix series.    |

When a new "good baseline" milestone lands (a release tag, a successful
integration → main merge), add it here.

---

## Integration branch workflow (Phase 3A onwards)

For multi-fix series where the combined behavior must be validated
before main sees it (per `docs/CC_DISPATCH_phase_3_safety_addendum.md`
Guardrail 2):

```
main
  ↑ one PR after CI + Smoke + manual antfooding
integration/phase-3a   ← integration branch
  ↑ each Cx PR runs CI + Smoke independently
security/c1-bcrypt   security/c2-xss-esc   security/c3-sync-fail-open   security/c4-osascript-injection
```

Rules:
1. Each `security/cN-*` PR targets `integration/phase-3a`, **not** `main`.
2. Each PR's CI + Smoke must be green to merge into integration.
3. When all four are merged: CI + Smoke run again on the combined
   integration state. Antfooding pass (per Guardrail 4) is mandatory.
4. Only then open ONE PR from `integration/phase-3a` → `main`. That PR
   carries the antfooding evidence in its body.
5. After main merge: delete `integration/phase-3a`.

---

## Antfooding pass

Per `docs/CC_DISPATCH_phase_3_safety_addendum.md` Guardrail 4: any
integration → main PR for a security/correctness series must include
antfooding evidence in `docs/ANTFOODING_LOG.md`.

Procedure:
1. `git checkout integration/phase-3a && git pull`
2. `pip install -e ".[dev]"` in the local venv
3. `ai-monitor --start` (NOT `--daemon` — interactive view for visual checks)
4. Open `http://localhost:9081/?token=$(cat ~/claude_watch_output/.dashboard_token)`
5. Verify each tab loads without console errors
6. Run a short Claude Code session (~5 min of typical work) and confirm
   sessions populate, alerts fire on synthetic triggers, no log errors
7. Write the entry in `docs/ANTFOODING_LOG.md` with the integration SHA

If anything regresses against the baseline entry, do NOT open the
integration → main PR. File an issue against the offending Cx PR and
fix on integration first.
