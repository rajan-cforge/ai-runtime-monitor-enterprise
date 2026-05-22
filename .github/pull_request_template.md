## Summary
<!-- one paragraph: what changed and why -->

## Audit / Issue links
<!-- links to docs/AUDIT_2026-05-21.md sections, GitHub issues -->

## How to verify
<!-- commands a reviewer can run locally -->

```bash
# example
make ci-fast
pytest tests/path/to/regression_test.py
```

## Test plan
<!-- tests added, coverage delta, expected mutation score -->

## Risk
<!-- what could break, blast radius -->

## Checklist
- [ ] `make ci-local` passes locally (or `pytest -q` until Q1 gates land)
- [ ] New code has tests
- [ ] Tests fail without the fix (proves they exercise the code)
- [ ] No `Co-Authored-By: Claude` trailer in commits
- [ ] Conventional commit messages (`<type>(<scope>): <subject>`)
- [ ] Updated `docs/RECONCILIATION_LOG.md` if any assumption shifted
- [ ] Grader subagent verdict attached (for sprint-lane PRs only)

---

## C3-specific: caller audit (required if this PR touches `_sanitize_string`)

<!-- Delete this section if the PR doesn't touch sync.py::_sanitize_string. -->

Per `docs/CC_DISPATCH_phase_3_continuous_antfooding.md` Step 5. Use
codebase-memory-mcp `trace_call_path` with `function_name=_sanitize_string`
(direction = callers) to enumerate every caller. For each, record how
the return value is used and verdict.

| File:line | How return value is used                 | Verdict |
|-----------|------------------------------------------|---------|
|           |                                          | HANDLES_EMPTY / PASSES_THROUGH |

If any caller is `PASSES_THROUGH`, fix it in this same PR. Do not
merge until every caller is `HANDLES_EMPTY`.
