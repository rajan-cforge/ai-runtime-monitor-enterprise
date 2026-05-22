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
