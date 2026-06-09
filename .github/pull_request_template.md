## Summary

(One-paragraph description of what this PR does and why.)

## Criticality (required — select one)

- [ ] **C0** docs-only, no code paths affected
- [ ] **C1** tests or scripts, no production behavior
- [ ] **C2** feature addition, no security implication
- [ ] **C3** feature with security implication or hot-path touch
- [ ] **C4** auth, secrets, crypto, trust boundary

Human diff review is required for **C4 on the security axis** (auth / secrets / crypto /
trust boundary / new off-box data flow). A PR high-tier only on the architecture axis is
review-satisfied by architect-pass + green CI + vigil-loop APPROVE + empirical evidence +
no R0 touched. See `CLAUDE.md` → Criticality classification.

## Hygiene (required)

- [ ] No AI attribution anywhere — no `Co-Authored-By: Claude`, no "Generated with Claude
  Code", no `claude.com/claude-code` link, no 🤖 line, in commits OR this PR description.

## Spec coverage

- [ ] Touched protocols have conformance tests
- [ ] Touched authentication paths have updated `docs/spec/functional/security.md`
- [ ] Touched APIs have updated `docs/spec/openapi.yaml` and `docs/spec/API-CONTRACTS.md`
- [ ] Touched DB schema has updated `docs/ARCHITECTURE.md` and `docs/spec/DATA-CLASSIFICATION.md`
- [ ] New dependencies have `docs/spec/dependency-rationale.md` entry
- [ ] CLAUDE.md mandatory patterns followed (no `==` for tokens, no `shell=True`, parameterized SQL, etc.)

## Derived decisions

Architectural decisions made during this PR that weren't in the existing spec, with rationale:

- (List items, or write "none")

## Testing

- [ ] Unit tests added or updated
- [ ] Integration tests pass locally
- [ ] Hot-path changes measured (if applicable)

## Known limitations or deferred work

Anything this PR intentionally does NOT cover, with rationale and target version or follow-up plan:

- (List items, or write "none")

This section exists per CLAUDE.md's source-honesty rule. If the PR introduces capabilities with known gaps, document them here rather than pretending they don't exist.

## Threat surface

Trust boundaries this change crosses (from `docs/spec/THREAT-MODEL.md`):

- [ ] B1 — User ↔ Dashboard
- [ ] B2 — Daemon ↔ DB
- [ ] B3 — Daemon ↔ Control Plane
- [ ] B4 — Proxy ↔ AI APIs
- [ ] B5 — Browser Extension ↔ Daemon
- [ ] None (purely internal change)

---

## C3-specific: caller audit (required if this PR touches `_sanitize_string`)

<!-- Delete this section if the PR doesn't touch sync.py::_sanitize_string. -->

Per the C3 fail-closed sanitization discipline (see `docs/spec/functional/sync.md`). Use codebase-memory-mcp `trace_call_path` with `function_name=_sanitize_string` (direction = callers) to enumerate every caller. For each, record how the return value is used and verdict.

| File:line | How return value is used                 | Verdict |
|-----------|------------------------------------------|---------|
|           |                                          | HANDLES_EMPTY / PASSES_THROUGH |

If any caller is `PASSES_THROUGH`, fix it in this same PR. Do not merge until every caller is `HANDLES_EMPTY`.
