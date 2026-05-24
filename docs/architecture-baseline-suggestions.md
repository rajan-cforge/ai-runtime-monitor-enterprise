# Architecture baseline — suggestions from the last 10 PRs

Generated 2026-05-23 by the architect-reviewer agent in one-shot baseline mode after Layer 8 install (PR #30, commit `5febb37`). These are GATHERED suggestions, not triaged issues — input for a future Phase 3F refactor sprint. No issues created; no code modified.

Scope: structural / design / API-choice observations only. Mechanical concerns (style, coverage, file/function size) are intentionally excluded — those gates already exist (ruff, ratchet, `scripts/check_*size.py`).

## Cross-cutting themes

1. **`dict`-as-record leaks through new abstractions.** The just-installed `Finding` Protocol still uses `context: dict` (no `[str, Any]`, no `TypedDict`). The CI workflows (`ci-security.yml`, `ci-supply-chain.yml`) and the secrets baseline equivalent likewise rely on untyped shapes. Once the Phase 3F detector/collector Protocols land, the right contract is a `TypedDict` (or a frozen dataclass per scanner) for each `context` shape, with a discriminator on `rule_id`. Direction: define a `FindingContext` union of `TypedDict`s keyed by scanner family before adding the second concrete scanner.

2. **Closed value sets are encoded as strings + docstring comments rather than `StrEnum`.** Present in `Finding.severity` (PR #30), in CI verdict labels (`PASS_WITH_NOTES`/`SUGGEST_REFACTOR`/`BLOCK_ARCHITECTURE` in the agent definitions), and implicitly in the coverage-ratchet `status = "ok"`/`"FAIL"` string in `scripts/coverage_ratchet.py`. Direction: introduce `class Severity(StrEnum)` in `protocols/scanner.py`, then audit downstream string-compare sites.

3. **Thresholds and tolerances are hardcoded module constants across the new gate scripts.** `MAX_LINES = 5500`, `MAX_LINES = 400`, `LINE_DROP_TOLERANCE = 0.1`, `BRANCH_DROP_TOLERANCE = 0.5`, `OVERALL_DROP_HARD_LIMIT = 5.0`. Each is intentional and documented, but they live in five separate scripts. Direction: when a fourth script lands, lift them into a single `scripts/_gates_config.py` (or `pyproject.toml [tool.vigil.gates]`) so the ratchet policy is one file, not five.

4. **Subprocess + git invocations are scattered.** `coverage_ratchet.py` shells out to `git diff --name-only`; CI workflows do the same in YAML; pre-commit's `detect-secrets` has its own baseline path. A small `vigil.git_helpers` module that wraps `git diff`, `git rev-parse`, and `BASE_REF` resolution (with `subprocess.run([..., shell=False])` per the api-choices rubric) would centralize the pattern before more scripts add their own copy.

5. **Placeholder Protocols (`collector.py`, `detector.py`) document the gap honestly but are not enforceable today.** The conformance meta-test correctly skips empty modules, but there is no lint that flags new classes named `*Collector` / `*Detector` outside the future Protocol. Direction: in Phase 3F, when the Protocols land, the existing `test_protocol_inventory.py` pattern auto-extends. Until then, the placeholders should not accumulate.

## Per-PR suggestions

### PR #30 — feat(review): architect + performance reviewer agents (Layer 8)

- `src/claude_monitoring/protocols/scanner.py`: `Finding.context: dict` should be `dict[str, Any]` or a TypedDict. The architecture rubric flags dict-as-record; tighten once actual context shapes are known from usage.
- `src/claude_monitoring/protocols/scanner.py`: `Finding.severity: str` with valid values in a docstring comment should be a `StrEnum`. The api-choices rubric prefers enums for closed value sets.
- `tests/architecture/test_scanner_conformance.py:82-84`: conformance via `hasattr(cls, ...)` is a string-compare on member names — it accepts a class whose `scan` attribute is a non-callable. Given `Scanner` is `@runtime_checkable`, the test can additionally assert `callable(getattr(cls, "scan"))` (small follow-up).
- `KNOWN_PROTOCOL_EXEMPT` in `test_scanner_conformance.py` is a frozenset literal embedded in the test file. As more exemptions accumulate, this becomes a hidden allowlist. Direction: move the exemption set into a top-level constant in `protocols/__init__.py` (or `protocols/_exemptions.py`) with one-line rationales next to each entry, so the Protocol package owns its own debt ledger.
- `protocols/__init__.py` re-exports `Finding` and `ScannerHealth` alongside `Scanner`. Conceptually the dataclasses are wire types, not Protocols. Consider a sub-namespace `protocols.types` for the wire shapes vs `protocols` proper for the Protocol classes — keeps "is this a contract?" obvious at import sites.

### PR #29 — ci(quality): add ci-security.yml + ci-supply-chain.yml

- License-gate uses a `grep -iE` pipeline on `licenses.csv`. The exclude-LGPL second `grep` is fragile: a license string like `"GPL-2.0-only WITH Classpath-exception-2.0"` slips through (it's GPL, but the prose match still excludes "GNU Lesser" — which it doesn't contain). Direction: parse CSV with a small Python script invoked from the workflow; one column, one decision, deterministic.
- `pip-audit` runs with `continue-on-error: true` and a TODO to remove it after a deps-upgrade PR. This is correct posture for now, but leaves a "soft gate" that may stay soft indefinitely if no one removes the flag. Direction: add an explicit issue or a `# REMOVE-BY: 2026-Q3` comment so the workflow itself is self-documenting about when it should harden.
- `bandit` exists in both `ci.yml` and `ci-security.yml` with the same suppression set. The commit message acknowledges this. Pulling the bandit invocation into a reusable workflow (`.github/workflows/_bandit.yml` with `workflow_call`) would remove the duplication and ensure suppressions are edited in one place.

### PR #28 — feat(quality): file/function size ratchets + functional-coverage nudge

- The three scripts (`check_file_size.py`, `check_function_size.py`, `check_functional_coverage.py`) have near-identical `main(argv)` + `check(roots)` + "PASS/FAIL/WARN print" structure. Direction: a tiny `scripts/_gate_runner.py` that takes a `Callable[[list[Path]], list[Violation]]` plus a label and handles I/O. The substance of each gate becomes ~20 lines.
- `check_function_size.py` walks the AST with `ast.walk` and treats every `FunctionDef`/`AsyncFunctionDef` independently, which is correct for length but means a 500-line class with a 450-line method reports only the method. That's fine, but the docstring's "Lambda" comment is stale (lambdas aren't actually checked). Tighten the docstring to match behavior.
- `check_functional_coverage.py` excludes `__init__.py` and `__main__.py` only. Real exclusion candidates (pure data modules, constants) are mentioned in the docstring but not implemented. Either drop the docstring sentence or implement a tiny `EXCLUDE_PATTERNS` list (`*_constants.py`, `_types.py`) so the warn list shrinks to actionable items.

### PR #27 — feat(ratchet): per-file coverage gate

- `coverage_ratchet.py` parses cobertura XML with `xml.etree.ElementTree`. For a CI-only tool that's fine, but the script treats missing `branch-rate` as `0.0` silently — which makes a base run with no branch data (older configs, mentioned in the docstring) look like a 100% branch-rate drop on the PR side. Direction: when `branch-rate` is missing on EITHER side, skip the branch comparison rather than coercing. Currently the script handles "missing in both" but not "missing in one".
- The function `ratchet(base_path, pr_path, changed)` mixes I/O (`print`), parsing, and decision logic. Splitting into `compute_deltas(...) -> RatchetResult` (pure) + `print_result(result)` would make the script unit-testable without subprocess (the test file currently runs the script as a subprocess for every case, which is correct given the current shape, but masks the pure decision-logic surface).
- `read_changed_files` falls back to `git diff` when no file argument is provided. The fallback shells out at runtime, which is fine for CLI but a foot-gun if the script is imported as a library. Per the architecture rubric "no I/O at deep call sites", consider injecting the changed-files set rather than computing it inside the module.

### PR #26 — infra: pre-public cleanup — remove personal notes, add LICENSE, fix presentation

Docs/infra cleanup. No architectural concerns; substance is removing private operational notes and switching license metadata. The two test-fixture renames (real-format AKIA key → fake pattern) are good hygiene — confirms the detection pipeline relies on shape, not on specific values.

### PR #23 — infra(q1): Makefile composite targets + pre-commit Q1 hooks + secrets baseline

- The Makefile uses `$(shell ...)` to auto-detect Python at parse time. That runs on every `make` invocation, including pure-display targets like `help`. Inexpensive today, but if more `$(shell ...)` calls accumulate, `make help` slows. Direction: lazy-evaluate (`PYTHON ?= ...` + functions) or accept the cost and add a comment to the top of the file.
- `ci-fast` / `ci-local` / `ci-full` define a clear ratchet of gates, but `ci-full` includes `coverage` which itself runs the full test suite again (after `ci-local` already did via `test`). Direction: split `coverage` into "instrument" and "report" so `ci-full` doesn't double-run.
- `.pre-commit-config.yaml` pins versions explicitly (good), but with no renovate / dependabot guard the pins go stale silently. Direction: when adding a dependency-update workflow, include pre-commit hook updates so `ruff v0.8.6` doesn't drift months behind.

### PR #22 — docs(sprint): mark Phase 3A DONE

Docs-only. No architectural concerns.

### PR #21 — docs(ssdlc): enforcement controls inventory

Docs-only. No architectural concerns — this document is itself the source-of-truth for the seven-layer model the architect-reviewer reasons against, so it's load-bearing prose, not code.

### PR #20 — Phase 3A: merge C1-C4 security fixes

This is the integration merge for four substantive security fixes (bcrypt verification, dashboard XSS escape helpers, sync.py fail-closed, osascript argv-list). Highest-impact structural observations:

- `dashboard.html` ships four escape helpers (`escHtml`, `escAttr`, `escJs`, `escUrl`) as free functions in inline JS. The alias `const esc = escHtml` is documented as a transition shim — but the PR notes acknowledge that many call sites still use bare `esc(`. Direction: a follow-up sweep + a regex-based gate in `scripts/` (similar in spirit to `check_function_size.py`) that fails when `dashboard.html` contains `esc(` outside the alias definition, so the migration is enforced by CI rather than memory.
- The XSS helpers re-implement `escapeHtml`/`escapeAttribute` semantics that mature libraries cover. For a vanilla-JS dashboard that ships a single HTML file the home-grown approach is the right tradeoff (no build step, no supply-chain surface), but it should be marked with a comment block noting the OWASP cheat sheet rule it implements, so any future reviewer can re-verify against the canonical rule rather than re-reading the regex.
- C1 (`cp/auth.py` `verify_endpoint_key`) is described as failing closed on malformed hashes — good. As `*Verifier` / `*Authenticator` patterns multiply (control-plane, sync, future agent), the same Protocol discipline introduced in PR #30 should apply. Worth a small `protocols/auth.py` placeholder analogous to `collector.py` / `detector.py` so the eventual unification has a documented landing spot.
- C4's `_escape_applescript_string` is correctly defended against `shell=True` injection. The api-choices rubric calls out exactly this pattern (`subprocess.run(["cmd", "arg"], check=True)`) — this PR is the reference implementation. Consider linking the rubric to the function's docstring so future readers see the policy origin.

### PR #19 — docs(incident): Day 1 antfooding credential discoveries

Docs-only. No architectural concerns.

## What I did not evaluate

- Runtime behavior, customer impact, perf measurement, or threat-modeling depth (performance-reviewer + security workflows own those).
- Test coverage gaps — that's the ratchet's job.
- File/function size — the new size-checks gate enforces those.
- Style / formatting — ruff.
- Mechanical duplication — pylint (when `check_duplication.py` lands).
- Whether the gates themselves catch real regressions (would need running them on synthetic bad PRs; out of scope for a static baseline sweep).
- The contents of large legacy modules touched only by import or by trivial test-fixture renames (e.g., `monitor.py` 5418 lines) — those are flagged by the size ratchet, and a Phase 3F split is already planned.
- The placeholder Protocol bodies for `Collector` / `Detector` — they are deliberately empty pending Phase 3F.
- Anything outside the 10 PRs in the dispatch list. There is older debt (legacy module shapes, prior detector surface) that the placeholder docstrings reference; that's input for Phase 3F's own discovery pass, not for this baseline sweep.
