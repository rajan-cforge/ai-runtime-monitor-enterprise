# Secure SDLC Enforcement at Vigil

This document is the complete inventory of how Vigil's development
process enforces secure SDLC principles through code, not policy. Every
control listed here is automated and runs on every change regardless
of who or what authored it.

The thesis is simple: tests can be skipped, agents can be told to
ignore rules, and humans get tired. None of that works against a
GitHub Action that refuses to merge.

## Threat model: what we are defending against

The defenders' threat model is intentionally broad:

1. **A well-intentioned developer makes a mistake.** Accidentally
   commits a secret, drops coverage, introduces a known-vulnerable
   dependency.
2. **A malicious developer tries to subvert review.** Bypasses
   pre-commit hooks via `--no-verify`, force-pushes to overwrite
   history, opens a PR that quietly removes a safety check.
3. **An AI agent acts beyond its mandate.** A specialist subagent
   misinterprets a prompt and tries to push directly to main, or
   adds a workaround that bypasses an existing gate.
4. **A compromised dependency injects malice.** A transitive npm or
   pip package ships a postinstall script that exfiltrates data.
5. **A drift over time.** What starts as 90% coverage becomes 60%
   because nobody noticed it eroding PR by PR.

Each gate below addresses at least one of these vectors. Many address
multiple.

## Architecture of enforcement

```
        ┌─────────────────────────────────────────────┐
        │  Layer 8  Review intelligence (multi-agent) │
        │           grader + architect + performance  │
        ├─────────────────────────────────────────────┤
        │  Layer 7  Release gates                     │
        │           Notarization, SBOM, attestation   │
        ├─────────────────────────────────────────────┤
        │  Layer 6.5  Spec-driven enforcement         │
        │             YAML rules + criticality + AST  │
        ├─────────────────────────────────────────────┤
        │  Layer 6  Branch protection                 │
        │           Required checks, signed commits   │
        ├─────────────────────────────────────────────┤
        │  Layer 5  CI workflows (per PR)             │
        │           ci-python, ci-security, smoke     │
        ├─────────────────────────────────────────────┤
        │  Layer 4  Pre-push hooks (local)            │
        │           make ci-local — full local CI     │
        ├─────────────────────────────────────────────┤
        │  Layer 3  Pre-commit hooks (local)          │
        │           ruff, bandit, detect-secrets      │
        ├─────────────────────────────────────────────┤
        │  Layer 2  Editor integration (real-time)    │
        │           LSP, ruff, mypy on save           │
        ├─────────────────────────────────────────────┤
        │  Layer 1  Type system (compile-time)        │
        │           mypy --strict, hmac.compare_digest│
        └─────────────────────────────────────────────┘
```

Lower layers fail faster and give faster feedback. Higher layers catch
what lower layers miss. A failure at any layer blocks the work.

### Layer 6.5: Spec-driven enforcement

Mechanical rules that map code-change patterns to required spec updates. Sits between branch protection (Layer 6, which determines *who* can merge) and release gates (Layer 7, which determines *what* can ship). Layer 6.5 determines *under what conditions* a PR can merge — independent of who pushed it.

The rules live in `.github/spec-requirements.yaml` as a versioned table. `scripts/check_spec_requirements.py` evaluates a PR's unified diff against every rule on each `pull_request` event (Layer 5 wires it as the `spec-requirements` job in `.github/workflows/ci.yml`). Rule severities are `BLOCK` (the gate fails) or `WARN` (the gate emits a message and merge proceeds). Pattern-matching uses `pathlib.PurePath.match` so `**` is the recursive-directory wildcard a shell user expects — `fnmatch` would silently underfire on nested module paths.

Four companion files implement the rest of the layer:

- **`CLAUDE.md`** (project constitution at the repo root) — defines the mandatory and forbidden patterns ruff and the AST checker enforce. The rationale lives here so future contributors see *why* each pattern matters rather than only seeing the gate fire.
- **`.github/pull_request_template.md`** — every PR declares its C0–C4 criticality, checks off touched specs, and discloses known limitations or deferred work. C3 and C4 require human diff review regardless of agent verdicts (Layer 8).
- **`scripts/check_design_patterns.py`** + `scripts/check_design_patterns_baseline.txt` — AST-walker for project-specific patterns. Some checks (DashboardHandler routes must call `verify_token`) are unique to this layer because ruff cannot express them; others (no `subprocess(shell=True)`, no `requests(verify=False)`) are intentional defense-in-depth against ruff's `S602`/`S501` — two independent enforcement paths on zero-tolerance forbiddens so a config drift in one doesn't disable both. New violations not in the baseline file fail the build.
- **`pyproject.toml` `[tool.ruff]`** — language-level enforcement for everything ruff can express (17 rule families: bugbear, pyupgrade, pathlib, blind-except, datetimez, tryceratops, perflint, pylint, simplify, bandit-via-ruff, etc.).

Two operational disciplines keep the layer maintainable:

- **Baselines shrink, never grow.** `check_design_patterns_baseline.txt` records existing violations on the day a rule lands; new violations fail the gate, cleanup PRs remove rows. The same discipline applies to the per-file coverage ratchet (Layer 5).
- **Warmup graduates to enforced.** New ruff rules that surface more than 20 violations land in `docs/RUFF_WARMUP.md` rather than blocking immediately. Each entry tracks current count, audit hypothesis, and a Phase 3F sprint target. Rules graduate to fully enforced when count reaches zero or the audit confirms a permanent ignore.

Three known validator limitations are documented inline in the YAML (search the file for `KNOWN LIMITATION`): `new-external-dependency` fires on version bumps as well as new deps (fix: adjacency-aware diff parsing in Phase 3F); `workflow-changes` is WARN-severity for v0.2 ergonomic reasons but is a candidate for escalation to BLOCK after architect-reviewer feedback; `hot-path-changes` requires a PR label the validator can't read from the diff alone (Phase 3F: add a `--pr-labels` argument sourced from `${{ toJson(github.event.pull_request.labels) }}` in the workflow).

Effect: from the day Layer 6.5 lands, a PR that touches authentication code without updating `docs/spec/functional/security.md` cannot merge. A PR that touches `_handle_*` routes without updating `openapi.yaml` cannot merge. A PR introducing `subprocess(shell=True)` or `requests(verify=False)` cannot merge — those are zero-tolerance forbiddens, baselined at zero, and the AST checker fails the build on any new occurrence.

### Layer 8: Review intelligence (multi-agent)

Three subagents review every PR in parallel after CI passes:

- **code-reviewer** — mechanical rubric, brevity-bound. Verdict: PASS / REVISE / BLOCK.
- **architect-reviewer** (`.claude/agents/architect-reviewer.md`) — design quality, API choices, modularity, Protocol conformance. Reads `.claude/rubrics/architecture.md` and `.claude/rubrics/api-choices.md`. Verdict: PASS_WITH_NOTES / SUGGEST_REFACTOR / BLOCK_ARCHITECTURE.
- **performance-reviewer** (`.claude/agents/performance-reviewer.md`) — algorithmic complexity, hot-path scrutiny, resource leaks, async correctness. Reads `.claude/rubrics/performance.md`. Verdict: PASS / WATCH / OPTIMIZE_RECOMMENDED.

All three are bound by the same brevity policy: surface the 3-5 highest-impact items, never enumerate the full rubric. SUGGEST/WATCH/OPTIMIZE verdicts are advisory; BLOCK-class verdicts (which are rare by design) require human decision. The orchestrator collects all three verdicts and includes them in a single consolidated ping to the maintainer.

The rubrics are the substance — agents are thin loops that apply them. When patterns drift, edit the rubric files; the agent definitions stay short and stable.

Protocol conformance for the `Scanner` interface is enforced by `tests/architecture/test_scanner_conformance.py`, with a meta-test (`test_protocol_inventory.py`) that fails the build if a new Protocol is added without a matching conformance file.

### Layer 8a: Pre-PR review loop

Reviewers run against the **local** diff before push, not only against the opened PR. The flow:

1. Implementation complete, local tests + lint pass.
2. `scripts/dev/pre_pr_review.sh` captures the diff into `~/.vigil-pre-pr-review/<timestamp>/`.
3. Orchestrator dispatches all three reviewers in local mode (they read the workspace + working tree, write verdicts to disk).
4. Each finding is tagged `FIX-BEFORE-MERGE`, `DEFER-TO-FOLLOWUP`, or `INFORMATIONAL`.
5. The orchestrator applies `FIX-BEFORE-MERGE` fixes to the working tree, re-runs targeted tests, and re-dispatches the reviewers to verify (cycle cap: 2).
6. All work — original change plus local fixes — commits as ONE commit.
7. Push and open the PR. The PR-time reviewers then run as final verification (should return PASS or PASS_WITH_NOTES with only `INFORMATIONAL` items).

Effect: PRs arrive on GitHub already-reviewed, CI runs once instead of twice per fix iteration, and the public git history is one commit per logical change. Review moves from "ask forgiveness" (PR opens, finds issues, amends) to "ask permission" (local review, fix, push clean).

The full procedure with the commit-message convention and skip rules is in `.claude/workflows/pre-pr-review.md`.

This layer is **procedural**, not mechanical — it relies on the orchestrator following the workflow document. The mechanical end-state is a GitHub App that auto-runs the loop on PR open without anyone dispatching it; that's Phase 3G work after launch.

## Inventory of enforcement controls

### Branching and history controls

**Rule: every change goes through a branch and PR.**

- *Why*: prevents direct manipulation of the canonical history.
  Forces visibility (every change has a reviewer-readable diff),
  reversibility (any merge can be reverted), and auditability (the
  reason for every change is recorded in PR body and commit message).
- *Mechanism*: branch protection on `main` requires PR before merge,
  rejects direct pushes.
- *Documented in*: `docs/BRANCHING.md`
- *Bypass path*: none. GitHub does not allow direct push to a branch
  with protection rules unless the user has explicit admin override,
  which is logged.

**Rule: branch names follow a strict prefix taxonomy.**

- *Why*: makes intent visible in `git branch -a` output. Security
  fixes are unmistakable; experimental work is unmistakable.
- *Prefixes enforced*:
  ```
  audit/       adversarial audits
  security/    security fixes (audit findings)
  fix/         non-security bug fixes
  feature/     new features
  infra/       tooling, CI, build
  lane-A..D    sprint lanes
  release/     release prep
  hotfix/      emergency post-release
  docs/        documentation-only
  ```
- *Mechanism*: PR template references the convention. CI does not
  currently enforce naming (planned Phase 3D as a custom check).
- *Documented in*: `docs/BRANCHING.md`

**Rule: linear history. Branches rebase, do not merge from main.**

- *Why*: keeps `git log --oneline` readable. Each commit reverts
  cleanly. No merge bubbles to trace through.
- *Mechanism*: branch protection rule "Require linear history".
- *Bypass path*: none. Push of a merge commit is rejected.

**Rule: no force-pushes to main.**

- *Why*: prevents history rewriting that would erase audit trail or
  hide malicious commits.
- *Mechanism*: branch protection rule "Allow force pushes: never".
  Pre-commit hook in `.claude/hooks/pre-tool-use.sh` rejects any
  `git push --force` command issued by an agent.
- *Bypass path*: none from outside admin override.

**Rule: branches deleted immediately after merge.**

- *Why*: prevents accidental re-merge of stale work and reduces
  cognitive load when listing branches.
- *Mechanism*: GitHub's "Automatically delete head branches" setting
  enabled.
- *Bypass path*: none for merged PRs.

### Commit hygiene controls

**Rule: conventional commit messages.**

- *Why*: machine-parseable history enables auto-generated CHANGELOGs,
  semantic version bumps, and reliable search by change type.
- *Format*: `<type>(<scope>): <subject>` where type is one of
  `feat | fix | security | perf | refactor | test | docs | chore | ci | build`.
- *Mechanism*: `compliance/conventional-pre-commit` runs on
  `commit-msg` stage. Rejects non-conforming messages.
- *Bypass path*: `git commit --no-verify` skips local hook, but CI
  on push verifies the commit message via the same convention and
  blocks merge.

**Rule: no `Co-Authored-By: Claude` trailers.**

- *Why*: attribution. A human reviewer should be able to see who
  authored a change without ambiguity. Agent assistance is implicit
  in the workflow, not a co-author claim.
- *Mechanism*: PR template requires "[x] No Co-Authored-By: Claude
  trailer in commits" before merge. Three pre-policy commits
  (8f07f9e, 770eef2, 7a8d712) are documented as historical
  exceptions in `docs/COMMIT_HISTORY_EXCEPTIONS.md`.
- *Future*: signed-commits gate (Q3 of quality gates) will make
  this enforced by gitsign signature requirements.

**Rule: signed commits (post Q3 of quality gates).**

- *Why*: cryptographic attribution. Prevents impersonation in commit
  metadata.
- *Mechanism*: gitsign keyless signing for both human and agent
  commits. Branch protection requires signed commits.
- *Status*: deferred to Phase 3G. Pre-policy commits documented as
  exceptions.

### Build and dependency controls

**Rule: editable install must succeed on every Python version in matrix.**

- *Why*: a broken `pip install -e ".[dev]"` blocks every other gate.
  Catching install bugs at PR time is much cheaper than catching
  them on every developer's machine.
- *Mechanism*: CI matrix runs ubuntu-latest × Python 3.9, 3.11, 3.12,
  3.13, plus macOS-14 × Python 3.12. All must pass.
- *Recent enforcement save*: PR #11 caught a `setuptools_scm` tag
  parsing bug that crashed Python 3.13+ installs.

**Rule: dependency vulnerabilities block merge.**

- *Why*: a CVE in a transitive dependency is just as exploitable as
  one in your own code.
- *Mechanism*:
  - Python: `pip-audit --strict` on every PR via `.github/workflows/ci-security.yml`
  - Rust (future Tauri work): `cargo audit` + `cargo deny check`
  - Node (future React migration): `npm audit --audit-level=moderate`
- *Bypass path*: none. CI status check is required for merge.

**Rule: new runtime dependencies require an entry in dependency-rationale.md.**

- *Why*: forces the per-dep "why this one and not the alternatives"
  conversation to happen at PR time, while it's still cheap. Records
  the decision so future contributors don't re-litigate it. Records
  the no-adopt list (Trivy, Codecov, GitPython, …) so the same dep
  doesn't get proposed again in 3 months.
- *Mechanism*: Layer 6.5 spec-requirements rule
  `new-external-dependency` — a PR that adds a line matching
  `"<pkg>[><=~^]…"` to `pyproject.toml` must also touch
  `docs/spec/dependency-rationale.md`. Validator is
  `scripts/check_spec_requirements.py`; CI job is `spec-requirements`.
- *Bypass path*: none for mechanical fire. The rule currently fires
  on version bumps too (KNOWN LIMITATION documented in the YAML);
  acceptable v0.2 friction until Phase 3F adds adjacency-aware diff
  parsing.

**Rule: spec corpus changes track code changes.**

- *Why*: when code that has a corresponding spec doc evolves, the
  spec must evolve with it — otherwise the spec drifts into fiction
  and stops being useful. Catches "I changed the auth flow but
  forgot to update `security.md`" at PR time, not at audit time.
- *Mechanism*: Layer 6.5 spec-requirements rules
  (`api-endpoint-changes`, `auth-changes`, `ca-cert-changes`,
  `sync-sanitization-changes`, `schema-changes`) map source-file +
  pattern matches to required doc updates. See
  `.github/spec-requirements.yaml` for the full table; each rule
  is severity `BLOCK` so a violation fails the gate.
- *Bypass path*: none for `BLOCK` rules. The validator skips
  malformed rules with a stderr warning rather than crashing the
  whole gate.

**Rule: secrets cannot land in the codebase.**

- *Why*: secrets in git history are forever, regardless of subsequent
  removal. The only safe rule is "never commit a secret."
- *Mechanism*:
  - Pre-commit hook: `detect-secrets` scans every staged file against
    a baseline at `.secrets.baseline`
  - CI: `trufflesecurity/trufflehog` scans diffs on every PR
  - Pre-commit hook: `detect-private-key` rejects PEM, OpenSSH, and
    other private key headers
- *Bypass path*: `git commit --no-verify` skips local. CI catches.
  False positives are explicitly allowlisted in baseline; never
  silently ignored.

**Rule: GPL / AGPL / LGPL dependencies are blocked.**

- *Why*: license compatibility for a commercial product. Copyleft
  licenses contaminate proprietary code.
- *Mechanism*: `pip-licenses --fail-on="GPL;AGPL;LGPL;SSPL"` runs in
  CI on every PR.
- *Documented in*: `pyproject.toml` license whitelist.

### Code quality controls

**Rule: formatter and linter clean on every file change.**

- *Why*: consistent style reduces cognitive load. Catches a huge class
  of bugs (unused variables, undefined names, misplaced f-strings)
  that look fine to the eye but cause runtime failures.
- *Mechanism*:
  - Pre-commit hook: `ruff format` + `ruff check --fix` runs on every
    staged Python file
  - CI: `ruff check` runs on the full diff against the 17-family
    aggressive ruleset (Layer 6.5)
  - Post-edit hook in `.claude/hooks/post-edit.sh` runs `ruff format`
    immediately after any Claude Code Edit tool call
- *Bypass path*: `--no-verify` skips local. CI catches.
- *Warmup*: rules with >20 existing violations land in
  `docs/RUFF_WARMUP.md` rather than blocking immediately; the warmup
  list shrinks over time as Phase 3F sprints clean up.

**Rule: project-specific design patterns enforced by AST checker.**

- *Why*: ruff covers what's expressible as static lint. Some
  CLAUDE.md mandatory and forbidden patterns aren't — e.g.,
  "DashboardHandler routes must call `verify_token`",
  `subprocess(shell=True)`, `requests(verify=False)`. A custom AST
  walker enforces these directly.
- *Mechanism*: `scripts/check_design_patterns.py` runs in the CI
  lint job (Layer 5) under the rules from Layer 6.5. Existing
  violations are baselined in
  `scripts/check_design_patterns_baseline.txt`; new violations not
  in the baseline fail the build.
- *Bypass path*: none. The baseline shrinks over time; cleanup PRs
  remove rows but never add them.

**Rule: dangerous bash commands are blocked at hook time.**

- *Why*: `rm -rf /`, `chmod 777`, `curl ... | bash` are categorically
  unsafe. An agent should never run them, regardless of intent.
- *Mechanism*: `.claude/hooks/pre-tool-use.sh` parses the bash command
  before it executes. Patterns matched: `rm -rf /*`, `rm -rf ~/*`,
  `git push --force*`, `chmod 777*`, `curl * | bash`, `curl * | sh`.
  The hook returns non-zero, which Claude Code respects as a block.
- *Bypass path*: none for agent. A human can run these commands
  outside of Claude Code; that is their explicit responsibility.

**Rule: tests must run and pass before session end.**

- *Why*: a Claude Code session that ends with failing tests creates
  the next developer's surprise. The fix gets harder the longer it
  sits broken.
- *Mechanism*: `.claude/hooks/stop.sh` runs `make ci-local` (which
  includes the full test suite) before the agent can release control.
  Non-zero exit blocks the session from ending.
- *Bypass path*: none for agent.

### Test quality controls

**Rule: 90% line coverage minimum, 85% branch coverage minimum.**

- *Why*: coverage gates the surface area of untested code. Without
  it, "we have tests" becomes "we have tests for the easy parts."
- *Mechanism*: `pytest --cov=claude_monitoring --cov-fail-under=90`
  runs on every PR. A custom `scripts/check_branch_coverage.py`
  enforces 85% branch coverage independently.
- *Status*: current coverage ~72%. Phase 3B Quality Gates Q1 ratchets
  the threshold up from current state rather than jumping immediately
  to 90%.
- *Bypass path*: none. CI status check is required.

**Rule: coverage ratchet — coverage cannot drop on any PR.**

- *Why*: enforces forward progress. Without a ratchet, gates erode
  over time as small drops accumulate.
- *Mechanism*: `scripts/coverage_ratchet.py` compares PR branch
  coverage to base branch. Fails if line drops > 0.1% or branch
  drops > 0.5%.
- *Bypass path*: none.

**Rule: every src module has a functional integration test.**

- *Why*: "we have tests" without integration coverage means the
  units work in isolation but the system doesn't.
- *Mechanism*: `scripts/check_functional_coverage.py` walks
  `src/claude_monitoring/` and asserts a corresponding
  `tests/integration/test_<module>.py` exists for every public
  module.
- *Status*: planned Phase 3D. Currently advisory.

**Rule: mutation testing on changed files (≥70% mutation score).**

- *Why*: coverage proves lines are executed; mutation testing proves
  the assertions actually catch bugs. A test that exercises a line
  but asserts nothing is a useless test, and mutation testing is
  the only honest measure of this.
- *Mechanism*: `mutmut` runs on Python files changed in the PR.
  Threshold: kill 70% of mutants. Below threshold fails CI.
- *Status*: planned Phase 3G post-launch (current coverage too low
  to make mutation testing meaningful on the full codebase).

**Rule: TDD discipline — regression test proves it fails without the fix.**

- *Why*: this is the only way to know a test actually catches the
  bug it claims to catch. A test that passes immediately could be
  testing nothing.
- *Mechanism*: PR template includes "[x] Tests fail without the fix
  (proves they exercise the code)" checkbox. The C1-C4 specialist
  agents had this verification step explicit in their prompts:
  ```
  5. git stash the fix. Run the test again. Confirm it fails again.
     (This proves the test is not a tautology.)
  6. git stash pop. Run the test. Confirm it passes again.
  ```
- *Bypass path*: human reviewer can clear the checkbox without
  verification. This is intentionally trust-but-verify; CI cannot
  prove the test exercises the right code path without running the
  pre-fix version.

### Architecture controls

**Rule: layered architecture enforced by import-linter.**

- *Why*: prevents `dashboard` from reaching into `proxy` internals
  or `domain` from depending on `requests`. Architecture stays
  enforceable as the code grows.
- *Mechanism*: `lint-imports --config importlinter.cfg` runs on
  every PR. Contracts include:
  - Layered: api → dashboard → services → adapters → domain → common
  - `extension_scanner` cannot import from `dashboard` or `api`
  - `dashboard` cannot import daemon internals (`proxy`, `collectors`)
  - Adapters cannot depend on services (dependency inversion)
  - Domain layer is pure (no `requests`, `httpx`, filesystem)
  - Tests use only public APIs (no `_internal` imports)
- *Status*: planned Phase 3D after layered structure exists (current
  codebase is flat; the layering work is part of audit M6 split).

**Rule: file size ≤ 500 lines, function size ≤ 50 lines.**

- *Why*: large files and large functions are correlated with bugs and
  resist review. A 4,800-line `monitor.py` is the audit's M6 finding.
- *Mechanism*: `scripts/check_file_size.py` and
  `scripts/check_function_size.py` (custom AST-based) run in CI.
  Exemptions: `# pragma: noqa: file-size` with comment explaining why.
- *Status*: planned Phase 3B with thresholds initially set above
  current state (e.g., 5000 for `monitor.py`), ratcheting downward
  as the M6 split happens.

**Rule: cyclomatic complexity ≤ 10 per function (xenon rating B).**

- *Why*: complex functions are hard to test and reason about. Forces
  refactoring of state machines and large conditionals.
- *Mechanism*: `xenon --max-absolute B --max-modules A --max-average A
  src/claude_monitoring`.
- *Status*: planned Phase 3D.

**Rule: no code duplication ≥ 5 lines.**

- *Why*: duplicated logic drifts. The Py3.9 `from __future__` bug
  was duplicated across 3 files; if it had been a single helper it
  would have been one fix.
- *Mechanism*: `pylint --disable=all --enable=duplicate-code
  --min-similarity-lines=5`.
- *Status*: planned Phase 3B as part of the duplication gate.

**Rule: dead code (90% confidence) blocks merge.**

- *Why*: unused code increases attack surface, confuses readers, and
  costs maintenance.
- *Mechanism*: `vulture src/claude_monitoring --min-confidence 90`.
- *Status*: planned Phase 3D.

### Smoke and end-to-end controls

**Rule: daemon must boot and serve the dashboard on every PR.**

- *Why*: unit tests pass while the actual app is broken. Smoke catches
  this class of regression.
- *Mechanism*: `.github/workflows/smoke.yml`. Starts the daemon,
  hits `/api/stats`, confirms dashboard HTML loads, scans daemon log
  for ERROR/TRACEBACK. Runs on every PR and on push to `main` and
  `integration/phase-3a`.
- *Bypass path*: none. Required check.
- *Recent enforcement save*: caught the install regression that
  broke pip on the rollback target during the antfood loop FATAL.

**Rule: combined-state CI on integration branches.**

- *Why*: each Cx fix passed CI individually. The four together must
  also pass CI as a unit before reaching `main`.
- *Mechanism*: integration branches (`integration/phase-3a` and
  future) run the full CI suite on push. The integration → main PR
  runs CI again on the combined state.
- *Bypass path*: none.

### Antfooding control loop

**Rule: dev machine runs the latest VALIDATED main + integration code.**

- *Why*: dogfooding catches what tests miss. A daemon running on
  the operator's own machine surfaces real-world issues immediately.
- *Mechanism*: `scripts/antfood-loop.sh` polls `origin/main` and
  `origin/integration/phase-3a` every 5 minutes, checks GitHub CI
  status via `gh CLI`, pulls and restarts the daemon only when CI
  is green. On boot failure, rolls back to last-known-good SHA
  stored at `~/.vigil-antfood-state`.
- *Robustness*: explicitly unsets HTTPS_PROXY env vars (the monitor's
  own proxy interferes with pip install), refuses to run on Python
  3.13+ with a clear remediation message, uses state-file rollback
  rather than a hardcoded tag.
- *Documented in*: `docs/RUNBOOK.md`

**Rule: every antfooding observation logs to `docs/ANTFOODING_LOG.md`.**

- *Why*: turns ad-hoc usage into an audit trail. Every day's
  observations become reference data for future sprint planning.
- *Mechanism*: convention. Each day's entry includes SHA running,
  duration, what was used for, what surprised the operator, structured
  probe results, verdict.

### Audit and incident controls

**Rule: adversarial two-wave audit pattern.**

- *Why*: a single reviewer (human or agent) is anchored by their
  initial framing. Two waves with the explicit job of falsifying
  the first wave's findings catches what a single pass misses.
- *Mechanism*: `docs/CC_PROMPT_AUDIT_adversarial_self_audit.md`
  dispatches 3 finders in wave 1 and 5 falsifiers in wave 2. The
  pattern has been validated: 25% of wave 1 findings were falsified
  in wave 2, and 2 of 4 final criticals were net-new from the wave 2
  completeness check.
- *Documented in*: `docs/AUDIT_2026-05-21.md` (the first run)

**Rule: probe credential-inheritance discipline.**

- *Why*: browser-based security probes silently inherit credentials
  from the app they're testing. The Day 1 Claude-in-Chrome probe
  reported a false C1-FOLLOWUP critical because the dashboard's
  monkey-patched `fetch` injected the auth token automatically.
- *Mechanism*: `docs/PROBE_DESIGN.md` documents required practice:
  - Out-of-browser HTTP client (curl) for auth verification
  - Or fresh tab on different origin with `credentials: 'omit'`
  - Or strip the monkey patch before testing
- *Status*: pattern documented after the false positive; next probe
  must reference and follow.

**Rule: incident response goes through doc records — public/private split required.**

- *Why*: incidents need permanent records, not Slack messages. But
  records that contain real credential values, vendor names, or
  customer session IDs do NOT belong in a public repo even if the
  values are inert. Mixing security-incident details with public
  source is a category error.
- *Mechanism — private*: real-credential incidents and operational
  records live in **local private notes** at
  `~/Documents/vigil-notes/incidents/<YYYY-MM-DD>-<slug>.md`. Each
  record carries the same fields (symptom, cause, recovery,
  disposition, reversibility) — they're just kept off the public repo.
- *Mechanism — public*: only aggregated, value-free learnings come
  into the public repo (e.g. an audit-doc table that says "Detector
  X had Y% TP rate on N samples" with no individual values, or a
  changelog entry "fixed false-positive class FP-7"). Build-break /
  CI-regression incidents that contain no sensitive content may
  still live in `docs/incidents/<date>-<title>.md`.
- *Reversibility*: disposition decisions explicit in the private
  record. If "not rotating" proves wrong later, reopen the private
  incident with the new disposition. Public visibility never gates
  the recovery path.

### Release controls (Phase 3G, post-launch)

**Rule: SBOM generated on every PR, published on every release.**

- *Why*: supply chain visibility. Customers and auditors can see
  exactly what's in the binary.
- *Mechanism*: `cyclonedx-py -o sbom.json` runs in CI.

**Rule: build provenance attested on every release.**

- *Why*: lets downstream consumers verify the binary came from this
  repo's CI, not from a developer's machine.
- *Mechanism*: `actions/attest-build-provenance` and
  `actions/attest-sbom`.

**Rule: notarization and code signing on macOS releases.**

- *Why*: Gatekeeper kills 30-40% of conversions on first install.
  Signed and notarized binaries install with no warning.
- *Mechanism*: Apple notarytool in release workflow. Signed via
  Developer ID Application certificate.
- *Status*: Lane A (Tauri) deferred to v0.3. v0.2 ships via
  Homebrew tap and pip, which don't require notarization.

## How this stops agents from violating SDLC principles

Six failure modes mapped to controls that prevent them:

**Failure 1: Agent pushes broken code directly to main.**
- Branch protection rejects direct push.
- PR required.
- CI must pass before merge.

**Failure 2: Agent skips tests with `pytest --no-cov` or marks them xfail.**
- Coverage ratchet blocks any drop.
- `pytest.ini` config has `--strict-markers --strict-config`.
- `tdd-loop` skill in `.claude/skills/` documents the discipline.

**Failure 3: Agent commits a secret accidentally.**
- `detect-secrets` pre-commit hook scans before commit.
- `trufflehog` CI workflow scans diffs on every PR.

**Failure 4: Agent introduces a known-vulnerable dependency.**
- `pip-audit` blocks PR.
- `pip-licenses` blocks GPL contamination.

**Failure 5: Agent removes a safety check in a refactoring PR.**
- Code review (human) required on every PR.
- Adversarial grader subagent reviews against the lane's rubric.
- Coverage ratchet catches if the safety check had tests covering it.
- import-linter (planned) catches if a layering rule was bypassed.

**Failure 6: Agent does a force-push to overwrite history.**
- Branch protection rejects force-push to main.
- Pre-commit hook blocks `git push --force*` patterns.
- Linear history requirement makes merge-bubble tricks impossible.

In each case, the agent does not need to be trusted. The system
catches the misbehavior automatically.

## What is NOT enforced (yet)

Honesty about gaps. Each is on the roadmap.

| Control | Status | Target |
|---|---|---|
| mypy --strict | Non-strict in Q2, strict in Q3 | Q3 (post M6 split) |
| import-linter contracts | Defined but not yet enforced | Q2 |
| Mutation testing | Defined but not yet enforced | Q3 |
| Signed commits | Documented, not enforced | Q3 |
| File/function size | Custom scripts not yet wired to CI | Q2 |
| Branch name enforcement | Convention only, not blocked | Q2 |
| Architectural fitness functions (coupling metrics) | Not started | Q3 |
| TDD verification automation (stash-and-rerun) | Convention only | Manual |
| Probe credential-inheritance check | Manual practice via docs/PROBE_DESIGN.md | Manual |
| SBOM attestation on releases | Workflow defined, no releases yet | Phase 3G |

The roadmap is committed. Each item has a phase tag in
`docs/SPRINT_ONE_WEEK.md` and a corresponding GitHub issue when work
begins.

## Validation: does this actually work?

Five concrete examples from the first week of operation. Each shows
the system catching what would otherwise have slipped through.

1. **PR #4 caught Py3.9 `from __future__` regression.** Audit
   finding H1 was firing in production. CI was red on main. The
   `pip install` failure on the matrix's Python 3.9 row blocked
   subsequent PRs until the fix landed.

2. **PR #11 caught `setuptools_scm` install regression.** When the
   antfood loop tried to roll back to the `pre-c1c4` tag on Python
   3.14, setuptools_scm crashed. The smoke workflow caught this
   class of issue before it shipped further.

3. **PR #16 closed the antfood-loop FATAL.** Loop died when HTTPS_PROXY
   leaked from the user's shell. The robustness PR documented the
   failure mode, added the fix, added 6 smoke tests, updated the
   RUNBOOK. No fix-and-forget — the fix included tests so the same
   regression cannot recur.

4. **Claude-in-Chrome probe found 3 real credential exposures.**
   The structured probe (Day 1 antfooding) traced sensitive-data
   alerts to three real credential leaks in historical Claude Code
   sessions: 3 AWS keys, an ACMS multi-pattern dump, an Anthropic
   key. These would have remained invisible without antfooding.

5. **C1-FOLLOWUP retracted as non-finding.** When Claude-in-Chrome's
   Test 1 reported a critical /api/* auth bypass, Claude Code did
   NOT immediately start the fix. It verified the claim with curl,
   discovered the probe had inherited credentials via monkey-patched
   fetch, and stopped to report. The orchestrator's "verify before
   acting" discipline caught a phantom critical before any code
   was written.

The pattern in every example is the same: an automated control
detected a problem before a human had to. That is what enforcement
means.

## How to add a new control

When a new failure mode is identified, the procedure to add a
permanent control is:

1. Identify which layer the control belongs to (1-7 above).
2. Implement the control as code (lint rule, CI workflow, hook,
   custom script, branch protection setting).
3. Add a regression test or example that demonstrates the control
   firing.
4. Update this document with a new entry under the appropriate
   section.
5. Open a PR. The PR itself runs through every existing control,
   which validates that the new control plays well with the existing
   set.

Controls are added through the same SDLC the rest of the codebase
follows. There is no out-of-band "policy update" channel. The policy
IS the code.

## References

- `docs/AUDIT_2026-05-21.md` — adversarial self-audit findings
- `docs/CC_PROMPT_AUDIT_adversarial_self_audit.md` — audit pattern
- `docs/BRANCHING.md` — branching and commit conventions
- `docs/TOOLING.md` — MCP servers and plugin capability map
- `docs/PROBE_DESIGN.md` — antfooding probe design discipline
- `docs/RUNBOOK.md` — operational procedures and emergency rollback
- `docs/SPRINT_ONE_WEEK.md` — current sprint state and phase plan
- `docs/COMMIT_HISTORY_EXCEPTIONS.md` — historical exceptions to
  current policy
- `docs/incidents/` — public-safe incident records (CI breaks, build
  regressions). Real-credential incidents live in private notes at
  `~/Documents/vigil-notes/incidents/` outside the repo.
- `.claude/agents/` — subagent definitions
- `.claude/skills/` — reusable workflow skills with Gotchas sections
- `.claude/rubrics/` — per-lane grading rubrics
- `.claude/hooks/` — deterministic enforcement hooks
- `.github/workflows/` — CI workflows

## Document version

Maintained as a living document. Updated whenever a new control is
added or an existing control changes scope.

Last reviewed: 2026-05-25 (Layer 6.5 added — spec-driven enforcement
via .github/spec-requirements.yaml, CLAUDE.md as constitution,
custom AST checker with baseline, aggressive ruff ruleset with
RUFF_WARMUP.md graduation discipline).
Next review trigger: at the close of Phase 3B (Quality Gates Q1)
when new controls are added.
