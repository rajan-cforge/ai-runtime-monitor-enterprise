# Claude Code Dispatch — Mechanical Guardrails for Design and Spec Enforcement

**Target branch:** `infra/spec-driven-enforcement`
**Base branch:** `main`
**Type:** Single PR with multiple components
**Priority:** Phase 3B closure work, runs after spec docs are merged

## Prerequisites

This PR REQUIRES the following docs to exist on `main` first:

- `docs/spec/PRD.md`
- `docs/spec/openapi.yaml`
- `docs/spec/API-CONTRACTS.md`
- `docs/spec/THREAT-MODEL.md`
- `docs/spec/SECURITY-MANIFEST.md`
- `docs/spec/DATA-CLASSIFICATION.md`
- `docs/spec/functional/monitor.md`
- `docs/spec/functional/sync.md`
- `docs/spec/functional/security.md`
- `docs/spec/functional/watch.md`
- `docs/spec/functional/wizard.md`
- `docs/spec/functional/status.md`
- `docs/spec/functional/db.md`
- `docs/spec/functional/config.md`
- `docs/spec/functional/scanners.md`
- `docs/spec/README.md`
- `docs/ARCHITECTURE.md` (revised version with trust boundaries, data flows, module dependency graph)

If any are missing, STOP and report which ones. Do not create them yourself as part of this PR.

## Goal

Install the mechanical enforcement layer that makes the spec docs binding rather than aspirational. After this PR lands, CI will reject changes that violate the layered rules below. Reviewers (human and agent) get a consistent set of standards to apply.

## Components

The PR consists of seven components. Implement them in order. Each component should pass the three-agent review pipeline (grader + architect + performance) before moving to the next.

### Component 1: CLAUDE.md as project constitution

Update or create `CLAUDE.md` at the repo root. This file is read by Claude Code at the start of every session and shapes its behavior throughout. The content must establish mandatory patterns, forbidden patterns, and a pre-implementation checklist.

Required sections:

```markdown
# Claude Code Orientation — Vigil

## Project identity

This is Vigil (formerly AI Runtime Monitor), an endpoint security product for AI developers.
Repo: ai-runtime-monitor-enterprise. Open source under Apache 2.0.

## Mandatory patterns

Use these patterns. Do not deviate without explicit user approval.

- **Constant-time comparison** for all credential and token checks: `hmac.compare_digest`. Never `==` for tokens.
- **Parameterized SQL queries** always. No string concatenation, no f-strings, no `%` formatting in SQL.
- **Context-aware HTML escaping** in dashboard.html. Use `escHtml`, `escAttr`, `escJs`, `escUrl` — never bare `esc()`.
- **Subprocess argv lists** for all subprocess calls. Never `shell=True`. For osascript, use the argv form.
- **Fail-closed sentinels** for sanitization. On any error, return "" (empty string) not the raw input.
- **chmod 600/700** enforcement on all sensitive files and directories. Use `security.enforce_permissions`.
- **NameConstraints on CA generation**. Never generate a CA without `permitted_subtrees`.
- **`from __future__ import annotations`** at the top of every Python file (for forward references).
- **Type hints** on every public function parameter and return value.
- **Docstrings** on every public function with at least one line describing purpose.

## Forbidden patterns

Never introduce these. If existing code has them, propose a fix in a separate PR.

- `eval()` or `exec()` on any user-provided data
- `pickle.load` or `yaml.unsafe_load` on any data
- `subprocess.run(..., shell=True)` for any reason
- SQL queries with `%s` interpolation or `f"SELECT ... {variable}"`
- `requests.post(url, verify=False)` — never disable TLS verification
- Bare `except:` clauses without re-raising or explicit handling
- `print()` for diagnostic output in production code paths (use `logger.*`)
- Module-level mutable state without explicit testing affordances
- Imports with side effects (e.g., importing a module that monkey-patches stdlib)
- New endpoints in `DashboardHandler` that don't call `verify_token`

## Pre-implementation checklist

Before writing any non-trivial code:

1. Read the relevant `docs/spec/functional/<module>.md` if it exists
2. Identify the trust boundary the change crosses (see `docs/spec/THREAT-MODEL.md`)
3. Identify the data classification of any data the change handles (see `docs/spec/DATA-CLASSIFICATION.md`)
4. If touching a Scanner, verify the `protocols/scanner.py` Protocol is satisfied
5. If touching authentication, update `docs/spec/functional/security.md`
6. If touching the API, update `docs/spec/openapi.yaml` AND `docs/spec/API-CONTRACTS.md`
7. If adding a new dependency, document the rationale in `docs/spec/dependency-rationale.md`
8. If the change is non-trivial, write a design doc at `docs/design/<feature>.md` before implementing

## Hot paths

These code paths are performance-critical. Do not add allocations or I/O inside them without measurement.

- `DashboardHandler.do_GET` and per-route handlers — every dashboard refresh hits multiple
- `JSONLSessionWatcher.run_loop` — high-frequency during active Claude Code sessions
- `ClaudeWatchAddon.response` — every intercepted HTTPS response
- `utils.scan_sensitive` — runs on every captured message body
- `utils.is_ai_process` — runs on every psutil process iter

## Source-honesty rules

When a requirement or spec is referenced but doesn't exist:
- Log it as "not yet authored" in the relevant doc
- Never invent the missing requirement
- Never proceed as if the requirement exists

When implementation reveals an architectural decision not previously documented:
- Mark it as "derived" in the relevant spec
- Surface it for explicit user ratification before merging

When a spec exists and code diverges from it:
- Either update the spec (explicit revision PR) OR revert the divergence
- Never silently leave spec and code disagreeing

## Design doc trigger criteria

Write a `docs/design/<feature>.md` before implementing if any of these are true:

- The change adds a new module
- The change crosses a trust boundary (new endpoint, new external API, new IPC)
- The change modifies the database schema
- The change adds a new external dependency
- The change touches the auth, masking, sanitization, or CA generation code
- The change is expected to take more than 100 lines

The design doc should cover: motivation, proposed approach, alternatives considered, threat surface,
and verification plan.

## Criticality classification

Every PR description must include a criticality level:

- **C0** — docs-only, no code paths affected
- **C1** — tests or scripts, no production behavior
- **C2** — feature addition, no security implication
- **C3** — feature with security implication or hot-path touch
- **C4** — auth, secrets, crypto, trust boundary

C3 and C4 PRs require human diff review even if all agents pass.

## Where things live

- Source code: `src/claude_monitoring/`
- Tests: `tests/`
- Specs: `docs/spec/`
- Architecture: `docs/ARCHITECTURE.md`
- SSDLC controls: `docs/SSDLC_ENFORCEMENT.md`
- Agent rubrics: `.claude/rubrics/`
- Agent definitions: `.claude/agents/`
- Quality gate scripts: `scripts/check_*.py`
- Local-only operational notes: `~/Documents/vigil-notes/` (NOT in repo)
```

If a `CLAUDE.md` already exists, this content REPLACES it. Stash the old content under `docs/internal/CLAUDE-archive-2026-05-24.md` if there's content worth keeping.

### Component 2: Aggressive ruff configuration

Update `pyproject.toml` `[tool.ruff]` section to enable security and style rules that match the mandatory patterns above. Add these rule sets:

```toml
[tool.ruff]
target-version = "py39"
line-length = 120

[tool.ruff.lint]
select = [
    "E",        # pycodestyle errors
    "F",        # pyflakes
    "W",        # pycodestyle warnings
    "I",        # isort (import order)
    "B",        # flake8-bugbear (common bug patterns)
    "UP",       # pyupgrade (modernization)
    "PTH",      # flake8-use-pathlib (prefer Path over os.path)
    "BLE",      # flake8-blind-except (catch bare except)
    "G",        # flake8-logging-format (proper logging)
    "DTZ",      # flake8-datetimez (timezone-aware datetimes)
    "TRY",      # tryceratops (try/except patterns)
    "PERF",     # perflint (performance anti-patterns)
    "PL",       # pylint (general)
    "RUF",      # ruff-specific
    "SIM",      # flake8-simplify
    "S",        # flake8-bandit (security)
    "TID",      # flake8-tidy-imports
]
ignore = [
    "S101",     # assert statements (we use them in tests)
    "PLR2004",  # magic values (too noisy; rely on code review)
    "TRY003",   # long exception messages (sometimes useful)
    "PERF203",  # try/except in loop (sometimes necessary)
    "PLR0913",  # too many arguments (judgment call)
]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = [
    "S",        # security rules don't apply to tests
    "PLR2004",  # magic values are common in tests
    "PT009",    # use of assertEqual is fine
]
"scripts/**/*.py" = [
    "T201",     # print statements are fine in scripts
]
```

Run `ruff check src/ scripts/ tests/ --fix` after configuring, but commit the manual fixes separately so the rules-enable diff is distinguishable from the auto-fixes.

For any rule that produces > 20 violations across the codebase, add it to a "warmup" group: enabled but with `--exit-zero` in the lint workflow until existing code is migrated. Document the warmup list in `docs/RUFF_WARMUP.md`. Tracked in `scripts/check_ruff_progress.py` (count violations weekly; goal is monotonic decrease).

### Component 3: Custom AST design-pattern checker

Create `scripts/check_design_patterns.py`. This is a project-specific AST walker that catches patterns ruff can't express. Mandatory checks:

```python
#!/usr/bin/env python3
"""Project-specific AST checks beyond what ruff provides.

Exits 0 if all checks pass, 1 if any violation found.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = PROJECT_ROOT / "src" / "claude_monitoring"

class DesignPatternChecker(ast.NodeVisitor):
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.violations: list[tuple[int, str]] = []
        self.in_dashboard_handler = False

    def visit_ClassDef(self, node):
        if node.name == "DashboardHandler":
            self.in_dashboard_handler = True
        self.generic_visit(node)
        if node.name == "DashboardHandler":
            self.in_dashboard_handler = False

    def visit_FunctionDef(self, node):
        # Check: public function has docstring
        if not node.name.startswith("_") and not ast.get_docstring(node):
            self.violations.append(
                (node.lineno, f"public function '{node.name}' missing docstring")
            )

        # Check: handler methods in DashboardHandler call verify_token or skip auth explicitly
        if self.in_dashboard_handler and node.name.startswith("_handle_"):
            calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)]
            has_auth = any(
                isinstance(c.func, ast.Attribute) and c.func.attr == "verify_token"
                or isinstance(c.func, ast.Name) and c.func.id == "verify_token"
                for c in calls
            )
            has_skip = any(
                isinstance(n, ast.Constant) and isinstance(n.value, str)
                and "auth-exempt" in n.value
                for n in ast.walk(node)
            )
            if not has_auth and not has_skip:
                self.violations.append(
                    (node.lineno, f"handler '{node.name}' must call verify_token or annotate # auth-exempt")
                )

        # Check: mutable default argument
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.violations.append(
                    (node.lineno, f"function '{node.name}' has mutable default argument")
                )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        # Check: no bare except
        if node.type is None:
            self.violations.append(
                (node.lineno, "bare 'except:' clause (use 'except Exception:' at minimum)")
            )
        # Check: pass-only handler that doesn't log
        if (
            isinstance(node.type, ast.Name) and node.type.id == "Exception"
            and len(node.body) == 1
            and isinstance(node.body[0], ast.Pass)
        ):
            self.violations.append(
                (node.lineno, "empty 'except Exception: pass' (silently swallowing errors)")
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check: subprocess.run without shell=False (defaults to False, but if shell=True passed, flag it)
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in ("run", "call", "check_output", "Popen")
            ):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.violations.append(
                            (node.lineno, f"subprocess.{node.func.attr}(shell=True) — use argv list instead")
                        )

        # Check: requests.* with verify=False
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "requests"
                and node.func.attr in ("get", "post", "put", "delete", "patch", "head", "request")
            ):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        self.violations.append(
                            (node.lineno, f"requests.{node.func.attr}(verify=False) — TLS verification disabled")
                        )

        # Check: == used to compare tokens (heuristic: variable named *token*)
        # (this is fuzzy; better caught by code review, but flag obvious cases)

        self.generic_visit(node)


def main() -> int:
    targets = list(SRC_DIR.rglob("*.py"))
    total_violations = 0
    for filepath in targets:
        if filepath.name.startswith("test_"):
            continue
        try:
            tree = ast.parse(filepath.read_text())
        except SyntaxError as e:
            print(f"{filepath}: syntax error at line {e.lineno}")
            total_violations += 1
            continue
        checker = DesignPatternChecker(filepath)
        checker.visit(tree)
        for lineno, msg in checker.violations:
            print(f"{filepath.relative_to(PROJECT_ROOT)}:{lineno}: {msg}")
            total_violations += 1
    if total_violations:
        print(f"\n{total_violations} design pattern violations")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Add to `.github/workflows/ci.yml` as a new step in the lint job:

```yaml
- name: Design pattern checks
  run: python scripts/check_design_patterns.py
```

Initial run will likely produce violations. For each: either fix the violation in this PR or add it to a baseline file (`scripts/check_design_patterns_baseline.txt`) that the checker reads and ignores. The baseline is meant to shrink over time, not grow.

### Component 4: Spec-requirements YAML and validator

Create `.github/spec-requirements.yaml`:

```yaml
version: 1
description: |
  Maps code changes to required spec updates. When a PR's diff matches a rule's
  conditions, the rule's requirements must be satisfied or CI fails.

rules:
  - id: api-endpoint-changes
    description: Changes to dashboard API handlers must update API contracts
    when_file_matches:
      - "src/claude_monitoring/monitor.py"
    when_diff_contains_pattern:
      - "_handle_"
      - "do_GET"
      - "do_POST"
    requires_doc_update:
      - "docs/spec/openapi.yaml"
    requires_doc_update_optional:
      - "docs/spec/API-CONTRACTS.md"
    severity: BLOCK

  - id: auth-changes
    description: Authentication and credential handling changes must update security spec
    when_change_touches_pattern:
      - "bcrypt"
      - "hmac.compare_digest"
      - "session_token"
      - "auth_token"
      - "dashboard_token"
      - "verify_token"
      - "ensure_dashboard_token"
    requires_doc_update:
      - "docs/spec/functional/security.md"
    requires_doc_update_optional:
      - "docs/spec/THREAT-MODEL.md"
    severity: BLOCK

  - id: ca-cert-changes
    description: CA generation, trust, NameConstraints changes must update threat model
    when_change_touches_pattern:
      - "generate_custom_ca"
      - "NameConstraints"
      - "trust_ca_cert"
      - "untrust_ca_cert"
    requires_doc_update:
      - "docs/spec/THREAT-MODEL.md"
    requires_doc_update_optional:
      - "docs/spec/functional/security.md"
    severity: BLOCK

  - id: sync-sanitization-changes
    description: Sync agent sanitization changes must update sync spec and threat model
    when_change_touches_pattern:
      - "_sanitize_string"
      - "_sanitize_payload"
      - "_SANITIZE_TEXT_FIELDS"
    requires_doc_update:
      - "docs/spec/functional/sync.md"
    requires_doc_update_optional:
      - "docs/spec/THREAT-MODEL.md"
    severity: BLOCK

  - id: schema-changes
    description: Database schema changes must update architecture and data classification
    when_file_matches:
      - "src/claude_monitoring/db.py"
    when_diff_contains_pattern:
      - "CREATE TABLE"
      - "CREATE INDEX"
      - "ALTER TABLE"
    requires_doc_update:
      - "docs/ARCHITECTURE.md"
    requires_doc_update_optional:
      - "docs/spec/DATA-CLASSIFICATION.md"
      - "docs/spec/functional/db.md"
    severity: BLOCK

  - id: new-external-dependency
    description: New runtime dependencies must be justified
    when_file_matches:
      - "pyproject.toml"
    when_diff_contains_pattern:
      - "^\\+\\s*\"[\\w-]+[><=~^]"
    requires_doc:
      - "docs/spec/dependency-rationale.md"
    severity: BLOCK

  - id: workflow-changes
    description: CI workflow changes require manual human review
    when_file_matches:
      - ".github/workflows/*.yml"
    requires_review: "manual_human_review"
    severity: WARN

  - id: protocol-conformance
    description: New scanner protocol implementations need conformance tests
    when_file_matches:
      - "src/claude_monitoring/scanners/*.py"
    requires_files:
      - "tests/architecture/test_scanner_conformance.py"
    requires_doc_update_optional:
      - "docs/spec/functional/scanners.md"
    severity: WARN

  - id: hot-path-changes
    description: Changes to hot-path code should be performance-reviewed
    when_file_matches:
      - "src/claude_monitoring/monitor.py:DashboardHandler"
      - "src/claude_monitoring/utils.py"
    when_change_touches_pattern:
      - "scan_sensitive"
      - "is_ai_process"
      - "do_GET"
    requires_pr_label: "performance-reviewed"
    severity: WARN
```

Create `scripts/check_spec_requirements.py`:

```python
#!/usr/bin/env python3
"""Validate that PR diffs satisfy spec-requirements.yaml rules.

Usage: python scripts/check_spec_requirements.py --diff <patch-file>

Exits:
  0 if all BLOCK rules satisfied (WARN rules may still emit messages)
  1 if any BLOCK rule violated
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from pathlib import Path

import yaml


def parse_diff(patch_text: str) -> tuple[set[str], list[str]]:
    """Return (files_touched, all_added_lines)."""
    files = set()
    added_lines = []
    current_file = None
    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            # diff --git a/path/to/file b/path/to/file
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[3][2:]  # strip "b/"
                files.add(current_file)
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
    return files, added_lines


def rule_applies(rule: dict, files: set[str], added_text: str) -> bool:
    """Determine if the rule's conditions match this PR."""
    file_match = True
    pattern_match = True

    if "when_file_matches" in rule:
        file_match = any(
            fnmatch.fnmatch(f, pat.split(":")[0])
            for f in files
            for pat in rule["when_file_matches"]
        )

    if "when_diff_contains_pattern" in rule:
        pattern_match = any(
            re.search(pat, added_text)
            for pat in rule["when_diff_contains_pattern"]
        )

    if "when_change_touches_pattern" in rule:
        pattern_match = pattern_match and any(
            pat in added_text
            for pat in rule["when_change_touches_pattern"]
        )

    # If both conditions are specified, both must match
    if "when_file_matches" in rule and ("when_diff_contains_pattern" in rule or "when_change_touches_pattern" in rule):
        return file_match and pattern_match
    if "when_file_matches" in rule:
        return file_match
    return pattern_match


def rule_satisfied(rule: dict, files: set[str], added_text: str) -> tuple[bool, list[str]]:
    """Check if the rule's requirements are satisfied. Returns (ok, missing_list)."""
    missing = []
    if "requires_doc_update" in rule:
        for doc in rule["requires_doc_update"]:
            if doc not in files:
                missing.append(f"doc not updated: {doc}")
    if "requires_doc" in rule:
        for doc in rule["requires_doc"]:
            if not Path(doc).exists() and doc not in files:
                missing.append(f"required doc missing: {doc}")
    if "requires_files" in rule:
        for f in rule["requires_files"]:
            if not Path(f).exists() and f not in files:
                missing.append(f"required file missing: {f}")
    # requires_pr_label and requires_review are out-of-band; not checkable here
    return (len(missing) == 0, missing)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--diff", required=True, help="Path to unified diff patch file")
    parser.add_argument("--rules", default=".github/spec-requirements.yaml")
    args = parser.parse_args()

    rules_doc = yaml.safe_load(Path(args.rules).read_text())
    patch_text = Path(args.diff).read_text()
    files, added_lines = parse_diff(patch_text)
    added_text = "\n".join(added_lines)

    if not files:
        print("No file changes detected; spec-requirements check passes vacuously")
        return 0

    block_violations = 0
    warn_violations = 0

    for rule in rules_doc.get("rules", []):
        if not rule_applies(rule, files, added_text):
            continue

        ok, missing = rule_satisfied(rule, files, added_text)
        if ok:
            continue

        severity = rule.get("severity", "BLOCK")
        prefix = "❌ BLOCK" if severity == "BLOCK" else "⚠ WARN"
        print(f"\n{prefix} rule '{rule['id']}': {rule['description']}")
        for m in missing:
            print(f"  - {m}")

        if severity == "BLOCK":
            block_violations += 1
        else:
            warn_violations += 1

    print(f"\n{block_violations} blocking, {warn_violations} warnings")
    return 1 if block_violations else 0


if __name__ == "__main__":
    sys.exit(main())
```

Add the dependency: `pip install pyyaml` (likely already present).

### Component 5: CI workflow integration

Add to `.github/workflows/ci.yml`:

```yaml
  spec-requirements:
    name: spec-requirements
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pyyaml
      - name: Generate PR diff
        run: git diff origin/${{ github.base_ref }}...HEAD > /tmp/pr.patch
      - name: Check spec requirements
        run: python scripts/check_spec_requirements.py --diff /tmp/pr.patch
```

After this PR merges and CI runs once on a follow-up PR, manually add `spec-requirements` to the required status checks via the branch protection ruleset (user-domain action; cannot be done by Claude Code).

### Component 6: PR template with criticality

Create `.github/pull_request_template.md`:

```markdown
## Summary

(One-paragraph description of what this PR does and why.)

## Criticality (required — select one)

- [ ] **C0** docs-only, no code paths affected
- [ ] **C1** tests or scripts, no production behavior
- [ ] **C2** feature addition, no security implication
- [ ] **C3** feature with security implication or hot-path touch
- [ ] **C4** auth, secrets, crypto, trust boundary

C3 and C4 require human diff review even if all agents pass.

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

## Threat surface

Trust boundaries this change crosses (from `docs/spec/THREAT-MODEL.md`):

- [ ] B1 — User ↔ Dashboard
- [ ] B2 — Daemon ↔ DB
- [ ] B3 — Daemon ↔ Control Plane
- [ ] B4 — Proxy ↔ AI APIs
- [ ] B5 — Browser Extension ↔ Daemon
- [ ] None (purely internal change)
```

### Component 7: SSDLC_ENFORCEMENT.md update

Update `docs/SSDLC_ENFORCEMENT.md` to add Layer 6.5 documenting the spec-driven enforcement:

```markdown
## Layer 6.5: Spec-driven enforcement (new in PR #N)

Between branch protection (Layer 6) and release gates (Layer 7), the spec-requirements
enforcement layer mechanically ensures that code changes carry corresponding spec updates.

### What it enforces

The `.github/spec-requirements.yaml` rules table maps code patterns to required spec
updates. The `scripts/check_spec_requirements.py` validator runs as a CI gate on every PR
and fails the build when:

- A change touches authentication code without updating the security spec
- A change touches the API surface without updating openapi.yaml
- A change adds a new dependency without rationale
- A change modifies the DB schema without updating architecture or data classification
- A change touches CA generation without updating the threat model
- A change modifies the sync sanitizer without updating the sync spec

### Source-honesty contract

Layer 6.5 also codifies the source-honesty rules (also in CLAUDE.md):

- Missing requirements are logged as "not yet authored," never invented
- Derived architectural decisions are surfaced for ratification, not silently merged
- Code-spec divergence requires explicit revision PR or revert

### Criticality classification

Every PR is classified C0-C4 via the PR template. C3 (security/hot-path) and C4
(auth/secrets/crypto/boundary) require human review beyond agent verdicts.

### Where the rules live

- `.github/spec-requirements.yaml` — the rules table
- `scripts/check_spec_requirements.py` — the validator
- `.github/pull_request_template.md` — criticality + spec coverage checklist
- `CLAUDE.md` — mandatory patterns enforced at write time
- `scripts/check_design_patterns.py` — AST checks beyond ruff
- `pyproject.toml` `[tool.ruff]` — write-time linting
```

## Discipline rules

- **The spec-requirements.yaml is a living document.** New rules get added as new patterns emerge. Each rule has a documented rationale in YAML comments.
- **The validator is read-only.** It reports violations; it never modifies files.
- **When a rule fires and the fix is non-trivial, log the gap as "not yet authored"** per source-honesty contract rather than inventing the missing artifact.
- **Manual human review (for workflow changes etc.) goes through the standard PR approval flow.** The rule just requires a human to look, not just CI.
- **WARN-severity rules emit messages but don't fail CI.** Use these for guidance toward best practices that aren't yet hard requirements.

## Pre-PR review applies

This PR runs through the three-agent pipeline. Specifically:

- **Architect agent** must validate that the YAML rules are coherent with the SSDLC framework and that the design pattern checker doesn't overlap with ruff in confusing ways
- **Performance agent** must confirm the validator script doesn't introduce CI bloat (target: < 5 seconds runtime even on large diffs)
- **Code review agent** must verify the AST checker handles edge cases (decorators, async functions, nested classes)

## Verification steps after merge

After this PR merges:

1. Open a test PR that intentionally violates each rule. Verify CI fails appropriately.
2. Open a test PR that satisfies all rules. Verify CI passes.
3. Add `spec-requirements` to required status checks (user-domain action via GitHub UI).
4. Document the verification in the PR comments for future reference.

## Stop and ping me when

- All seven components are implemented as one cohesive PR
- The three-agent pipeline has run with consolidated verdict
- A test PR demonstrating each rule's enforcement is prepared (but not necessarily merged)

I will review the consolidated verdict and approve the merge if the rules look correct.

## Commit message format

Use squash-merge with a structured commit message:

```
ci(enforcement): spec-driven mechanical guardrails (#N)

Adds CLAUDE.md project constitution, aggressive ruff rules, custom AST
checker, spec-requirements YAML + validator, criticality PR template,
and SSDLC layer 6.5 documentation.

Co-authored: Rajan Yadav <rajan.conch@gmail.com>
```

## What this PR does not do

- Does NOT add `spec-requirements` to required status checks (user-domain GitHub UI action)
- Does NOT enable mypy strict mode (separate Phase 3G PR)
- Does NOT add the design-doc trigger automation (separate Phase 3G PR)
- Does NOT replace the current code-reviewer + architect + performance agent pipeline (Layer 8 stays)
- Does NOT change the merge strategy or branching rules (BRANCHING.md stays as-is)

End of dispatch.
