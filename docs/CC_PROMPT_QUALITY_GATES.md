# Claude Code Sprint Prompt — Track Q: Code-Enforced Quality Gates

## Mission

Install the seven-layer code-enforcement stack. After this lands, neither
agents nor humans can ship code that violates style, type safety, test
coverage, mutation quality, architecture rules, security policy, or
release policy. The harness hooks become thin wrappers around these gates.

## Branch

```
git checkout -b infra/quality-gates
```

## Files to Create or Update

```
ai-runtime-monitor/
├── Makefile                                  # single entrypoint for every gate
├── pyproject.toml                            # Python tool configs (extend)
├── .pre-commit-config.yaml                   # Layer 3
├── .github/
│   ├── CODEOWNERS                            # auto-request reviews
│   ├── workflows/
│   │   ├── ci-python.yml                     # Layer 5
│   │   ├── ci-desktop.yml                    # Tauri + Rust
│   │   ├── ci-site.yml                       # Next.js
│   │   ├── ci-architecture.yml               # import-linter + complexity
│   │   ├── ci-security.yml                   # bandit + semgrep + pip-audit + trivy
│   │   ├── ci-mutation.yml                   # mutmut on changed modules
│   │   ├── ci-supply-chain.yml               # SBOM, sigstore attestation
│   │   ├── release.yml                       # notarize + sign + publish
│   │   └── branch-protection.yml             # documents protection rules
│   └── pull_request_template.md
├── tests/
│   ├── conftest.py                           # extend with strict markers
│   ├── _plugins/
│   │   └── functional_coverage.py            # custom: every src module has tests/integration
│   └── architecture/
│       └── test_layering.py                  # import-linter conformance tests
├── importlinter.cfg                          # architecture fitness rules
├── .mutmut.cfg                               # mutation testing config
├── .secrets.baseline                         # detect-secrets baseline
├── desktop/
│   ├── Cargo.toml                            # extend with clippy + deny configs
│   ├── clippy.toml
│   ├── deny.toml                             # cargo-deny rules
│   └── .cargo/config.toml                    # strict warnings
├── claude_monitoring/dashboard/app/
│   ├── package.json                          # extend with quality scripts
│   ├── eslint.config.mjs                     # strict
│   ├── tsconfig.json                         # strict everywhere
│   └── .size-limit.json                      # bundle size budget
└── docs/
    ├── ARCHITECTURE.md                       # the layering rules in prose
    ├── QUALITY_GATES.md                      # this file as project doc
    └── ADR/                                  # architectural decision records
        └── 0001-template.md
```

## Makefile (single source of truth)

```makefile
.PHONY: help format lint type test test-unit test-integration test-e2e \
        coverage mutation security architecture deps-audit complexity \
        docs-coverage ci-local ci-fast ci-full clean

PYTHON := python3.12
PIP := $(PYTHON) -m pip
COVERAGE_MIN := 90
MUTATION_MIN := 70
BRANCH_COVERAGE_MIN := 85

help:
	@echo "Quality Gates — every check runs in CI. Run locally before pushing."
	@echo ""
	@echo "  make ci-fast      Layer 1-3 (pre-commit equivalent, ~30 sec)"
	@echo "  make ci-local     Layer 4 (full local CI, ~5 min)"
	@echo "  make ci-full      Layer 5 (everything including mutation, ~30 min)"
	@echo ""
	@echo "Individual gates:"
	@echo "  make format       Auto-format Python + Rust + TS"
	@echo "  make lint         ruff + clippy + eslint, no fixes"
	@echo "  make type         mypy --strict + tsc --noEmit + cargo check"
	@echo "  make test         Full pytest + vitest + cargo test"
	@echo "  make coverage     pytest --cov, fail if < $(COVERAGE_MIN)%"
	@echo "  make mutation     mutmut on changed modules, fail if < $(MUTATION_MIN)%"
	@echo "  make security     bandit + semgrep + pip-audit + cargo-audit"
	@echo "  make architecture import-linter, complexity, file size limits"
	@echo "  make deps-audit   pip-audit, cargo-audit, npm-audit, license check"

# === Layer 1-2: types and editor ===

format:
	ruff format claude_monitoring tests
	cd desktop && cargo fmt
	cd claude_monitoring/dashboard/app && npm run format
	cd ../airuntimemonitor-site 2>/dev/null && npm run format || true

lint:
	ruff check claude_monitoring tests --no-fix
	cd desktop && cargo clippy --all-targets --all-features -- -D warnings
	cd claude_monitoring/dashboard/app && npm run lint

type:
	mypy --strict claude_monitoring
	cd desktop && cargo check --all-targets --all-features
	cd claude_monitoring/dashboard/app && npm run typecheck

# === Layer 3: tests ===

test: test-unit test-integration

test-unit:
	pytest tests/unit -v --no-cov

test-integration:
	pytest tests/integration -v --no-cov

test-e2e:
	pytest tests/e2e -v --no-cov

coverage:
	pytest tests/ \
		--cov=claude_monitoring \
		--cov-branch \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-report=xml \
		--cov-fail-under=$(COVERAGE_MIN) \
		--strict-markers \
		--strict-config
	@$(PYTHON) scripts/check_branch_coverage.py $(BRANCH_COVERAGE_MIN)
	@$(PYTHON) scripts/check_functional_coverage.py

mutation:
	@$(PYTHON) scripts/run_mutation_on_changed.py --min-score $(MUTATION_MIN)

# === Layer 4: architecture and complexity ===

architecture:
	lint-imports --config importlinter.cfg
	radon cc claude_monitoring --min C --total-average
	radon mi claude_monitoring --min B
	radon raw claude_monitoring --summary
	$(PYTHON) scripts/check_file_size.py --max-lines 500 claude_monitoring/
	$(PYTHON) scripts/check_function_size.py --max-lines 50 claude_monitoring/
	vulture claude_monitoring --min-confidence 80 || true

complexity:
	radon cc claude_monitoring --min B --show-complexity
	xenon --max-absolute B --max-modules A --max-average A claude_monitoring

# === Layer 5: security ===

security:
	bandit -r claude_monitoring -c pyproject.toml
	semgrep --config=auto --error claude_monitoring
	detect-secrets scan --baseline .secrets.baseline
	pip-audit
	cd desktop && cargo audit
	cd desktop && cargo deny check
	cd claude_monitoring/dashboard/app && npm audit --audit-level=moderate
	$(PYTHON) scripts/check_no_eval_or_exec.py claude_monitoring/

deps-audit:
	pip-audit --strict
	pip-licenses --fail-on="GPL;AGPL;LGPL" --format=markdown
	cd desktop && cargo deny check licenses advisories bans
	cd claude_monitoring/dashboard/app && license-checker --failOn 'GPL;AGPL'

docs-coverage:
	interrogate -v claude_monitoring --fail-under 80 \
		--ignore-init-method --ignore-magic --ignore-private

# === Composite targets ===

ci-fast: format lint type
	@echo "✓ Fast gates passed (Layer 1-3 equivalent)"

ci-local: ci-fast test coverage architecture security
	@echo "✓ Local CI passed (Layer 4 equivalent)"

ci-full: ci-local mutation deps-audit docs-coverage
	@echo "✓ Full CI passed (Layer 5 equivalent — ready to push)"

clean:
	rm -rf .coverage htmlcov coverage.xml .mypy_cache .ruff_cache
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__
	cd desktop && cargo clean
	cd claude_monitoring/dashboard/app && rm -rf node_modules/.cache dist
```

## pyproject.toml (extend existing)

```toml
[tool.ruff]
line-length = 100
target-version = "py312"
extend-exclude = ["migrations", ".worktrees"]

[tool.ruff.lint]
select = [
    "E", "F", "W",      # pycodestyle + pyflakes
    "B",                # bugbear (likely bugs)
    "S",                # bandit security checks
    "SIM",              # simplifications
    "UP",               # pyupgrade
    "RUF",              # ruff-specific
    "PL",               # pylint
    "TRY",              # tryceratops (exception anti-patterns)
    "PERF",             # perflint
    "ANN",              # missing type annotations
    "ASYNC",            # async anti-patterns
    "PTH",              # use pathlib
    "RET",              # return statement issues
    "ARG",              # unused arguments
    "ERA",              # commented-out code
    "PD",               # pandas anti-patterns (skip if no pandas)
    "PGH",              # pygrep hooks
    "COM",              # trailing commas
    "DTZ",              # datetime timezone awareness
    "ICN",              # import conventions
    "PIE",              # misc lints
    "T20",              # print statements
    "RSE",              # raise statements
    "SLF",              # private member access
    "TCH",              # type-checking import blocks
    "TID",              # tidy imports
    "YTT",              # sys.version misuse
]
ignore = [
    "ANN401",           # allow Any in clearly intended places
    "S101",             # asserts ok in tests
    "TRY003",           # long messages in exceptions are fine
    "COM812",           # conflicts with formatter
]

[tool.ruff.lint.per-file-ignores]
"tests/**/*" = ["S101", "ANN", "PLR2004", "SLF001"]
"scripts/**/*" = ["T20"]

[tool.ruff.lint.flake8-tidy-imports.banned-api]
"typing.Any".msg = "Use a specific type. If you really need Any, add a # noqa with a comment explaining why."

[tool.mypy]
python_version = "3.12"
strict = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_return_any = true
warn_unreachable = true
disallow_any_unimported = true
disallow_any_expr = false  # too aggressive
disallow_any_decorated = true
disallow_any_explicit = false  # allow explicit Any with comment
disallow_any_generics = true
disallow_subclassing_any = true
disallow_untyped_calls = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
strict_optional = true
strict_equality = true
extra_checks = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false  # tests can be looser

[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
addopts = [
    "--strict-markers",
    "--strict-config",
    "--tb=short",
    "-p", "no:cacheprovider",
    "--import-mode=importlib",
    "-W", "error",  # warnings are errors
]
markers = [
    "unit: fast, isolated, no I/O",
    "integration: real I/O, real DB, may take seconds",
    "e2e: full system, may take minutes",
    "slow: deselect with -m 'not slow'",
    "security: security-relevant test (must exist for security code)",
    "functional: covers a user-facing feature end-to-end",
]
filterwarnings = [
    "error",
    "ignore::DeprecationWarning:botocore.*",  # third-party noise
]

[tool.coverage.run]
branch = true
source = ["claude_monitoring"]
omit = [
    "*/migrations/*",
    "*/__main__.py",
    "*/conftest.py",
]
parallel = true

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "raise NotImplementedError",
    "if TYPE_CHECKING:",
    "if __name__ == .__main__.:",
    "@overload",
    "@abstractmethod",
]
show_missing = true
precision = 2
skip_covered = false
fail_under = 90

[tool.bandit]
exclude_dirs = ["tests", "scripts"]
skips = ["B101"]  # assert in tests

[tool.interrogate]
ignore-init-method = true
ignore-magic = true
ignore-private = true
ignore-semiprivate = false
fail-under = 80
exclude = ["tests", "build", "docs"]
verbose = 1

[tool.vulture]
min_confidence = 80
paths = ["claude_monitoring"]
exclude = ["tests", "*/migrations/*"]
```

## .pre-commit-config.yaml (Layer 3, local fast feedback)

```yaml
default_install_hook_types: [pre-commit, pre-push, commit-msg]
default_stages: [pre-commit]
fail_fast: false

repos:
  # === Layer 1: file hygiene ===
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-toml
      - id: check-merge-conflict
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-case-conflict
      - id: check-executables-have-shebangs
      - id: check-symlinks
      - id: detect-private-key
      - id: forbid-new-submodules
      - id: mixed-line-ending
        args: ['--fix=lf']

  # === Layer 2: secrets ===
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: package-lock\.json

  # === Layer 3: Python ===
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.0
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies:
          - types-requests
          - types-PyYAML
          - pydantic
        args: [--strict]
        files: ^claude_monitoring/

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.9
    hooks:
      - id: bandit
        args: ['-c', 'pyproject.toml']
        exclude: ^tests/

  # === Layer 3: Rust ===
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: bash -c 'cd desktop && cargo fmt -- --check'
        language: system
        files: \.rs$
        pass_filenames: false
      - id: cargo-clippy
        name: cargo clippy
        entry: bash -c 'cd desktop && cargo clippy --all-targets -- -D warnings'
        language: system
        files: \.rs$
        pass_filenames: false

  # === Layer 3: TypeScript ===
  - repo: local
    hooks:
      - id: eslint
        name: eslint dashboard
        entry: bash -c 'cd claude_monitoring/dashboard/app && npm run lint'
        language: system
        files: \.(ts|tsx|js|jsx)$
        pass_filenames: false
      - id: tsc
        name: tsc dashboard
        entry: bash -c 'cd claude_monitoring/dashboard/app && npm run typecheck'
        language: system
        files: \.(ts|tsx)$
        pass_filenames: false

  # === Layer 3: shell scripts ===
  - repo: https://github.com/koalaman/shellcheck-precommit
    rev: v0.10.0
    hooks:
      - id: shellcheck

  # === Layer 3: markdown ===
  - repo: https://github.com/igorshubovych/markdownlint-cli
    rev: v0.41.0
    hooks:
      - id: markdownlint
        args: ['--config', '.markdownlint.json']

  # === Commit message format ===
  - repo: https://github.com/compilerla/conventional-pre-commit
    rev: v3.4.0
    hooks:
      - id: conventional-pre-commit
        stages: [commit-msg]
        args: []

  # === Layer 4: pre-push runs full local CI ===
  - repo: local
    hooks:
      - id: ci-local
        name: full local CI
        entry: make ci-local
        language: system
        stages: [pre-push]
        pass_filenames: false
        always_run: true
```

## importlinter.cfg (architecture fitness)

```ini
[importlinter]
root_package = claude_monitoring
include_external_packages = True

# Layered architecture: lower layers cannot import from upper layers.
[importlinter:contract:layered-architecture]
name = Layered architecture
type = layers
layers =
    claude_monitoring.api
    claude_monitoring.dashboard
    claude_monitoring.services
    claude_monitoring.adapters
    claude_monitoring.domain
    claude_monitoring.common

# The extension scanner is a self-contained subsystem.
[importlinter:contract:extension-scanner-isolation]
name = Extension scanner does not import from dashboard or api
type = forbidden
source_modules =
    claude_monitoring.extension_scanner
forbidden_modules =
    claude_monitoring.dashboard
    claude_monitoring.api

# The dashboard never imports daemon internals directly.
[importlinter:contract:dashboard-uses-api-only]
name = Dashboard talks to daemon only via API client
type = forbidden
source_modules =
    claude_monitoring.dashboard
forbidden_modules =
    claude_monitoring.proxy
    claude_monitoring.collectors
    claude_monitoring.daemon

# Adapters cannot depend on services (dependency inversion).
[importlinter:contract:dependency-inversion]
name = Adapters cannot depend on services
type = forbidden
source_modules =
    claude_monitoring.adapters
forbidden_modules =
    claude_monitoring.services

# No domain code touches the network or filesystem directly.
[importlinter:contract:domain-purity]
name = Domain layer is pure
type = forbidden
source_modules =
    claude_monitoring.domain
forbidden_modules =
    requests
    httpx
    aiohttp
    socket
    pathlib

# Tests cannot reach into private modules.
[importlinter:contract:test-public-api-only]
name = Tests use only public APIs
type = forbidden
source_modules =
    tests
forbidden_modules =
    claude_monitoring.*._internal
    claude_monitoring.*._private
```

## .github/workflows/ci-python.yml (Layer 5)

```yaml
name: CI Python
on:
  pull_request:
  push:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  fast-gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: pip
      - run: pip install -e ".[dev,test]"
      - run: make ci-fast

  tests:
    runs-on: ${{ matrix.os }}
    needs: fast-gates
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-14]
        python-version: ['3.12']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: pip install -e ".[dev,test]"
      - run: make coverage
      - uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: true

  coverage-ratchet:
    runs-on: ubuntu-latest
    needs: tests
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e ".[dev,test]"
      - name: Coverage on base branch
        run: |
          git checkout ${{ github.base_ref }}
          make coverage
          mv coverage.xml coverage-base.xml
      - name: Coverage on PR branch
        run: |
          git checkout ${{ github.head_ref }}
          make coverage
      - name: Ratchet check
        run: python scripts/coverage_ratchet.py coverage-base.xml coverage.xml
        # Fails if line coverage drops > 0.1% or branch coverage drops > 0.5%

  functional-coverage:
    runs-on: ubuntu-latest
    needs: fast-gates
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e ".[dev,test]"
      - name: Every src module has a functional test
        run: python scripts/check_functional_coverage.py --strict
```

## .github/workflows/ci-architecture.yml

```yaml
name: CI Architecture
on:
  pull_request:
  push:
    branches: [main]

jobs:
  layering:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e ".[dev]"
      - run: lint-imports --config importlinter.cfg

  complexity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install radon xenon
      - name: Cyclomatic complexity
        run: |
          xenon --max-absolute B --max-modules A --max-average A claude_monitoring
      - name: Maintainability index
        run: |
          radon mi claude_monitoring --min B
      - name: File and function size
        run: |
          python scripts/check_file_size.py --max-lines 500 claude_monitoring/
          python scripts/check_function_size.py --max-lines 50 claude_monitoring/

  dead-code:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vulture
      - run: vulture claude_monitoring --min-confidence 90

  docs-coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install interrogate
      - run: interrogate -v claude_monitoring --fail-under 80
```

## .github/workflows/ci-mutation.yml

```yaml
name: CI Mutation Testing
on:
  pull_request:
    paths:
      - 'claude_monitoring/**/*.py'
  schedule:
    - cron: '0 6 * * 1'  # Weekly full run on Monday morning

jobs:
  mutation-changed:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e ".[dev,test]" mutmut
      - name: Mutation test on changed files
        run: |
          CHANGED_FILES=$(git diff --name-only origin/${{ github.base_ref }}...HEAD \
            | grep '\.py$' | grep '^claude_monitoring/' || true)
          if [ -z "$CHANGED_FILES" ]; then
            echo "No Python changes — skipping mutation"
            exit 0
          fi
          mutmut run --paths-to-mutate "$CHANGED_FILES" --runner "pytest -x -q"
          SCORE=$(mutmut results | awk '/killed/ {killed=$2} /total/ {total=$2} END {print killed/total*100}')
          echo "Mutation score: $SCORE%"
          if (( $(echo "$SCORE < 70" | bc -l) )); then
            echo "FAIL: mutation score $SCORE% below threshold 70%"
            mutmut results
            exit 1
          fi

  mutation-full:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    timeout-minutes: 360
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e ".[dev,test]" mutmut
      - run: mutmut run --paths-to-mutate claude_monitoring/
      - run: mutmut results > mutation-report.txt
      - uses: actions/upload-artifact@v4
        with:
          name: mutation-report
          path: mutation-report.txt
```

## .github/workflows/ci-security.yml

```yaml
name: CI Security
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 4 * * *'  # daily

jobs:
  sast-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install bandit semgrep
      - run: bandit -r claude_monitoring -c pyproject.toml -f json -o bandit.json
      - run: semgrep --config=auto --config=p/security-audit --error claude_monitoring
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: bandit.json
          category: bandit

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

  dependencies-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install pip-audit
      - run: pip-audit --strict

  dependencies-rust:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: desktop } }
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: EmbarkStudios/cargo-deny-action@v1
      - run: cargo install cargo-audit
      - run: cargo audit

  dependencies-node:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: cd claude_monitoring/dashboard/app && npm audit --audit-level=moderate

  containers:
    runs-on: ubuntu-latest
    if: hashFiles('**/Dockerfile') != ''
    steps:
      - uses: actions/checkout@v4
      - uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          exit-code: 1

  iac:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          soft_fail: false
```

## .github/workflows/ci-supply-chain.yml

```yaml
name: CI Supply Chain
on:
  pull_request:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e . cyclonedx-bom
      - run: cyclonedx-py -o sbom.json
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: sbom.json }

  attestation:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: sbom
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: write
      attestations: write
    steps:
      - uses: actions/download-artifact@v4
        with: { name: sbom }
      - uses: actions/attest-build-provenance@v1
        with: { subject-path: sbom.json }
      - uses: actions/attest-sbom@v1
        with:
          subject-path: '*.whl,*.tar.gz,*.dmg'
          sbom-path: sbom.json

  licenses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e . pip-licenses
      - run: pip-licenses --fail-on="GPL;AGPL;LGPL;SSPL"
```

## Custom Quality Scripts

### `scripts/check_functional_coverage.py`

```python
"""Enforce: every src module has a corresponding integration test.

Run this in CI. Fails if a public module lacks a functional/integration
test mapping. This is what "100% functional coverage" means in practice.
"""
import argparse
import sys
from pathlib import Path

SRC_ROOT = Path("claude_monitoring")
TEST_ROOT = Path("tests/integration")

# Modules that are exempt (e.g., pure type stubs, generated code)
EXEMPT = {
    "claude_monitoring/__init__.py",
    "claude_monitoring/_version.py",
}

def find_unmapped_modules() -> list[Path]:
    unmapped = []
    for src_file in SRC_ROOT.rglob("*.py"):
        if src_file.name.startswith("_"):
            continue
        if str(src_file) in EXEMPT:
            continue
        if src_file.parent.name in {"migrations", "__pycache__"}:
            continue

        # Compute expected test path
        rel = src_file.relative_to(SRC_ROOT)
        test_candidate = TEST_ROOT / rel.parent / f"test_{rel.stem}.py"

        if not test_candidate.exists():
            unmapped.append(src_file)

    return unmapped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    unmapped = find_unmapped_modules()

    if unmapped:
        print(f"FAIL: {len(unmapped)} modules without integration tests:")
        for path in unmapped:
            rel = path.relative_to(SRC_ROOT)
            expected = TEST_ROOT / rel.parent / f"test_{rel.stem}.py"
            print(f"  {path} -> expected {expected}")
        if args.strict:
            return 1

    print(f"OK: {len(list(SRC_ROOT.rglob('*.py')))} modules mapped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### `scripts/coverage_ratchet.py`

```python
"""Coverage cannot drop on a PR. Period."""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def line_rate(xml_path: Path) -> tuple[float, float]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    line = float(root.attrib["line-rate"]) * 100
    branch = float(root.attrib["branch-rate"]) * 100
    return line, branch


def main() -> int:
    base = Path(sys.argv[1])
    pr = Path(sys.argv[2])

    base_line, base_branch = line_rate(base)
    pr_line, pr_branch = line_rate(pr)

    print(f"Base:   line={base_line:.2f}%  branch={base_branch:.2f}%")
    print(f"PR:     line={pr_line:.2f}%  branch={pr_branch:.2f}%")

    line_drop = base_line - pr_line
    branch_drop = base_branch - pr_branch

    if line_drop > 0.1:
        print(f"FAIL: line coverage dropped by {line_drop:.2f}%")
        return 1
    if branch_drop > 0.5:
        print(f"FAIL: branch coverage dropped by {branch_drop:.2f}%")
        return 1

    print("OK: coverage maintained or improved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### `scripts/check_file_size.py` and `scripts/check_function_size.py`

(Implement using `ast` module. Fail if any non-test file exceeds N lines.
Fail if any function exceeds M lines. Exempt: test files, generated code,
files with `# pragma: noqa: file-size` at the top.)

## Branch Protection (`docs/QUALITY_GATES.md` — apply via GitHub UI or `gh`)

```
Branch: main
Settings to apply via GitHub repo settings or `gh api`:

Required status checks (all must pass before merge):
  ✓ ci-python / fast-gates
  ✓ ci-python / tests (ubuntu-latest, 3.12)
  ✓ ci-python / tests (macos-14, 3.12)
  ✓ ci-python / coverage-ratchet
  ✓ ci-python / functional-coverage
  ✓ ci-architecture / layering
  ✓ ci-architecture / complexity
  ✓ ci-architecture / dead-code
  ✓ ci-architecture / docs-coverage
  ✓ ci-mutation / mutation-changed
  ✓ ci-security / sast-python
  ✓ ci-security / secrets
  ✓ ci-security / dependencies-python
  ✓ ci-supply-chain / sbom

Other requirements:
  ✓ Require pull request reviews before merging (minimum 1)
  ✓ Require review from CODEOWNERS
  ✓ Dismiss stale reviews on push
  ✓ Require conversation resolution before merging
  ✓ Require signed commits
  ✓ Require linear history (no merge commits, squash or rebase only)
  ✓ Require branches to be up to date before merging
  ✓ Restrict who can push to matching branches: empty (no one)
  ✓ Allow force pushes: no
  ✓ Allow deletions: no

Apply via gh:
  gh api repos/rajan-cforge/ai-runtime-monitor/branches/main/protection \
    -X PUT --input branch-protection.json
```

## Integration with the Multi-Agent Harness

The harness from CC_PROMPT_00 already has hooks. Update them to delegate
to make targets, not invent their own checks:

```bash
# .claude/hooks/post-edit.sh — simplified
#!/usr/bin/env bash
set -e
file="$CLAUDE_HOOK_EDITED_FILE"

# Run only the gate that's fast enough for an inline hook
case "$file" in
  *.py)    ruff format "$file" && ruff check "$file" ;;
  *.rs)    rustfmt "$file" ;;
  *.ts|*.tsx) cd $(dirname "$file") && prettier --write "$file" ;;
esac

# .claude/hooks/stop.sh — refuse to release control unless ci-local passes
#!/usr/bin/env bash
set -e
echo "Running make ci-local before session end..."
if ! make ci-local; then
  echo "BLOCKED: ci-local failed. Fix before ending session."
  exit 1
fi
```

The grader subagents in `.claude/agents/code-reviewer.md` and
`security-reviewer.md` should also invoke these gates and treat their
output as evidence, not produce their own opinions on style.

## Gotchas

- **Mutation testing is slow.** Full-repo mutation takes hours. Only
  run it on changed files in PRs, full suite weekly via cron.
- **Coverage gaming.** Without mutation testing, agents will write
  tests that touch lines but assert nothing. The mutation gate is the
  honest measure of test quality.
- **import-linter requires accurate layer definitions.** If the layers
  are wrong, the rule is wrong. Update `importlinter.cfg` when you
  intentionally add a new layer.
- **Signed commits require GPG or SSH signing setup.** Without it, no
  one (including agents) can push to main. Set this up on Day 0.
- **`make ci-full` is the right local pre-push gate.** `make ci-local`
  is fast enough for the harness Stop hook. `make ci-fast` is the
  pre-commit gate.
- **Functional coverage check is opinionated.** It requires a
  `tests/integration/test_<module>.py` per src module. If your repo
  structure differs, update `scripts/check_functional_coverage.py`
  to match before turning on `--strict`.
- **Pre-commit can be bypassed with `--no-verify`.** Branch protection
  cannot. The CI workflows are the real gate.
- **Cyclomatic complexity threshold B (1-10).** Some legitimately
  complex code (state machines, parsers) will need `# noqa` exemptions
  with comments explaining why. Do not lower the threshold globally.

## Verification Checklist

```bash
# 1. Pre-commit installs and runs
pre-commit install --install-hooks
pre-commit run --all-files

# 2. Makefile targets all exist and run
make help
make ci-fast
make ci-local

# 3. Coverage gate fails on artificial drop
git checkout -b test/coverage-gate
echo "def untested(): pass" >> claude_monitoring/__init__.py
make coverage
# Expected: fails because untested() reduces coverage

# 4. Architecture rule fires on a violation
git checkout -b test/architecture-gate
echo "from claude_monitoring.proxy import *" >> claude_monitoring/dashboard/app.py
make architecture
# Expected: lint-imports reports violation of dashboard-uses-api-only

# 5. Mutation testing runs on changed files
git checkout -b test/mutation
# Modify a function such that one mutation survives
make mutation
# Expected: fail with mutation score < 70%

# 6. Branch protection blocks direct push to main
git checkout main
echo "test" >> README.md
git commit -am "test"
git push
# Expected: rejected by branch protection

# 7. CI workflows visible in GitHub Actions
gh workflow list

# 8. All gates pass on a clean main
git checkout main && git pull
make ci-full
# Expected: every gate green
```

## First Commit

```
infra(quality): seven-layer code-enforced quality gate stack

- Makefile with composite targets (ci-fast, ci-local, ci-full)
- pyproject.toml with strict ruff, mypy, pytest, coverage configs
- .pre-commit-config.yaml with fast local gates
- importlinter.cfg with layered architecture rules
- 8 GitHub Actions workflows covering Python, desktop, site,
  architecture, security, mutation, supply chain, release
- Custom scripts: functional coverage, coverage ratchet,
  file/function size checks
- Branch protection documentation

Coverage gate: 90% line, 85% branch, 70% mutation.
Architecture gate: layered + extension-scanner isolation +
  dashboard isolation + dependency inversion + domain purity.
Security gate: bandit + semgrep + trufflehog + pip-audit + cargo
  audit + cargo deny + npm audit + checkov + trivy.
Release gate: SBOM + sigstore attestation + signed commits +
  Apple notarization + Tauri update signing.

This stack runs regardless of whether the change came from an
agent, a human, or a script. Hooks in .claude/ now delegate to
make targets instead of inventing their own checks.

Refs: Boris Cherny code-enforced must-haves pattern,
      Anthropic's published CI patterns,
      the seven-layer enforcement model in docs/QUALITY_GATES.md
```
