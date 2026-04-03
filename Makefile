.PHONY: install dev test lint format clean start start-deep stop status verify configure help coverage e2e security ci

# Auto-detect python/pip — prefer .venv, then python3.12, then python3
PYTHON := $(shell \
	if [ -x .venv/bin/python ]; then echo .venv/bin/python; \
	elif command -v python3.12 >/dev/null 2>&1; then echo python3.12; \
	elif command -v python3 >/dev/null 2>&1; then echo python3; \
	else echo python; fi)
PIP := $(PYTHON) -m pip

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

check-python:
	@if [ -z "$(PYTHON)" ]; then \
		echo "Error: Python not found. Install Python 3.9+ from https://python.org"; \
		exit 1; \
	fi
	@if [ -z "$(PIP)" ]; then \
		echo "Error: pip not found. Try: $(PYTHON) -m ensurepip --upgrade"; \
		exit 1; \
	fi

install: check-python ## Install ai-runtime-monitor (one-click setup)
	$(PIP) install -e .
	@echo ""
	@# Check if ai-monitor is on PATH
	@if command -v ai-monitor >/dev/null 2>&1; then \
		echo "  \033[32m✓\033[0m ai-monitor is on PATH"; \
	else \
		echo "  \033[33m⚠\033[0m ai-monitor not on PATH."; \
		for d in $$HOME/.local/bin $$HOME/Library/Python/3.12/bin $$HOME/Library/Python/3.11/bin $$HOME/Library/Python/3.10/bin $$HOME/Library/Python/3.9/bin; do \
			if [ -f "$$d/ai-monitor" ]; then \
				echo "  Scripts installed to: $$d"; \
				echo "  Add to your shell profile:"; \
				echo "    export PATH=\"$$d:\$$PATH\""; \
				break; \
			fi; \
		done; \
	fi
	@echo ""
	@echo "  Done. Run 'make start' or 'ai-monitor --start' to launch."

dev: check-python ## Install with dev dependencies (linting, testing)
	$(PIP) install -e ".[dev]"

start: ## Start the monitor + dashboard on http://localhost:9081
	@lsof -ti :9081 2>/dev/null | xargs kill -9 2>/dev/null || true
	$(PYTHON) -m claude_monitoring.monitor --start

start-deep: ## Start monitor + HTTPS proxy for deep API capture
	@lsof -ti :9081 2>/dev/null | xargs kill -9 2>/dev/null || true
	$(PYTHON) -m claude_monitoring.monitor --start --with-proxy

verify: ## Verify proxy setup
	$(PYTHON) -m claude_monitoring.watch --verify

configure: ## Configure proxy for Claude Code
	$(PYTHON) -m claude_monitoring.watch --configure claude_code

stop: ## Stop the monitor
	@lsof -ti :9081 2>/dev/null | xargs kill -9 2>/dev/null && echo "Stopped." || echo "Not running."

status: ## Check if the monitor is running
	@curl -sf http://localhost:9081/api/stats > /dev/null 2>&1 && echo "Running on http://localhost:9081" || echo "Not running."

test: ## Run the test suite
	$(PYTHON) -m pytest

lint: ## Run linter checks
	$(PYTHON) -m ruff check src/ tests/
	$(PYTHON) -m ruff format --check src/ tests/

format: ## Auto-format code
	$(PYTHON) -m ruff format src/ tests/
	$(PYTHON) -m ruff check --fix src/ tests/

coverage: ## Run tests with HTML coverage report
	$(PYTHON) -m pytest --cov=claude_monitoring --cov-report=html --cov-fail-under=90
	@echo "Coverage report: htmlcov/index.html"

e2e: ## Run Playwright E2E tests
	$(PYTHON) -m pytest tests/e2e/ -v

security: ## Run security scans
	$(PYTHON) -m bandit -r src/ -s B101,B404,B603,B607,B608 --severity-level medium
	@echo "Security scan complete."

ci: lint test ## Run full CI pipeline locally

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .coverage htmlcov coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
