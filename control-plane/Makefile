.PHONY: setup start stop teardown health logs test clean

# Default: show help
help:
	@echo "Control Plane — Available targets:"
	@echo ""
	@echo "  make setup      Full setup (checks ports, generates .env, builds, starts)"
	@echo "  make start      Start all services (assumes setup done)"
	@echo "  make stop       Stop all services (preserves data)"
	@echo "  make teardown   Stop and remove all data"
	@echo "  make health     Health check all services"
	@echo "  make logs       Tail all service logs"
	@echo "  make logs-cp    Tail control plane logs only"
	@echo "  make logs-pg    Tail postgres logs only"
	@echo "  make test       Run CP tests"
	@echo "  make clean      Remove .env, __pycache__, .pyc"
	@echo "  make connect    Show command to connect your laptop"
	@echo ""

setup:
	@bash scripts/setup.sh

start:
	docker compose up -d

stop:
	docker compose down

teardown:
	@bash scripts/teardown.sh --wipe

health:
	@bash scripts/health-check.sh

logs:
	docker compose logs -f

logs-cp:
	docker compose logs -f control-plane

logs-pg:
	docker compose logs -f postgres

test:
	docker compose exec control-plane pytest tests/ -v

clean:
	rm -f .env
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete

connect:
	@source .env 2>/dev/null && echo "" && \
	echo "Run this on your laptop:" && \
	echo "" && \
	echo "  ai-monitor --start --control-plane http://localhost:$$CP_HOST_PORT --cp-api-key $$CP_API_KEY" && \
	echo ""
