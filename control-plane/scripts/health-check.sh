#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Load .env
source .env 2>/dev/null || { echo "ERROR: .env not found. Run setup.sh first."; exit 1; }

echo "=== Control Plane Health Check ==="
echo ""

# Check Docker services
echo "[Services]"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
echo ""

# Check Postgres
echo -n "[Postgres] "
if docker compose exec -T postgres pg_isready -U monitor -q 2>/dev/null; then
    TABLES=$(docker compose exec -T postgres psql -U monitor -d fleet_monitor -tAc \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null)
    echo "healthy ($TABLES tables)"
else
    echo "UNREACHABLE"
fi

# Check CP API
echo -n "[Control Plane API] "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${CP_HOST_PORT}/api/v1/endpoints" \
    -H "X-API-Key: ${CP_API_KEY}" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    ENDPOINTS=$(curl -s "http://localhost:${CP_HOST_PORT}/api/v1/endpoints" \
        -H "X-API-Key: ${CP_API_KEY}" 2>/dev/null | python3 -c \
        "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
    echo "healthy ($ENDPOINTS endpoints registered)"
else
    echo "UNREACHABLE (HTTP $HTTP_CODE)"
fi

# Check fleet dashboard
echo -n "[Fleet Dashboard] "
DASH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:${CP_HOST_PORT}/dashboard" 2>/dev/null || echo "000")
if [ "$DASH_CODE" = "200" ]; then
    echo "serving at http://localhost:${CP_HOST_PORT}/dashboard"
else
    echo "NOT SERVING (HTTP $DASH_CODE)"
fi

# Check test client
echo -n "[Test Client] "
TC_STATUS=$(docker compose ps test-client --format "{{.Status}}" 2>/dev/null)
if echo "$TC_STATUS" | grep -q "Up"; then
    echo "running ($TC_STATUS)"
else
    echo "NOT RUNNING ($TC_STATUS)"
fi

echo ""
echo "Done."
