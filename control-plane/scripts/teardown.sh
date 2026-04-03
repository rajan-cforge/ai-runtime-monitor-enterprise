#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Control Plane Teardown ==="

if [ "${1:-}" = "--wipe" ]; then
    echo "Stopping services and removing all data..."
    docker compose down -v
    echo "Postgres volume deleted."
else
    echo "Stopping services (data preserved in Docker volume)..."
    docker compose down
    echo ""
    echo "Data preserved. To wipe: ./scripts/teardown.sh --wipe"
fi

echo "Done."
