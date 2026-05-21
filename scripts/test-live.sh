#!/usr/bin/env bash
# Run live integration tests against a real Vaultwarden instance.
#
# Usage:
#   ./scripts/test-live.sh [test binary args...]
#
# Extra arguments are passed after `--` to the test binary (not to cargo),
# so they are test-harness args: filter names, --nocapture, --ignored, etc.
#
# Example:
#   ./scripts/test-live.sh                          # run all live tests
#   ./scripts/test-live.sh session::login           # run one test by filter
#   ./scripts/test-live.sh -- --nocapture           # pass harness flag
#
# The script starts Vaultwarden via Docker Compose, waits for it to be ready,
# runs the live_tests binary, and tears everything down on exit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.live-test.yml"
SERVICE_URL="http://localhost:18222"
ADMIN_TOKEN="live-test-admin-token"

cleanup() {
    echo "→ Stopping Vaultwarden..."
    docker compose -f "$COMPOSE_FILE" down -v --timeout 10 2>/dev/null || true
}
trap cleanup EXIT

echo "→ Starting Vaultwarden (docker compose)..."
docker compose -f "$COMPOSE_FILE" up -d

echo "→ Waiting for Vaultwarden to be ready..."
for i in $(seq 1 60); do
    if curl -sf "$SERVICE_URL/alive" >/dev/null 2>&1; then
        echo "→ Vaultwarden is ready (${i}s)."
        break
    fi
    if [ "$i" = "60" ]; then
        echo "ERROR: Vaultwarden did not become ready within 60 seconds." >&2
        docker compose -f "$COMPOSE_FILE" logs 2>&1 | tail -40
        exit 1
    fi
    sleep 1
done

export VAULTWARDEN_LIVE_TEST_URL="$SERVICE_URL"
export VAULTWARDEN_LIVE_ADMIN_TOKEN="$ADMIN_TOKEN"

echo "→ Running live integration tests..."
cd "$REPO_ROOT"
# Run tests single-threaded to avoid overwhelming the test server.
# Any extra arguments are passed to the test binary (after --).
cargo test --test live_tests -- --test-threads=1 --nocapture "$@"
