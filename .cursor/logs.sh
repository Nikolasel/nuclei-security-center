#!/usr/bin/env bash
# Foreground terminal that tails the Compose stack logs so the agent can watch
# the backend / scanner / Keycloak / Postgres / MinIO output live.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Wait for the daemon (start.sh brings it up).
for _ in $(seq 1 60); do
  sudo docker info >/dev/null 2>&1 && break
  sleep 2
done

exec sudo docker compose logs -f
