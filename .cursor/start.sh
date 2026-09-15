#!/usr/bin/env bash
# Per-boot startup: bring up the Docker daemon and the full Compose stack, then
# return once the backend is healthy. Idempotent (compose up -d is a no-op when
# services already run). Images are baked into the build snapshot by install.sh,
# so this does not rebuild.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() { printf '\n[start] %s\n' "$*"; }

# Ensure the daemon + kernel networking are up.
"$REPO_ROOT/.cursor/dockerd.sh"

log "starting the Compose stack (postgres, minio, keycloak, scanner, backend)"
sudo docker compose up -d

# Wait for the backend to serve, so the agent boots into a ready stack.
log "waiting for the backend to become healthy on http://localhost:8080"
for _ in $(seq 1 60); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/healthz 2>/dev/null)" = "200" ]; then
    log "stack is up — UI at http://localhost:8080 (Keycloak login: admin/admin, operator/operator, viewer/viewer)"
    exit 0
  fi
  sleep 2
done

log "backend did not report healthy in time; recent logs:"
sudo docker compose logs --tail=30 backend || true
# Don't hard-fail the boot: the stack may still be coming up (e.g. first-run
# template sync). The compose-logs terminal shows live progress.
exit 0
