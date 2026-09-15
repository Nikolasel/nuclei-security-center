#!/usr/bin/env bash
# Idempotent bootstrap for the Cloud Agent dev environment.
#
# This repo's primary dev loop is the full Docker Compose stack (Postgres, MinIO,
# Keycloak OIDC, the scanner node, and the backend) — see docs/DEVELOPMENT.md.
# We run it via Docker-in-Docker inside the Cloud Agent VM. This script installs
# Docker + its dependencies and pre-builds/pulls every image so a booted agent
# starts fast. It also fetches Go/JS deps so the code is editable and the unit
# tests run natively (outside Docker). Safe to run repeatedly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() { printf '\n[install] %s\n' "$*"; }

# ---- 1. Docker engine + Compose + the bits needed for nested (DinD) use ----
# overlay2 can't stack on the VM's overlay root, so Docker uses the fuse-overlayfs
# storage driver; iptables is needed for bridge NAT / published ports.
# Check the whole toolchain, not just the docker binary: a base image could ship
# `docker` without Compose v2 or without fuse-overlayfs, and configuring the
# fuse-overlayfs storage driver below without that binary would crash-loop dockerd.
if ! command -v docker >/dev/null 2>&1 \
  || ! command -v fuse-overlayfs >/dev/null 2>&1 \
  || ! docker compose version >/dev/null 2>&1; then
  log "installing Docker engine, Compose, and DinD dependencies"
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -o Dpkg::Options::=--force-confold -y \
    docker.io docker-compose-v2 iptables fuse-overlayfs uidmap slirp4netns dbus-user-session fuse3
else
  log "Docker, Compose, and fuse-overlayfs already installed"
fi

# Complete any interrupted dpkg config (fuse3 ships an interactive conffile prompt).
sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a --force-confold >/dev/null 2>&1 || true

# Rootful Docker with the fuse-overlayfs storage driver (overlay2 is unavailable
# on the nested overlay root).
sudo mkdir -p /etc/docker
printf '{\n  "storage-driver": "fuse-overlayfs"\n}\n' | sudo tee /etc/docker/daemon.json >/dev/null

# Let the invoking (non-root) user run docker without sudo in new shells
# (convenience only; the scripts still use sudo so they work before the group
# change takes effect). Prefer $SUDO_USER so running the script under sudo still
# grants the real VM user, not root.
sudo groupadd -f docker
sudo usermod -aG docker "${SUDO_USER:-$(id -un)}" || true

# ---- 2. Dev config (.env) — dev values match the seeded Keycloak realm ----
if [ ! -f .env ]; then
  log "creating .env from .env.example"
  cp .env.example .env
fi

# ---- 3. Start dockerd so we can bake images into the snapshot ----
"$REPO_ROOT/.cursor/dockerd.sh"

# ---- 4. Pre-build + pull all stack images (baked into the build snapshot) ----
# Best-effort + idempotent: skip work when an image is already present, and
# retry transient registry hiccups (e.g. Docker Hub anonymous rate limits).
image_present() { sudo docker image inspect "$1" >/dev/null 2>&1; }
retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    if [ "$n" -ge 3 ]; then return 1; fi
    log "command failed; retry $n in $((15 * n))s: $*"
    sleep $((15 * n))
  done
}
# Compose project name comes from the `name:` in docker-compose.yml, which fixes
# the built image names to <project>-<service>.
project="nuclei-security-center"

if image_present "${project}-backend" && image_present "${project}-scanner"; then
  log "backend + scanner images already built"
else
  log "building backend + scanner images"
  retry sudo docker compose build || {
    if image_present "${project}-backend" && image_present "${project}-scanner"; then
      log "build failed but images are already present — using cached images"
    else
      log "ERROR: could not build backend/scanner images"; exit 1
    fi
  }
fi

log "pulling Postgres / MinIO / Keycloak images"
retry sudo docker compose pull postgres minio keycloak \
  || log "pull incomplete — relying on any already-cached images (start.sh will surface issues)"

# ---- 5. Native tooling for editing + unit tests outside Docker ----
# Guarded so a base image missing Go/Node doesn't abort the Docker setup under
# `set -e` (the stack itself builds these inside containers regardless).
if command -v go >/dev/null 2>&1; then
  log "downloading Go modules"
  go mod download
else
  log "go not on PATH — skipping Go module download (native unit tests unavailable)"
fi
if command -v npm >/dev/null 2>&1; then
  log "installing web dependencies"
  (cd web && npm ci)
else
  log "npm not on PATH — skipping web dependency install (native SPA tooling unavailable)"
fi

log "install complete"
