#!/usr/bin/env bash
# Start the rootful Docker daemon if it isn't already running, and prepare the
# kernel networking knobs nested Docker needs. Idempotent; returns once the
# daemon answers. This VM has no systemd managing docker, so we launch dockerd
# directly and detach it so it survives the caller returning.
set -euo pipefail

# Same-bridge container-to-container traffic is dropped by netfilter in this
# nested setup (legacy/nft split); let bridged frames bypass iptables so the
# compose services can reach each other. NAT egress + published ports are
# unaffected (those use POSTROUTING/PREROUTING, not the bridge hook).
sudo modprobe br_netfilter 2>/dev/null || true
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1 || true

if sudo docker info >/dev/null 2>&1; then
  exit 0
fi

# An unclean shutdown (no systemd manages dockerd here) can leave a stale pid
# file that makes the next `dockerd` abort with "pid file found". Remove it when
# it points at a process that is no longer running.
if [ -f /var/run/docker.pid ] && ! sudo kill -0 "$(cat /var/run/docker.pid 2>/dev/null)" 2>/dev/null; then
  echo "[dockerd] removing stale /var/run/docker.pid"
  sudo rm -f /var/run/docker.pid
fi

echo "[dockerd] starting Docker daemon"
sudo bash -c 'nohup dockerd >/var/log/dockerd.log 2>&1 &'

for _ in $(seq 1 30); do
  if sudo docker info >/dev/null 2>&1; then
    echo "[dockerd] ready"
    exit 0
  fi
  sleep 1
done

echo "[dockerd] failed to become ready; see /var/log/dockerd.log" >&2
sudo tail -n 20 /var/log/dockerd.log >&2 || true
exit 1
