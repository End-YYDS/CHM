#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
detect_container_runtime() {
  if [[ -n "${CONTAINER_RUNTIME-}" ]]; then
    echo "$CONTAINER_RUNTIME"
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    echo "docker"
  elif command -v podman >/dev/null 2>&1; then
    echo "podman"
  else
    printf 'Error: neither "docker" nor "podman" found in PATH\n' >&2
    exit 1
  fi
}

CR="$(detect_container_runtime)"
echo "==> Using container runtime: $CR"

"$CR" run -d \
  --name CHM-DNS \
  -e POSTGRES_USER=chm \
  -e POSTGRES_PASSWORD=qpM9CdpdbpF4z6C\
  -e POSTGRES_DB=dns \
  -v pgdata:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:latest

export SQLX_OFFLINE=true
export DATABASE_URL=postgresql://chm:qpM9CdpdbpF4z6C@127.0.0.1:5432/dns
cargo sqlx migrate run
