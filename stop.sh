#!/usr/bin/env bash
# Ferma lo stack Supabase locale + il server FastAPI (uvicorn).
# I dati restano in supabase/volumes/db/data.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> stopping FastAPI server (uvicorn app:app)"
if pkill -f "uvicorn app:app"; then
  echo "    server stopped"
else
  echo "    no server running"
fi

echo "==> stopping Supabase containers (data remains persistent)"
docker compose -f supabase/docker-compose.yml down

if docker ps -a --format '{{.Names}}' | grep -q '^vuln-test-linux-1$'; then
  echo "==> stopping and removing test container vuln-test-linux-1"
  docker rm -f vuln-test-linux-1
fi

if docker ps -a --format '{{.Names}}' | grep -q '^vuln-test-windows-1$'; then
  echo "==> stopping and removing test container vuln-test-windows-1"
  docker rm -f vuln-test-windows-1
fi

echo "==> done. Restart: ./start.sh"
