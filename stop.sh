#!/usr/bin/env bash
# Ferma lo stack Supabase locale. I dati restano in supabase/volumes/db/data.
# (Il server FastAPI si ferma con Ctrl+C nel terminale dove gira start.sh.)
set -euo pipefail
cd "$(dirname "$0")"
echo "==> spengo i container Supabase (i dati restano persistenti)"
docker compose -f supabase/docker-compose.yml down
echo "==> fatto. Riavvio: ./start.sh"
