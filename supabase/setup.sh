#!/usr/bin/env bash
# Avvia lo stack Supabase locale e applica lo schema in modo idempotente.
# Rilanciabile a piacere: i dati restano in ./volumes/db/data.
set -euo pipefail

cd "$(dirname "$0")"

# Carica le variabili (.env) anche nello shell, non solo in docker compose.
set -a; [ -f .env ] && . ./.env; set +a

echo "==> docker compose up -d"
docker compose up -d

echo "==> attendo che il DB sia healthy..."
for i in $(seq 1 40); do
  if docker compose exec -T db pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    echo "    DB pronto."
    break
  fi
  sleep 2
  if [ "$i" = "40" ]; then echo "ERRORE: DB non pronto in tempo."; exit 1; fi
done

# authenticator e' un ruolo riservato: la password va impostata dal superuser
# supabase_admin (non da 'postgres'). Deve combaciare con PGRST_DB_URI nel compose.
echo "==> imposto password ruolo authenticator (via supabase_admin)"
docker compose exec -T db psql -U supabase_admin -d postgres \
  -c "ALTER ROLE authenticator WITH LOGIN PASSWORD '${POSTGRES_PASSWORD:-postgres-local-pw}';" >/dev/null
docker compose restart rest >/dev/null

echo "==> applico schema (volumes/db/init/01-schema.sql)"
docker compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
  < volumes/db/init/01-schema.sql

echo "==> ricarico cache PostgREST"
docker compose exec -T db psql -U postgres -d postgres \
  -c "NOTIFY pgrst, 'reload schema';" >/dev/null

cat <<'EOF'

==> FATTO.
  Studio GUI : http://localhost:3001
  REST API   : http://localhost:8001/rest/v1/   (header: apikey + Authorization Bearer)
  Postgres   : localhost:5432  (user=postgres)
  Dati       : ./volumes/db/data  (persistenti)

EOF
