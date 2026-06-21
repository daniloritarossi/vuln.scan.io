#!/usr/bin/env bash
# Avvio completo del Vulnerability Feed Aggregator:
#   1) prepara il virtualenv Python e le dipendenze
#   2) avvia lo stack Supabase locale (Docker, in background) + schema
#   3) lancia il server FastAPI in foreground (Ctrl+C per fermarlo)
#
# Supabase resta acceso dopo Ctrl+C (i dati sono persistenti). Per spegnerlo: ./stop.sh
#
# Uso:
#   ./start.sh                 avvio normale (porta 8000)
#   PORT=9000 ./start.sh       porta diversa per FastAPI
#   ./start.sh --no-supabase   avvia solo l'app (Supabase gia' attivo o non voluto)
set -euo pipefail

cd "$(dirname "$0")"
PORT="${PORT:-8000}"
WITH_SUPABASE=1
[ "${1:-}" = "--no-supabase" ] && WITH_SUPABASE=0

# --- 1) Virtualenv + dipendenze ---------------------------------------------
# Non usiamo 'source activate' (puo' mancare in venv incompleti): chiamiamo
# direttamente i binari in .venv/bin, sempre presenti.
PYBIN=".venv/bin/python"
if [ ! -x "$PYBIN" ]; then
  echo "==> creo virtualenv .venv"
  python3 -m venv .venv
fi
export PATH="$PWD/.venv/bin:$PATH"
echo "==> installo/aggiorno dipendenze (requirements.txt)"
"$PYBIN" -m pip install -q --upgrade pip
"$PYBIN" -m pip install -q -r requirements.txt

# --- 2) Stack Supabase (Docker) ---------------------------------------------
if [ "$WITH_SUPABASE" = "1" ]; then
  if ! docker info >/dev/null 2>&1; then
    echo "ERRORE: Docker non e' in esecuzione. Avvia Docker e riprova." >&2
    exit 1
  fi
  echo "==> avvio Supabase locale (Docker)"
  ( cd supabase && ./setup.sh )
else
  echo "==> salto Supabase (--no-supabase)"
fi

# --- 3) Server FastAPI (foreground) -----------------------------------------
cat <<EOF

============================================================
  App        : http://127.0.0.1:${PORT}
  Studio GUI : http://localhost:3001
  REST API   : http://localhost:8001/rest/v1/
============================================================
  Ctrl+C ferma l'app. Supabase resta attivo -> ./stop.sh per spegnerlo.

EOF

# Niente --reload: il watcher di uvicorn tenterebbe di entrare in
# supabase/volumes/db/data (dati Postgres, uid 100 perms 700) e crasherebbe con
# PermissionError. Per hot-reload in sviluppo vedi nota sotto.
exec "$PYBIN" -m uvicorn app:app --host 127.0.0.1 --port "${PORT}"
