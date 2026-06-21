# Vulnerability Feed Aggregator

Web app per **audit autorizzati**: gestisce un inventario di asset e verifica la
presenza di software potenzialmente vulnerabile a partire da una **descrizione
testuale** della vulnerabilità (anche senza CVE esplicito).

Backend **FastAPI** · Frontend **HTML + Tailwind** (CDN) · risultati in tempo
reale via **Server-Sent Events**.

> ⚠️ **Uso responsabile.** Eseguire scansioni o login solo su asset di propria
> titolarità o per cui si ha autorizzazione scritta. Scansionare sistemi terzi
> senza permesso è illecito.

---

## Architettura (modulare)

| File | Ruolo |
|------|-------|
| `app.py` | Server FastAPI: pagina web + API (`/api/identify`, `/api/scan`, `/api/assets`). |
| `assets.py` | Parsing dell'inventario `assets.txt` (`IP\|user\|pass`). |
| `osint.py` | Estrazione del **Software Target** dalla descrizione (locale + DuckDuckGo opzionale). |
| `scanner.py` | Motore di verifica: banner grabbing TCP reale (no-auth) + path autenticato (simulato/SSH). |
| `templates/index.html` | UI: form + tabella risultati in tempo reale. |
| `assets.txt` | Inventario di esempio. |

### Flusso
1. L'utente inserisce un testo (es. *"Buffer overflow affecting OpenSSH 8.4"*).
2. `osint.identify_product` isola prodotto (`openssh`) e versione (`8.4`).
   - Estrazione **locale** (regex + dizionario prodotti) come primaria.
   - Se fallisce e l'OSINT è attivo → query **DuckDuckGo** + ri-matching.
3. La UI mostra il **prodotto identificato**.
4. `scanner.scan_asset` cicla ogni asset:
   - **No-auth** → banner grabbing TCP reale sulle porte del prodotto.
   - **Auth** → simulato di default (vedi sotto), o SSH reale via paramiko.
5. La tabella si popola **un asset alla volta** (SSE), con esito del matching.

---

## Formato `assets.txt`

```
IP|username|password
```

- `45.33.32.156||`  oppure  solo `45.33.32.156` → **Autenticazione non richiesta**.
- `93.184.216.34|admin|secret123` → controllo **autenticato**.
- Righe `#...` = commenti.

> `45.33.32.156` = `scanme.nmap.org`, host pubblico che il progetto Nmap
> autorizza esplicitamente per test di scansione.

---

## Sicurezza del path autenticato

In `scanner.py`:

```python
SIMULATE_AUTH = True   # default: nessun login SSH reale
```

- `True` (default) → l'audit autenticato è **simulato** (deterministico, per demo/test).
- `False` → abilita login **SSH reale** via `paramiko` (`_scan_auth_real`).
  Usare **solo** su host di propria titolarità. Usa `RejectPolicy` sulle host key.

---

## Avvio

Richiede `pip` e `venv` (su Debian/Ubuntu: `sudo apt install python3-pip python3-venv`).

```bash
cd vulnerability_feed_aggregator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# avvio server
uvicorn app:app --reload --port 8000
#   oppure:  python3 app.py
```

Apri **http://127.0.0.1:8000**.

---

## Persistenza su Supabase (locale, Docker)

I risultati di ogni scansione vengono salvati su un **Supabase locale** in Docker.
Stack "lean" (`./supabase/docker-compose.yml`): Postgres + PostgREST + Studio +
gateway nginx. I dati sono **persistenti** su bind-mount (`./supabase/volumes/db/data`,
cartella reale del PC) e sopravvivono a `down`/reboot.

```bash
cd supabase
./setup.sh          # avvia i container e applica lo schema (idempotente)
```

| Servizio   | URL / porta                         | Note                                  |
|------------|-------------------------------------|---------------------------------------|
| Studio GUI | http://localhost:3001               | table editor / SQL editor             |
| REST API   | http://localhost:8001/rest/v1/      | header `apikey` + `Authorization`     |
| Postgres   | localhost:5432 (`postgres`)         | accesso diretto                       |

L'app vi si collega col client **supabase-py** (`db.py`), in modalità *best-effort*:
se Supabase è spento la scansione **non** si interrompe. Override via env:
`SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `SUPABASE_PERSIST=0` (disattiva).

**Schema** (`supabase/volumes/db/init/01-schema.sql`):
- `scans` — una riga per scansione: target identificato (prodotto/versione/alias/
  source/candidates/dependencies) + sintesi CVE (count/ids/summary).
- `scan_results` — una riga per asset: ip, method, product_found, detected_version,
  raw_evidence, vuln_match, cve_count, cve_ids.

> ⚠️ Le chiavi in `supabase/.env` sono **demo, solo per il locale**. Mai in produzione.
> Stop stack: `docker compose -f supabase/docker-compose.yml down` (i dati restano).

### Test rapidi dei moduli (senza server/rete)
```bash
python3 osint.py      # estrazione prodotto da esempi
python3 assets.py     # dump inventario interpretato
python3 scanner.py    # scansione (esegue banner grab reale!)
```

---

## Esempi di input
- `Remote Code Execution in Python 3.10 via HTTP component` → prodotto **python** v3.10
- `Buffer overflow affecting OpenSSH 8.4` → prodotto **openssh** v8.4
- `Some weird issue in nginx 1.21` → prodotto **nginx** v1.21

I prodotti riconosciuti sono in `KNOWN_PRODUCTS` (`osint.py`) — estendibile.

---

## Nota sulla grafica
Era stato richiesto un template **Google Stitch** (`id 12695694979658623731`):
non è accessibile da questo ambiente (nessuna API/export). Il frontend è quindi
una UI Tailwind originale (dashboard scura). Esportando l'HTML del template
Stitch, è sufficiente sostituire `templates/index.html` mantenendo gli
`id` degli elementi (`desc`, `run`, `rows`, `targetCard`, …) per riusare la
logica JS già pronta.
