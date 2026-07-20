"""
conftest.py
------------
Fixture condivise per i test funzionali RBAC (cono di visibilita').

Richiede lo stack Supabase locale attivo (./supabase/setup.sh) perche' l'app
carica utenti/asset da li'. Crea utenti/asset/gruppi dedicati ai test
(prefisso '_ftest_') e li ripulisce a fine sessione: NON tocca mai l'utente
admin/admin seedato di default (evita di innescare il flusso must_change_password
e di rischiare l'unico account admin reale).

Nessuna email reale viene inviata: gli utenti di test sono creati SEMPRE con
password esplicita (bypassa il flusso di invito via SMTP, che nel config.json
locale punta a un account Gmail vero).
"""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

# TestClient parla ASGI in-process su "http://testserver" (http, non https):
# un cookie con flag Secure non verrebbe rispedito dal client sulle richieste
# successive, facendo fallire l'autenticazione per motivi di trasporto e non
# di logica applicativa. Va impostato PRIMA di importare app (letto a livello
# di modulo). In produzione resta Secure di default (vedi app.py).
os.environ.setdefault("VFA_COOKIE_SECURE", "0")

import app as app_module  # noqa: E402
import auth  # noqa: E402
import db  # noqa: E402

ROLES = ("admin", "manager", "editor", "viewer")
ROLE_PASSWORD = "Ftest-Passw0rd-2026!"          # rispetta min_password_len=12
USERNAME = "_ftest_{role}".format


@pytest.fixture(scope="session")
def client():
    """TestClient 'anonimo' condiviso (nessun cookie): triggera lo startup event."""
    with TestClient(app_module.app) as c:
        yield c


@pytest.fixture(scope="session")
def anon_client(client):
    """Alias esplicito per le richieste senza sessione."""
    return TestClient(app_module.app)


def _seed_user(username: str, role: str, must_change: bool = False) -> int:
    uid = db.insert_user({
        "username": username,
        "password_hash": auth.hash_password(ROLE_PASSWORD),
        "role": role,
        "is_active": True,
        "must_change_password": must_change,
    })
    assert uid, (
        f"Seed utente '{username}' fallito: Supabase locale raggiungibile? "
        "(cd supabase && ./setup.sh)"
    )
    return uid


@pytest.fixture(scope="session")
def role_user_ids(client):
    """Un utente per ruolo, gia' attivo (must_change_password=False)."""
    ids = {role: _seed_user(USERNAME(role=role), role) for role in ROLES}
    yield ids
    for uid in ids.values():
        db.delete_user(uid)


def _login(username: str) -> TestClient:
    c = TestClient(app_module.app)
    r = c.post("/api/login", json={"username": username, "password": ROLE_PASSWORD})
    assert r.status_code == 200, f"login {username} fallito: {r.status_code} {r.text}"
    return c


@pytest.fixture(scope="session")
def role_clients(role_user_ids):
    """TestClient autenticato per ciascun ruolo (cookie di sessione separati)."""
    return {role: _login(USERNAME(role=role)) for role in ROLES}


@pytest.fixture(scope="session")
def cone_fixture(role_user_ids, role_clients):
    """
    Due asset + due gruppi per esercitare il cono di visibilita' dell'editor:
      - asset_in / group_in  -> assegnati all'editor di test
      - asset_out / group_out -> NON assegnati (fuori scope)
    """
    admin_c = role_clients["admin"]

    r_in = admin_c.post("/api/assets", json={"ip": "10.99.0.1", "os_type": "linux"})
    r_out = admin_c.post("/api/assets", json={"ip": "10.99.0.2", "os_type": "linux"})
    assert r_in.status_code == 200, r_in.text
    assert r_out.status_code == 200, r_out.text
    asset_in = r_in.json()["index"]
    asset_out = r_out.json()["index"]

    r_gin = admin_c.post("/api/groups", json={"name": "_ftest_group_in"})
    r_gout = admin_c.post("/api/groups", json={"name": "_ftest_group_out"})
    assert r_gin.status_code == 200, r_gin.text
    assert r_gout.status_code == 200, r_gout.text
    group_in = r_gin.json()["id"]
    group_out = r_gout.json()["id"]

    admin_c.put(f"/api/groups/{group_in}/members",
                json={"user_ids": [role_user_ids["editor"]]})
    admin_c.put(f"/api/assets/{asset_in}/assignments",
                json={"user_ids": [role_user_ids["editor"]], "group_ids": []})

    yield {"asset_in": asset_in, "asset_out": asset_out,
           "group_in": group_in, "group_out": group_out}

    admin_c.delete(f"/api/assets/{asset_in}")
    admin_c.delete(f"/api/assets/{asset_out}")
    admin_c.delete(f"/api/groups/{group_in}")
    admin_c.delete(f"/api/groups/{group_out}")


@pytest.fixture(scope="session")
def findings_fixture(cone_fixture):
    """Un finding sull'asset in-cono e uno sull'asset fuori-cono dell'editor,
    inseriti direttamente via db.py (bypassa ingest.py, non serve un report
    reale) per esercitare lo scope su /api/findings/{id}/status."""
    rows = [
        {"fingerprint": "_ftest_fp_in", "source": "_ftest",
         "asset_ip": "10.99.0.1", "title": "ftest in-scope",
         "severity": "LOW", "status": "open"},
        {"fingerprint": "_ftest_fp_out", "source": "_ftest",
         "asset_ip": "10.99.0.2", "title": "ftest out-of-scope",
         "severity": "LOW", "status": "open"},
    ]
    assert db.upsert_findings(rows), "seed findings fallito (Supabase su?)"
    found = db.fetch_findings_by_fps(["_ftest_fp_in", "_ftest_fp_out"])
    by_fp = {f["fingerprint"]: f["id"] for f in found}
    ids = {"in": by_fp["_ftest_fp_in"], "out": by_fp["_ftest_fp_out"]}
    yield ids
    client = db._get_client()
    if client is not None:
        client.table("findings").delete().in_("id", list(ids.values())).execute()
