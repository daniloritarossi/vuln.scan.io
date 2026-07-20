"""
test_password_change.py
------------------------
Cambio password: flusso forzato (must_change_password), policy sulla nuova
password, e invalidazione della sessione precedente al cambio (logout
globale). Indipendente dal ruolo (stesso comportamento per tutti e 4).
"""
import time

import auth
import db
from fastapi.testclient import TestClient

import app as app_module

FORCED_PW = "Ftest-Forced-0ld!"
NEW_PW = "Ftest-Brand-New-2026!"


def _seed_forced_user(role="editor"):
    uid = db.insert_user({
        "username": "_ftest_forced_pw",
        "password_hash": auth.hash_password(FORCED_PW),
        "role": role, "is_active": True, "must_change_password": True,
    })
    assert uid, "seed utente must_change_password fallito"
    return uid


def test_forced_password_change_blocks_other_endpoints():
    uid = _seed_forced_user()
    try:
        c = TestClient(app_module.app)
        r = c.post("/api/login", json={"username": "_ftest_forced_pw",
                                        "password": FORCED_PW})
        assert r.status_code == 200
        assert r.json()["must_change_password"] is True

        # API bloccata con 403 dedicato, non un generico Forbidden di ruolo
        r_api = c.get("/api/assets")
        assert r_api.status_code == 403
        assert r_api.json().get("code") == "password_change_required"

        # pagina normale -> redirect a /change-password
        r_page = c.get("/assets", follow_redirects=False)
        assert r_page.status_code == 303
        assert r_page.headers.get("location") == "/change-password"

        # le rotte consentite restano raggiungibili
        assert c.get("/api/me").status_code == 200
        assert c.get("/change-password", follow_redirects=False).status_code == 200
    finally:
        db.delete_user(uid)


def test_password_change_flow_and_session_invalidation():
    uid = _seed_forced_user()
    try:
        c = TestClient(app_module.app)
        r = c.post("/api/login", json={"username": "_ftest_forced_pw",
                                        "password": FORCED_PW})
        assert r.status_code == 200
        old_cookie_value = c.cookies.get(app_module.SESSION_COOKIE)
        assert old_cookie_value
        # 'iat' del token e' in secondi interi: garantisce che
        # password_changed_at ricada oltre iat+1 (logout globale affidabile).
        time.sleep(1.1)

        # password attuale sbagliata -> 400
        r_bad = c.post("/api/change-password",
                       json={"old_password": "not-the-real-one",
                             "new_password": NEW_PW})
        assert r_bad.status_code == 400

        # policy: nuova password troppo corta -> 400, nessun cambio
        r_short = c.post("/api/change-password",
                         json={"old_password": FORCED_PW, "new_password": "short"})
        assert r_short.status_code == 400

        # nuova == vecchia -> 400
        r_same = c.post("/api/change-password",
                        json={"old_password": FORCED_PW, "new_password": FORCED_PW})
        assert r_same.status_code == 400

        # cambio valido -> 200, cookie riemesso, must_change_password sbloccato
        r_ok = c.post("/api/change-password",
                      json={"old_password": FORCED_PW, "new_password": NEW_PW})
        assert r_ok.status_code == 200, r_ok.text
        assert c.get("/api/assets").status_code == 200

        # il cookie EMESSO PRIMA del cambio non e' piu' valido (logout globale)
        stale_client = TestClient(app_module.app)
        stale_client.cookies.set(app_module.SESSION_COOKIE, old_cookie_value)
        r_stale = stale_client.get("/api/me")
        assert r_stale.status_code == 401
    finally:
        db.delete_user(uid)
