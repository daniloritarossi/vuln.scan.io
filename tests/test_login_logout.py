"""
test_login_logout.py
---------------------
Funzionale: login/logout per ciascun ruolo, credenziali errate, account non
attivo, nessuna enumerazione utenti dai messaggi di errore.
"""
import auth
import db
from fastapi.testclient import TestClient

import app as app_module
from conftest import ROLE_PASSWORD

ROLES = ("admin", "manager", "editor", "viewer")


def test_login_success_returns_correct_role(role_user_ids):
    for role in ROLES:
        c = TestClient(app_module.app)
        r = c.post("/api/login", json={"username": f"_ftest_{role}",
                                        "password": ROLE_PASSWORD})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["role"] == role
        assert body["must_change_password"] is False
        assert app_module.SESSION_COOKIE in r.cookies


def test_login_wrong_password(role_user_ids):
    c = TestClient(app_module.app)
    r = c.post("/api/login", json={"username": "_ftest_admin",
                                    "password": "wrong-password"})
    assert r.status_code == 401
    assert "credenziali non valide" in r.json()["error"].lower()


def test_login_unknown_username_same_message_as_wrong_password(role_user_ids):
    """No enumeration: username inesistente e password errata danno lo
    stesso messaggio generico."""
    c = TestClient(app_module.app)
    r_unknown = c.post("/api/login", json={"username": "_ftest_does_not_exist",
                                            "password": "whatever12345"})
    r_wrong = c.post("/api/login", json={"username": "_ftest_admin",
                                          "password": "wrong-password"})
    assert r_unknown.status_code == r_wrong.status_code == 401
    assert r_unknown.json()["error"] == r_wrong.json()["error"]


def test_login_inactive_invited_user_rejected():
    """Utente invitato (password_hash assente, is_active False): stesso 401
    generico, nessuna informazione sullo stato dell'invito."""
    uid = db.insert_user({"username": "_ftest_invited", "role": "viewer",
                          "password_hash": None, "is_active": False})
    assert uid, "seed utente invitato fallito"
    try:
        c = TestClient(app_module.app)
        r = c.post("/api/login", json={"username": "_ftest_invited",
                                        "password": "anything123456"})
        assert r.status_code == 401
        assert "credenziali non valide" in r.json()["error"].lower()
    finally:
        db.delete_user(uid)


def test_logout_deletes_session_cookie(role_clients):
    c = role_clients["viewer"]
    # sessione valida prima del logout
    assert c.get("/api/me").status_code == 200
    r = c.get("/logout", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers.get("location") == "/login"
    set_cookie = r.headers.get("set-cookie", "")
    assert app_module.SESSION_COOKIE in set_cookie
    # ri-autentica il client condiviso per non rompere gli altri test della sessione
    r2 = c.post("/api/login", json={"username": "_ftest_viewer",
                                     "password": ROLE_PASSWORD})
    assert r2.status_code == 200
