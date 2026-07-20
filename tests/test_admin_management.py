"""
test_admin_management.py
-------------------------
Percorso positivo (solo admin) per la gestione utenti/gruppi, e le regole di
business che proteggono dal lockout ("non puoi eliminare te stesso").
manager/editor/viewer negati sono gia' coperti da test_rbac_matrix.py.

Gli utenti creati via API includono SEMPRE 'password' nel body per evitare
il flusso di invito via email reale (SMTP configurato con un account Gmail
vero in config.json).
"""
import db


def test_admin_can_create_update_delete_user(role_clients):
    admin_c = role_clients["admin"]

    r = admin_c.post("/api/users", json={
        "username": "_ftest_crud_user", "role": "viewer",
        "password": "Ftest-Crud-Passw0rd!",
    })
    assert r.status_code == 200, r.text
    new_id = r.json()["id"]

    try:
        r_list = admin_c.get("/api/users")
        assert any(u["id"] == new_id for u in r_list.json()["users"])

        r_upd = admin_c.put(f"/api/users/{new_id}", json={"role": "editor"})
        assert r_upd.status_code == 200, r_upd.text
        target = db.fetch_user(new_id)
        assert target["role"] == "editor"
    finally:
        r_del = admin_c.delete(f"/api/users/{new_id}")
        assert r_del.status_code == 200, r_del.text
    assert db.fetch_user(new_id) is None


def test_admin_cannot_delete_self(role_clients, role_user_ids):
    admin_c = role_clients["admin"]
    r = admin_c.delete(f"/api/users/{role_user_ids['admin']}")
    assert r.status_code == 400
    assert "stesso" in r.json()["error"].lower()
    # l'account sopravvive
    assert db.fetch_user(role_user_ids["admin"]) is not None


def test_admin_rejects_invalid_role():
    from fastapi.testclient import TestClient
    import app as app_module
    from conftest import ROLE_PASSWORD
    c = TestClient(app_module.app)
    c.post("/api/login", json={"username": "_ftest_admin", "password": ROLE_PASSWORD})
    r = c.post("/api/users", json={
        "username": "_ftest_bad_role", "role": "superuser",
        "password": "Ftest-Bad-Role-Pw!",
    })
    assert r.status_code == 400
    assert "ruolo" in r.json()["error"].lower()


def test_admin_can_create_and_delete_group(role_clients):
    admin_c = role_clients["admin"]
    r = admin_c.post("/api/groups", json={"name": "_ftest_crud_group"})
    assert r.status_code == 200, r.text
    gid = r.json()["id"]
    try:
        names = {g["name"] for g in admin_c.get("/api/groups").json()["groups"]}
        assert "_ftest_crud_group" in names
    finally:
        r_del = admin_c.delete(f"/api/groups/{gid}")
        assert r_del.status_code == 200, r_del.text
