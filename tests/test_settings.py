"""
test_settings.py
-----------------
Percorso positivo di POST /api/settings (solo admin): round-trip a valore
INVARIATO. Il produttivo config.json contiene credenziali SMTP reali, quindi
il test rimanda al client esattamente cio' che GET ha restituito (i placeholder
'••••••••' vengono ignorati dal server, che preserva il valore originale) e
verifica che dopo il giro la config resti identica: nessuna scrittura reale
di dati diversi da quelli gia' presenti.
"""


def test_admin_settings_roundtrip_is_noop(role_clients):
    admin_c = role_clients["admin"]

    before = admin_c.get("/api/settings")
    assert before.status_code == 200
    cfg = before.json()

    r = admin_c.post("/api/settings", json=cfg)
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    after = admin_c.get("/api/settings")
    assert after.status_code == 200
    assert after.json() == cfg, "il round-trip non dovrebbe alterare la config"


def test_manager_can_read_but_not_write_settings(role_clients):
    manager_c = role_clients["manager"]
    assert manager_c.get("/api/settings").status_code == 200
    r = manager_c.post("/api/settings", json={})
    assert r.status_code == 403
