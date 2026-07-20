"""
test_editor_scope.py
---------------------
Cono di visibilita' dell'editor: deve vedere/operare SOLO sugli asset e
gruppi assegnati a lui (o a un suo gruppo). admin/manager/viewer restano
"unscoped" (viewer e' sola lettura ma vede tutto l'inventario, con lo
username redatto).
"""


def _ips(assets_json):
    return {a["ip"] for a in assets_json["assets"]}


def _ids(assets_json):
    return {a["index"] if "index" in a else a.get("id") for a in assets_json["assets"]}


def test_editor_sees_only_assigned_asset(role_clients, cone_fixture):
    r = role_clients["editor"].get("/api/assets")
    assert r.status_code == 200
    ips = _ips(r.json())
    assert "10.99.0.1" in ips          # asset_in: assegnato
    assert "10.99.0.2" not in ips      # asset_out: fuori cono


def test_unscoped_roles_see_both_assets(role_clients, cone_fixture):
    for role in ("admin", "manager", "viewer"):
        r = role_clients[role].get("/api/assets")
        assert r.status_code == 200
        ips = _ips(r.json())
        assert {"10.99.0.1", "10.99.0.2"} <= ips, f"{role} dovrebbe vedere tutti gli asset"


def test_viewer_username_redacted(role_clients, cone_fixture):
    r = role_clients["viewer"].get("/api/assets")
    assert r.status_code == 200
    for a in r.json()["assets"]:
        assert a["username"] is None


def test_editor_all_view_includes_assignment(role_clients, cone_fixture):
    r = role_clients["editor"].get("/api/assets/all")
    assert r.status_code == 200
    by_ip = {a["ip"]: a for a in r.json()["assets"]}
    assert "10.99.0.1" in by_ip
    assert "10.99.0.2" not in by_ip


def test_editor_forbidden_outside_cone(role_clients, cone_fixture):
    editor_c = role_clients["editor"]
    asset_out = cone_fixture["asset_out"]

    r = editor_c.patch(f"/api/assets/{asset_out}/enabled", json={"enabled": False})
    assert r.status_code == 403

    r = editor_c.delete(f"/api/assets/{asset_out}")
    assert r.status_code == 403

    r = editor_c.put(f"/api/assets/{asset_out}",
                      json={"ip": "10.99.0.2", "os_type": "linux"})
    assert r.status_code == 403


def test_editor_allowed_inside_cone(role_clients, cone_fixture):
    editor_c = role_clients["editor"]
    asset_in = cone_fixture["asset_in"]

    # toggle e poi ripristino: nessun cambio di stato residuo
    r = editor_c.patch(f"/api/assets/{asset_in}/enabled", json={"enabled": False})
    assert r.status_code == 200
    r = editor_c.patch(f"/api/assets/{asset_in}/enabled", json={"enabled": True})
    assert r.status_code == 200


def test_editor_cannot_reassign_assets(role_clients, cone_fixture):
    """Riassegnare un asset e' riservato ad admin/manager: l'editor non puo'
    farlo nemmeno su un asset del proprio cono (rischio self-escalation)."""
    editor_c = role_clients["editor"]
    asset_in = cone_fixture["asset_in"]
    r = editor_c.put(f"/api/assets/{asset_in}/assignments",
                      json={"user_ids": [], "group_ids": []})
    assert r.status_code == 403


def test_editor_create_asset_is_self_assigned(role_clients, role_user_ids):
    editor_c = role_clients["editor"]
    r = editor_c.post("/api/assets", json={"ip": "10.99.0.50", "os_type": "linux"})
    assert r.status_code == 200, r.text
    new_id = r.json()["index"]
    try:
        # subito visibile all'editor (auto-assegnato)
        r2 = editor_c.get("/api/assets")
        assert "10.99.0.50" in _ips(r2.json())
        # e l'editor stesso puo' cancellarlo (dentro il proprio cono)
    finally:
        editor_c.delete(f"/api/assets/{new_id}")


def test_editor_sees_only_own_group(role_clients, cone_fixture):
    r = role_clients["editor"].get("/api/groups")
    assert r.status_code == 200
    names = {g["name"] for g in r.json()["groups"]}
    assert "_ftest_group_in" in names
    assert "_ftest_group_out" not in names


def test_admin_sees_all_groups(role_clients, cone_fixture):
    r = role_clients["admin"].get("/api/groups")
    assert r.status_code == 200
    names = {g["name"] for g in r.json()["groups"]}
    assert {"_ftest_group_in", "_ftest_group_out"} <= names


def test_findings_status_scope(role_clients, cone_fixture, findings_fixture):
    """PATCH /api/findings/{id}/status: l'editor puo' operare solo sul
    finding dell'asset nel proprio cono (10.99.0.1), non su quello fuori
    cono (10.99.0.2), anche se lo status_change altrimenti sarebbe valido."""
    editor_c = role_clients["editor"]

    r = editor_c.patch(f"/api/findings/{findings_fixture['in']}/status",
                        json={"status": "triaged"})
    assert r.status_code == 200, r.text

    r = editor_c.patch(f"/api/findings/{findings_fixture['out']}/status",
                        json={"status": "triaged"})
    assert r.status_code == 403, r.text

    # admin/manager (unscoped) possono operare su entrambi
    for role in ("admin", "manager"):
        r = role_clients[role].patch(f"/api/findings/{findings_fixture['out']}/status",
                                      json={"status": "triaged"})
        assert r.status_code == 200, f"{role}: {r.text}"
