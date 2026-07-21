"""
test_rbac_matrix.py
--------------------
Matrice funzionale ruolo x endpoint: per ogni rotta protetta verifica che
SOLO i ruoli ammessi passino la dependency (`require_roles`) e che gli altri
ruoli autenticati ricevano 403 (JSON per /api/*, redirect 303 per le pagine).

Le rotte a sola lettura vengono chiamate per intero (200 atteso per i ruoli
ammessi). Le rotte mutanti/pesanti (scan, import, settings, users, ecc.)
vengono esercitate SOLO in negativo qui (403 per i ruoli non ammessi): la
dependency di ruolo viene valutata da FastAPI PRIMA del corpo della funzione,
quindi un ruolo non ammesso riceve 403 senza alcun side-effect, alcuna
chiamata di rete o scrittura reale. Il percorso positivo di queste rotte e'
coperto nei test dedicati (cono di visibilita', gestione utenti, settings).

ROLES = admin, manager, editor, viewer (vedi auth.py).
"""
import pytest

ROLES = ("admin", "manager", "editor", "viewer")
ADMIN_ONLY = ("admin",)
ADMIN_MANAGER = ("admin", "manager")
WRITER = ("admin", "manager", "editor")           # tutto tranne viewer
ALL = ROLES


def _forbidden(resp, path: str):
    if path.startswith("/api/"):
        return resp.status_code == 403
    # pagine: Forbidden -> redirect a "/"
    return resp.status_code in (303, 307) and resp.headers.get("location") in ("/", "http://testserver/")


# (metodo, path, kwargs extra per il client, ruoli ammessi, full_call)
# full_call=True  -> chiamata reale anche per i ruoli ammessi (200 atteso, no side-effect)
# full_call=False -> per i ruoli ammessi si verifica solo "non e' 401/403" (side-effect/rete pesanti)
READ_MATRIX = [
    ("GET", "/", {}, ALL, True),
    ("GET", "/assets", {}, ALL, True),
    ("GET", "/sbom", {}, ALL, True),
    ("GET", "/findings", {}, ALL, True),
    ("GET", "/intel", {}, ALL, True),
    ("GET", "/risk", {}, ALL, True),
    ("GET", "/audit", {}, WRITER, True),
    ("GET", "/settings", {}, ADMIN_MANAGER, True),
    ("GET", "/admin", {}, ADMIN_ONLY, True),
    ("GET", "/api/me", {}, ALL, True),
    ("GET", "/api/assets", {}, ALL, True),
    ("GET", "/api/assets/all", {}, ALL, True),
    ("GET", "/api/audit", {}, WRITER, True),
    ("GET", "/api/groups", {}, WRITER, True),
    ("GET", "/api/users", {}, ADMIN_MANAGER, True),
    ("GET", "/api/settings", {}, ADMIN_MANAGER, True),
    ("GET", "/api/posture", {}, ALL, True),
    ("GET", "/api/posture/runs", {}, ALL, True),
    ("GET", "/api/risk", {"params": {"probe": "false"}}, ALL, True),
    ("GET", "/api/risk/trend", {}, ALL, True),
    ("GET", "/api/sbom", {}, ALL, True),
    ("GET", "/api/sbom/export", {"params": {"format": "cyclonedx"}}, WRITER, True),
]

# Rotte mutanti/pesanti: verificate SOLO in negativo (403 per i ruoli esclusi).
GATE_ONLY_MATRIX = [
    ("POST", "/api/settings", {"json": {}}, ADMIN_ONLY),
    ("POST", "/api/users", {"json": {}}, ADMIN_ONLY),
    ("POST", "/api/users/999999/invite", {}, ADMIN_ONLY),
    ("POST", "/api/users/999999/reset", {}, ADMIN_ONLY),
    ("PUT", "/api/users/999999", {"json": {}}, ADMIN_ONLY),
    ("DELETE", "/api/users/999999", {}, ADMIN_ONLY),
    ("POST", "/api/groups", {"json": {}}, ADMIN_ONLY),
    ("DELETE", "/api/groups/999999", {}, ADMIN_ONLY),
    ("PUT", "/api/groups/999999/members", {"json": {}}, ADMIN_ONLY),
    ("PUT", "/api/assets/999999/assignments", {"json": {}}, ADMIN_MANAGER),
    ("GET", "/api/ollama/models", {}, ADMIN_MANAGER),
    ("POST", "/api/assets", {"json": {}}, WRITER),
    ("PUT", "/api/assets/999999", {"json": {}}, WRITER),
    ("PATCH", "/api/assets/999999/enabled", {"json": {}}, WRITER),
    ("PATCH", "/api/assets/999999/context", {"json": {}}, WRITER),
    ("DELETE", "/api/assets/999999", {}, WRITER),
    ("POST", "/api/findings/import", {"json": {}}, WRITER),
    ("PATCH", "/api/findings/999999/status", {"json": {}}, WRITER),
    ("POST", "/api/findings/999999/ticket", {"json": {}}, WRITER),
    ("POST", "/api/findings/scan-local", {"json": {}}, ADMIN_MANAGER),
    ("GET", "/api/posture/scan", {}, WRITER),
    ("POST", "/api/identify", {"json": {}}, WRITER),
    ("GET", "/api/scan", {}, WRITER),
]


@pytest.mark.parametrize("method,path,kwargs,allowed,full_call", READ_MATRIX)
def test_read_matrix(role_clients, method, path, kwargs, allowed, full_call):
    for role in ROLES:
        c = role_clients[role]
        resp = c.request(method, path, follow_redirects=False, **kwargs)
        if role in allowed:
            assert resp.status_code not in (401, 403), (
                f"{role} DOVREBBE poter accedere a {method} {path}, "
                f"ricevuto {resp.status_code}: {resp.text[:200]}"
            )
            if full_call:
                assert resp.status_code < 400, (
                    f"{role} su {method} {path} atteso <400, "
                    f"ricevuto {resp.status_code}: {resp.text[:200]}"
                )
        else:
            assert _forbidden(resp, path), (
                f"{role} NON dovrebbe poter accedere a {method} {path}, "
                f"ricevuto {resp.status_code}: {resp.text[:200]}"
            )


@pytest.mark.parametrize("method,path,kwargs,allowed", GATE_ONLY_MATRIX)
def test_gate_only_matrix_denies_other_roles(role_clients, method, path, kwargs, allowed):
    """Solo il lato negativo: nessuna chiamata reale per i ruoli ammessi
    (evita scan di rete, invio email o scritture di config reali)."""
    for role in ROLES:
        if role in allowed:
            continue
        c = role_clients[role]
        resp = c.request(method, path, follow_redirects=False, **kwargs)
        assert resp.status_code == 403, (
            f"{role} NON dovrebbe poter chiamare {method} {path}, "
            f"ricevuto {resp.status_code}: {resp.text[:200]}"
        )


def test_anonymous_gets_401_on_api(anon_client):
    for path in ("/api/me", "/api/assets", "/api/users", "/api/settings"):
        resp = anon_client.get(path)
        assert resp.status_code == 401, f"{path}: atteso 401, ricevuto {resp.status_code}"


def test_anonymous_redirects_to_login_on_pages(anon_client):
    for path in ("/", "/admin", "/settings", "/audit"):
        resp = anon_client.get(path, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers.get("location") == "/login"
