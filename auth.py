"""
auth.py
-------
Autenticazione e RBAC (cono di visibilita') del Vulnerability Feed Aggregator.

Ruoli:
  admin   -> tutto, inclusa la configurazione dell'applicazione.
  manager -> tutto tranne la scrittura della configurazione; gestisce le
             assegnazioni asset -> utente/gruppo e vede l'audit completo.
  editor  -> opera SOLO sugli asset assegnati a lui o a uno dei suoi gruppi
             (il "cono di visibilita'").
  viewer  -> sola lettura (niente scansioni, niente export SBOM, niente audit).

Password: PBKDF2-HMAC-SHA256 con salt casuale (stdlib, nessuna dipendenza).
Sessione: cookie HttpOnly con token firmato HMAC-SHA256
          "<user_id>.<expiry_unix>.<firma>". Il ruolo e i gruppi NON stanno
          nel token: vengono riletti dal DB a ogni richiesta, cosi' revoche e
          cambi ruolo hanno effetto immediato.
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Request

import db
from config import load_config

logger = logging.getLogger("vfa.auth")

SESSION_COOKIE = "vfa_session"
SESSION_TTL = 12 * 3600          # 12 ore
_PBKDF2_ITERATIONS = 200_000
_SECRET_FILE = Path(__file__).parent / ".vfa_auth_secret"

ROLES = ("admin", "manager", "editor", "viewer")
# Ruoli che vedono TUTTI gli asset (nessun filtro di scope).
UNSCOPED_ROLES = ("admin", "manager", "viewer")


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Ritorna 'pbkdf2$<iter>$<salt_hex>$<hash_hex>'."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(plain: str, stored: str) -> bool:
    """Confronto a tempo costante contro l'hash memorizzato."""
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Token di sessione firmato
# ---------------------------------------------------------------------------

def _secret() -> bytes:
    """Segreto HMAC: env VFA_AUTH_SECRET, altrimenti file locale auto-generato."""
    env = os.environ.get("VFA_AUTH_SECRET")
    if env:
        return env.encode()
    if not _SECRET_FILE.exists():
        _SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
        _SECRET_FILE.chmod(0o600)
    return _SECRET_FILE.read_text(encoding="utf-8").strip().encode()


def make_session_token(user_id: int) -> str:
    """Token 'uid.exp.iat.sig'. 'iat' serve a invalidare le sessioni emesse
    PRIMA di un cambio password (logout globale su cambio/reset)."""
    now = int(time.time())
    exp = now + SESSION_TTL
    payload = f"{user_id}.{exp}.{now}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def parse_session_token(token: str) -> Optional[tuple]:
    """Ritorna (user_id, issued_at) se il token e' valido e non scaduto."""
    try:
        uid_s, exp_s, iat_s, sig = token.split(".")
        payload = f"{uid_s}.{exp_s}.{iat_s}"
        expected = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp_s) < time.time():
            return None
        return int(uid_s), int(iat_s)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Token one-time (attivazione account / reset password)
# ---------------------------------------------------------------------------

def hash_token(plain: str) -> str:
    """SHA-256 del token: in DB va solo l'hash, mai il token in chiaro."""
    return hashlib.sha256(plain.encode()).hexdigest()


def create_onetime_token(user_id: int, purpose: str) -> Optional[str]:
    """
    Genera un token one-time ('activation' | 'reset'), ne salva l'hash con
    scadenza da config e brucia gli eventuali token pendenti dello stesso tipo.
    Ritorna il token in chiaro (da mettere nel link email), None se DB giu'.
    """
    cfg = load_config()["auth"]
    hours = (cfg.get("invite_ttl_hours", 48) if purpose == "activation"
             else cfg.get("reset_ttl_hours", 4))
    plain = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    db.invalidate_auth_tokens(user_id, purpose)
    if not db.insert_auth_token(user_id, hash_token(plain), purpose, expires):
        return None
    return plain


def consume_onetime_token(plain: str, purpose: str) -> Optional[dict]:
    """
    Verifica un token one-time e lo brucia. Ritorna la riga utente se valido,
    None altrimenti (inesistente, scaduto, gia' usato, purpose sbagliato).
    Risposta volutamente indistinguibile fra i casi (no enumeration).
    """
    row = db.fetch_auth_token(hash_token(plain or ""))
    if not row or row.get("purpose") != purpose or row.get("used_at"):
        return None
    try:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp < datetime.now(timezone.utc):
            return None
    except Exception:
        return None
    user = db.fetch_user(row["user_id"])
    if not user:
        return None
    db.mark_auth_token_used(row["id"])
    return user


def set_user_password(user_id: int, plain: str) -> bool:
    """
    Imposta la password (hash PBKDF2) + password_changed_at (invalida le
    sessioni emesse prima) + attiva l'account e azzera il cambio forzato.
    """
    return db.update_user(user_id, {
        "password_hash": hash_password(plain),
        "password_changed_at": datetime.now(timezone.utc).isoformat(),
        "must_change_password": False,
        "is_active": True,
    })


def password_policy_error(plain: str) -> Optional[str]:
    """Messaggio di errore se la password non rispetta la policy, None se ok."""
    min_len = load_config()["auth"].get("min_password_len", 12)
    if len(plain or "") < min_len:
        return f"Password troppo corta: minimo {min_len} caratteri"
    return None


def _rotation_expired(password_changed_at: Optional[str]) -> bool:
    """True se la rotation policy e' attiva e la password e' scaduta."""
    days = load_config()["auth"].get("rotation_days", 0)
    if not days:
        return False
    if not password_changed_at:
        return True
    try:
        changed = datetime.fromisoformat(password_changed_at)
    except Exception:
        return True
    return changed + timedelta(days=int(days)) < datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Utente corrente + scope
# ---------------------------------------------------------------------------

@dataclass
class CurrentUser:
    id: int
    username: str
    role: str
    group_ids: list = field(default_factory=list)
    must_change_password: bool = False
    email: Optional[str] = None

    @property
    def scoped(self) -> bool:
        """True se l'utente vede solo gli asset assegnati (ruolo editor)."""
        return self.role not in UNSCOPED_ROLES

    def to_dict(self) -> dict:
        return {"id": self.id, "username": self.username, "role": self.role,
                "group_ids": self.group_ids, "email": self.email,
                "must_change_password": self.must_change_password}


class AuthRequired(Exception):
    """Nessuna sessione valida: 401 per le API, redirect a /login per le pagine."""


class Forbidden(Exception):
    """Sessione valida ma ruolo/scope insufficiente: 403."""
    def __init__(self, detail: str = "Operazione non consentita per il tuo ruolo"):
        self.detail = detail


class PasswordChangeRequired(Exception):
    """Cambio password obbligatorio (primo accesso, reset admin o rotation)."""


# Path raggiungibili anche con must_change_password attivo: il minimo per
# completare il cambio password e uscire.
_CHANGE_PW_ALLOWED = ("/change-password", "/api/change-password",
                      "/api/me", "/logout")


def get_current_user(request: Request) -> CurrentUser:
    """
    Dependency FastAPI: risolve l'utente dal cookie di sessione.
    Ruolo e gruppi sono riletti dal DB a ogni richiesta (revoca immediata).
    Rifiuta: account non attivi, sessioni emesse prima dell'ultimo cambio
    password, e forza il cambio se must_change_password o rotation scaduta.
    """
    token = request.cookies.get(SESSION_COOKIE) or ""
    parsed = parse_session_token(token)
    if parsed is None:
        raise AuthRequired()
    uid, iat = parsed
    row = db.fetch_user(uid)
    if not row or not row.get("is_active", True):
        raise AuthRequired()
    # Logout globale su cambio/reset password: le sessioni emesse PRIMA di
    # password_changed_at non sono piu' valide.
    changed_at = row.get("password_changed_at")
    if changed_at:
        try:
            if datetime.fromisoformat(changed_at).timestamp() > iat + 1:
                raise AuthRequired()
        except AuthRequired:
            raise
        except Exception:
            pass
    must_change = bool(row.get("must_change_password")) \
        or _rotation_expired(changed_at)
    if must_change and request.url.path not in _CHANGE_PW_ALLOWED:
        raise PasswordChangeRequired()
    groups = db.fetch_user_group_ids(uid) or []
    return CurrentUser(id=row["id"], username=row["username"],
                       role=row["role"], group_ids=groups,
                       must_change_password=must_change,
                       email=row.get("email"))


def require_roles(*roles):
    """Factory di dependency: consente solo i ruoli indicati."""
    def dep(request: Request) -> CurrentUser:
        user = get_current_user(request)
        if user.role not in roles:
            raise Forbidden()
        return user
    return dep


def visible_asset_ids(user: CurrentUser) -> Optional[set]:
    """
    Insieme degli asset id nel cono di visibilita' dell'utente.
    None = nessun filtro (admin/manager/viewer vedono tutto).
    Set vuoto = editor senza alcuna assegnazione.
    """
    if not user.scoped:
        return None
    ids = db.fetch_assigned_asset_ids(user.id, user.group_ids)
    return ids if ids is not None else set()


def visible_asset_ips(user: CurrentUser) -> Optional[set]:
    """
    Come visible_asset_ids ma per IP/hostname (findings e posture referenziano
    gli asset per ip). None = nessun filtro.
    """
    ids = visible_asset_ids(user)
    if ids is None:
        return None
    rows = db.fetch_assets() or []
    return {r["ip"] for r in rows if r["id"] in ids}


# ---------------------------------------------------------------------------
# Seed utente admin di default
# ---------------------------------------------------------------------------

def ensure_default_admin() -> None:
    """
    Crea l'utente admin/admin al primo avvio se la tabella users e' vuota,
    con cambio password FORZATO al primo accesso.
    Best-effort: se il DB non e' raggiungibile riprova al prossimo avvio.
    """
    users = db.fetch_users()
    if users is None:
        logger.warning("Seed admin saltato: Supabase non raggiungibile.")
        return
    if users:
        return
    new_id = db.insert_user({
        "username": "admin",
        "password_hash": hash_password("admin"),
        "role": "admin",
        "must_change_password": True,
        "is_active": True,
    })
    if new_id:
        logger.warning("Creato utente di default admin/admin — "
                       "cambio password forzato al primo accesso.")
