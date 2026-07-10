"""
mailer.py
---------
Invio email transazionali (invito/attivazione account, reset password)
via SMTP (stdlib smtplib, nessuna dipendenza).

Configurazione in config.json, sezione 'smtp'. Se 'host' e' vuoto le email
sono disabilitate: le funzioni ritornano False e il chiamante espone il link
di attivazione all'admin (consegna manuale).

Le email NON contengono mai password: solo link one-time con token.
"""

import logging
import smtplib
from email.message import EmailMessage

from config import load_config

logger = logging.getLogger("vfa.mailer")


class MailError(Exception):
    """Invio fallito: SMTP non configurato o errore di consegna."""


def smtp_enabled() -> bool:
    """True se la sezione smtp ha un host configurato."""
    return bool((load_config().get("smtp") or {}).get("host"))


def _send(to_addr: str, subject: str, body: str) -> None:
    cfg = load_config()["smtp"]
    host = cfg.get("host")
    if not host:
        raise MailError("SMTP non configurato (settings -> smtp.host)")
    msg = EmailMessage()
    msg["From"] = cfg.get("from_addr") or cfg.get("username") or "vulnscan@localhost"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(cfg.get("port") or 587), timeout=15) as s:
            if cfg.get("use_tls", True):
                s.starttls()
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password") or "")
            s.send_message(msg)
    except Exception as exc:
        raise MailError(f"Invio email fallito: {exc}") from exc


def activation_link(token: str) -> str:
    base = (load_config()["smtp"].get("base_url") or "http://localhost:8000").rstrip("/")
    return f"{base}/activate?token={token}"


def send_activation(to_addr: str, username: str, token: str) -> None:
    """Email di invito: link one-time per impostare la propria password."""
    link = activation_link(token)
    ttl = load_config()["auth"].get("invite_ttl_hours", 48)
    _send(
        to_addr,
        "VULN.SCAN.IO — Attiva il tuo account",
        f"Ciao {username},\n\n"
        f"e' stato creato un account per te su VULN.SCAN.IO.\n"
        f"Attivalo e scegli la tua password aprendo questo link "
        f"(valido {ttl} ore, utilizzabile una sola volta):\n\n"
        f"  {link}\n\n"
        f"Se non ti aspettavi questa email, ignorala.\n",
    )


def send_reset(to_addr: str, username: str, token: str) -> None:
    """Email di reset: link one-time per reimpostare la password."""
    link = activation_link(token)
    ttl = load_config()["auth"].get("reset_ttl_hours", 4)
    _send(
        to_addr,
        "VULN.SCAN.IO — Reimposta la password",
        f"Ciao {username},\n\n"
        f"e' stato richiesto il reset della tua password su VULN.SCAN.IO.\n"
        f"Reimpostala aprendo questo link (valido {ttl} ore, utilizzabile "
        f"una sola volta):\n\n"
        f"  {link}\n\n"
        f"Se non hai richiesto tu il reset, ignora questa email: la tua "
        f"password attuale resta valida.\n",
    )
