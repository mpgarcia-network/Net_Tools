"""Envio de e-mail (SMTP) para notificacoes.

Usa apenas a stdlib (smtplib + email). Config em Settings:
host, porta, usuario, senha (cifrada), TLS (STARTTLS) ou SSL (SMTPS), remetente.
Se o SMTP nao estiver configurado, as funcoes viram no-op silencioso.
"""

import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage

from .db import SessionLocal
from .models import Setting
from .security import decrypt_secret

log = logging.getLogger("app.mailer")


def _smtp_config() -> dict | None:
    db = SessionLocal()
    try:
        s = db.get(Setting, 1)
        if not s or not s.smtp_host:
            return None
        return {
            "host": s.smtp_host,
            "port": int(s.smtp_port or 587),
            "user": s.smtp_user or "",
            "password": decrypt_secret(s.smtp_password_enc),
            "tls": bool(s.smtp_tls),
            "ssl": bool(s.smtp_ssl),
            "sender": s.smtp_from or (s.smtp_user or "configpush@localhost"),
        }
    finally:
        db.close()


def send(to: list[str], subject: str, body: str) -> bool:
    """Envia e-mail (best-effort). Retorna True se enviou."""
    to = [x.strip() for x in to if x and x.strip()]
    if not to:
        return False
    cfg = _smtp_config()
    if not cfg:
        log.debug("SMTP nao configurado; e-mail ignorado: %s", subject)
        return False
    try:
        msg = EmailMessage()
        msg["From"] = cfg["sender"]
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject
        msg.set_content(body)
        if cfg["ssl"]:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15, context=ctx) as srv:
                if cfg["user"]:
                    srv.login(cfg["user"], cfg["password"])
                srv.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as srv:
                if cfg["tls"]:
                    srv.starttls(context=ssl.create_default_context())
                if cfg["user"]:
                    srv.login(cfg["user"], cfg["password"])
                srv.send_message(msg)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("falha ao enviar e-mail (%s): %s", subject, e)
        return False


def send_async(to: list[str], subject: str, body: str) -> None:
    """Envia em thread (nao bloqueia a requisicao)."""
    threading.Thread(target=send, args=(to, subject, body), daemon=True).start()


def send_test(to: list[str]) -> bool:
    return send(to, "[Config Push] Teste de e-mail", "Este e um e-mail de teste do Config Push.")
