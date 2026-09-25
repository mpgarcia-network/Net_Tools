"""Autenticacao via Active Directory / LDAP (bind simples).

Mesmo modelo do rConfig: o app faz *bind* no AD com o usuario+senha e, se ok,
descobre os grupos do usuario e mapeia para um papel do Config Push.

Config em Settings (auth_mode, ldap_server, ldap_domain, ldap_base_dn,
ldap_bind_dn/password, ldap_role_map, ldap_default_role). Requer ``ldap3``.
"""

import json
import logging

from .db import SessionLocal
from .models import Setting
from .security import decrypt_secret

log = logging.getLogger("app.ldap")


def ldap_config() -> dict | None:
    db = SessionLocal()
    try:
        s = db.get(Setting, 1)
        if not s or not s.ldap_server:
            return None
        try:
            role_map = json.loads(s.ldap_role_map or "{}")
        except (ValueError, TypeError):
            role_map = {}
        return {
            "server": s.ldap_server,
            "domain": s.ldap_domain or "",
            "base_dn": s.ldap_base_dn or "",
            "bind_dn": s.ldap_bind_dn or "",
            "bind_password": decrypt_secret(s.ldap_bind_password_enc),
            "user_attr": s.ldap_user_attr or "sAMAccountName",
            "group_attr": s.ldap_group_attr or "memberOf",
            "verify_tls": bool(s.ldap_verify_tls),
            "role_map": role_map,
            "default_role": s.ldap_default_role or "viewer",
        }
    finally:
        db.close()


def role_from_groups(groups: list[str], role_map: dict, default: str) -> str:
    """Mapeia os DNs/nomes de grupo para um papel (primeiro que casar vence)."""
    norm = {g.lower() for g in groups}
    for ad_group, role in role_map.items():
        g = (ad_group or "").lower()
        if not g:
            continue
        # casa por substring (aceita nome curto do grupo ou DN completo)
        if any(g in x for x in norm):
            return role
    return default


def authenticate(username: str, password: str) -> dict | None:
    """Faz bind no AD. Devolve {username, email, groups, role, dn} ou None.

    Retorna None se LDAP nao configurado ou credenciais invalidas.
    """
    cfg = ldap_config()
    if not cfg:
        return None
    try:
        from ldap3 import ALL, Connection, Server, Tls
    except Exception:  # noqa: BLE001
        log.warning("ldap3 nao instalado; login AD indisponivel")
        return None

    domain = cfg["domain"]
    if domain and "\\" not in username and "@" not in username:
        bind_user = f"{username}@{domain}"
    else:
        bind_user = username

    tls = Tls(validate=0 if not cfg["verify_tls"] else 2)
    server = Server(cfg["server"], use_ssl=cfg["server"].lower().startswith("ldaps"), tls=tls)
    try:
        conn = Connection(server, user=bind_user, password=password, auto_bind=True, read_timeout=10)
    except Exception as e:  # noqa: BLE001
        log.info("bind LDAP falhou para %s: %s", username, e)
        return None

    try:
        # busca o proprio usuario na base para pegar email e grupos
        base = cfg["base_dn"] or server.info.other.get("defaultNamingContext", [None])[0]
        search = f"({cfg['user_attr']}={username})"
        conn.search(
            search_base=base,
            search_filter=search,
            attributes=["mail", "memberOf", "displayName"],
        )
        if not conn.entries:
            return None
        entry = conn.entries[0]
        groups = [str(g) for g in (entry.memberOf.values if "memberOf" in entry else [])]
        email = str(entry.mail) if "mail" in entry else ""
        dn = entry.entry_dn
        role = role_from_groups(groups, cfg["role_map"], cfg["default_role"])
        return {"username": username, "email": email, "groups": groups, "role": role, "dn": dn}
    finally:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass
