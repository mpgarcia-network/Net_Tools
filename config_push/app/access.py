"""Controle de acesso por papel do equipamento (site role) e nivel de operador.

Hierarquia de site role: core > distribuicao/tor > acesso. O firewall entra no
nivel avancado (exige mais conhecimento). Device **sem** site role (nao
classificado) so pode ser alvo de avancado/admin (fail-closed).
"""

# --- Papeis de usuario ------------------------------------------------------
ADMIN_ROLES = {"admin"}
RUN_ROLES = {"admin", "operator_basic", "operator_medium", "operator_advanced"}
MANAGE_ROLES = {"admin", "operator_advanced"}
APPROVER_ROLES = {"admin", "approver"}
AUDIT_ROLES = {
    "admin",
    "approver",
    "operator_basic",
    "operator_medium",
    "operator_advanced",
}
ALL_ROLES = (
    "admin",
    "operator_basic",
    "operator_medium",
    "operator_advanced",
    "approver",
    "viewer",
)

# --- Papeis de equipamento (site role) --------------------------------------
# "" = nao classificado (fail-closed: so avancado/admin mira).
SITE_ROLES = ("acesso", "tor", "distribuicao", "core", "firewall")

# Alcada de cada nivel de operador. Fail-closed: "" (nao classificado) so
# aparece no avancado (e admin, que e' bypass).
_CLEARANCE: dict[str, set[str]] = {
    "operator_basic": {"acesso"},
    "operator_medium": {"acesso", "tor", "distribuicao"},
    "operator_advanced": {"acesso", "tor", "distribuicao", "core", "firewall", ""},
}


def normalize_site_role(value: str) -> str:
    """Normaliza o site role para um dos valores validos (ou "")."""
    v = (value or "").strip().lower()
    return v if v in SITE_ROLES else ""


def allowed_site_roles(role: str) -> set[str]:
    """Conjunto de site roles que o papel pode mirar (admin = todos + vazio)."""
    if role in ADMIN_ROLES:
        return set(SITE_ROLES) | {""}
    return set(_CLEARANCE.get(role, set()))


def can_target(role: str, site_role: str) -> bool:
    """True se o papel pode criar/executar run num device com esse site role."""
    if role in ADMIN_ROLES:
        return True
    return normalize_site_role(site_role) in _CLEARANCE.get(role, set())


def can_manage_devices(role: str) -> bool:
    return role in MANAGE_ROLES
