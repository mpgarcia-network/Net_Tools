"""Renderizacao de comandos com variaveis (Jinja2) por device/site.

Os modelos de comando (snippets) podem conter placeholders Jinja que sao
resolvidos **por device** no momento da execucao:

    hostname {{ name }}
    ! site: {{ site }} / camada: {{ site_role }}
    interface Vlan{{ var.vlan_mgmt }}
     description MGMT {{ site }}
    ntp-server {{ var.ntp }}

Variaveis disponiveis (top-level): ``name``, ``hostname``, ``ip``, ``vendor``,
``model``, ``driver``/``device_type``, ``protocol``, ``port``, ``site``,
``site_role``, ``tags`` (lista) e ``device`` (dict). Alem disso:
``var`` (globais + site, com o site sobrescrevendo), ``global``, ``site_vars``,
``now`` e ``today``.

As variaveis globais/site sao um JSON editavel em Configuracoes:
``{"globals": {...}, "sites": {"HU1": {...}}}``.

Seguranca: ambiente **sandbox** do Jinja2 e ``StrictUndefined`` — variavel
inexistente gera erro (o alvo falha com mensagem clara) em vez de aplicar
config incompleta.
"""

import json
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment

from .config import settings

_env = SandboxedEnvironment(
    undefined=StrictUndefined,
    autoescape=False,
    keep_trailing_newline=True,
)

_DEVICE_FIELDS = (
    "name",
    "hostname",
    "ip",
    "vendor",
    "model",
    "driver",
    "device_type",
    "protocol",
    "port",
    "site",
    "site_role",
    "tags",
)


class TemplateVarError(ValueError):
    """Variaveis invalidas ou erro de renderizacao do template."""


def _scalar(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.dumps(value, ensure_ascii=False)


def _clean_map(obj: dict) -> dict:
    return {str(k): _scalar(v) for k, v in obj.items()}


_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def valid_key(key: str) -> bool:
    """True se a chave e' um identificador valido (letras/numeros/_)."""
    return bool(_KEY_RE.match((key or "").strip()))


def parse_vars(raw: str) -> dict:
    """Le o JSON de parametros:

    ``{"fields": [{"key","description"}], "globals": {...}, "sites": {...}}``.

    ``fields`` define os campos exibidos na tela; se ausente, e' derivado das
    chaves de ``globals`` (compatibilidade com o formato antigo).
    """
    if not (raw or "").strip():
        return {"fields": [], "globals": {}, "sites": {}}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as e:
        raise TemplateVarError(f"JSON de parametros invalido: {e}") from None
    if not isinstance(data, dict):
        raise TemplateVarError("os parametros devem ser um objeto JSON")
    globals_ = data.get("globals") or {}
    sites = data.get("sites") or {}
    fields_raw = data.get("fields") or []
    if not isinstance(globals_, dict):
        raise TemplateVarError("'globals' deve ser um objeto JSON")
    if not isinstance(sites, dict):
        raise TemplateVarError("'sites' deve ser um objeto JSON")
    if not isinstance(fields_raw, list):
        raise TemplateVarError("'fields' deve ser uma lista")

    fields: list[dict] = []
    seen: set[str] = set()
    for item in fields_raw:
        if isinstance(item, dict):
            key = str(item.get("key") or "").strip()
            desc = str(item.get("description") or "").strip()
        else:
            key, desc = str(item or "").strip(), ""
        if valid_key(key) and key not in seen:
            seen.add(key)
            fields.append({"key": key, "description": desc})
    if not fields:
        for key in globals_:
            if valid_key(key) and key not in seen:
                seen.add(key)
                fields.append({"key": str(key), "description": ""})

    clean_sites = {}
    for site, vals in sites.items():
        if vals and not isinstance(vals, dict):
            raise TemplateVarError(f"'sites.{site}' deve ser um objeto JSON")
        clean_sites[str(site)] = _clean_map(vals or {})
    return {"fields": fields, "globals": _clean_map(globals_), "sites": clean_sites}


def dump_vars(data: dict) -> str:
    """Serializa os parametros de volta para o JSON guardado no banco."""
    return json.dumps(
        {
            "fields": data.get("fields") or [],
            "globals": data.get("globals") or {},
            "sites": data.get("sites") or {},
        },
        ensure_ascii=False,
        indent=2,
    )


def build_context(device: dict, all_vars: dict | None = None) -> dict:
    """Monta o dicionario de variaveis do device para o template."""
    av = all_vars or {"globals": {}, "sites": {}}
    site_name = (device.get("site") or "").strip()
    site_vars = dict(av.get("sites", {}).get(site_name, {})) if site_name else {}
    merged = {**av.get("globals", {}), **site_vars}

    try:
        now = datetime.now(ZoneInfo(settings.timezone))
    except Exception:  # noqa: BLE001
        now = datetime.now()

    tags = [t.strip() for t in (device.get("tags") or "").split(",") if t.strip()]
    dev_view = {
        "name": device.get("name", ""),
        "hostname": device.get("name", ""),
        "ip": device.get("ip", ""),
        "vendor": device.get("vendor", ""),
        "model": device.get("model", ""),
        "driver": device.get("device_type", ""),
        "device_type": device.get("device_type", ""),
        "protocol": device.get("protocol", ""),
        "port": device.get("port", ""),
        "site": site_name,
        "site_role": device.get("site_role", ""),
        "tags": tags,
    }
    ctx = dict(dev_view)
    ctx.update(
        {
            "var": merged,
            "global": av.get("globals", {}),
            "site_vars": site_vars,
            "now": now,
            "today": now.strftime("%Y-%m-%d"),
            "device": dev_view,
        }
    )
    return ctx


def has_template(body: str) -> bool:
    return "{{" in (body or "") or "{%" in (body or "")


def render(body: str, device: dict, all_vars: dict | None = None) -> str:
    """Renderiza o corpo (Jinja) com os dados do device + variaveis."""
    text = body or ""
    if not has_template(text):
        return text
    try:
        ctx = build_context(device, all_vars)
    except TemplateVarError:
        raise
    except Exception as e:  # noqa: BLE001
        raise TemplateVarError(f"contexto de variaveis invalido: {e}") from None
    try:
        return _env.from_string(text).render(**ctx)
    except TemplateError as e:
        raise TemplateVarError(str(e)) from None


def variable_reference() -> list[tuple[str, str]]:
    """Lista (nome, descricao) das variaveis de device, para a UI."""
    return [
        ("name / hostname", "nome do device"),
        ("ip", "IP de gerencia"),
        ("vendor", "fabricante"),
        ("model", "modelo/plataforma"),
        ("driver", "driver Netmiko"),
        ("protocol", "ssh ou telnet"),
        ("port", "porta"),
        ("site", "site/local fisico"),
        ("site_role", "camada (acesso/tor/.../core)"),
        ("tags", "lista de tags"),
        ("var.*", "variaveis globais + do site"),
        ("now / today", "data/hora da execucao"),
    ]
