"""Cliente de IA (chat) para o Assistente.

Suporta provedores compativeis com a API da OpenAI (OpenAI, Azure, Groq,
Ollama local, etc.) e a API da Anthropic. A configuracao vem de Configuracoes
(banco) com fallback para variaveis de ambiente (ver ``settings_store.ai_config``).

Nao depende de SDK externo: usa apenas ``urllib``.
"""

import json
import re
import ssl
import urllib.error
import urllib.request

MASK = "<***>"

# palavras cujo valor (ultimo token) deve ser mascarado
_SENSITIVE_LAST = (
    "password",
    "passwd",
    "secret",
    "pre-shared-key",
    "wpa-passphrase",
    "tacacs",
    "radius",
)


class AIError(RuntimeError):
    """Erro de configuracao ou de chamada a IA."""


def mask_config(text: str) -> str:
    """Mascara segredos (community SNMP, senhas) antes de enviar a IA."""
    out: list[str] = []
    for line in (text or "").splitlines():
        low = line.lower()
        if "community" in low:
            # snmp-agent community read <nome>  |  snmp-server community <nome> ...
            if re.search(r"community\s+(read|write)\s+", low):
                line = re.sub(
                    r"(?i)(community\s+(?:read|write)\s+)(\S+)", r"\1" + MASK, line
                )
            else:
                line = re.sub(r"(?i)(community\s+)(\S+)", r"\1" + MASK, line)
        elif any(k in low for k in _SENSITIVE_LAST):
            parts = line.rsplit(None, 1)
            if len(parts) == 2:
                line = f"{parts[0]} {MASK}"
        out.append(line)
    return "\n".join(out)


def build_request(
    cfg: dict, system: str, user: str, history: list[dict] | None = None
) -> dict:
    """Monta URL/headers/payload da chamada (separado p/ testes)."""
    provider = (cfg.get("provider") or "openai").strip().lower()
    base = (cfg.get("base") or "").rstrip("/")
    key = cfg.get("key") or ""
    model = (cfg.get("model") or "").strip()
    hist = list(history or [])
    if not base or (provider != "azure" and not model):
        raise AIError("IA nao configurada (URL e modelo sao obrigatorios)")

    if provider == "anthropic":
        return {
            "url": f"{base}/v1/messages",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            },
            "payload": {
                "model": model,
                "max_tokens": int(cfg.get("max_tokens") or 1500),
                "system": system,
                "messages": hist + [{"role": "user", "content": user}],
            },
        }

    messages = [{"role": "system", "content": system}] + hist + [
        {"role": "user", "content": user}
    ]
    if provider == "azure":
        endpoint = base if "/chat/completions" in base else f"{base}/chat/completions"
        return {
            # Para Azure, base pode ser o endpoint completo do deployment,
            # incluindo /chat/completions?api-version=...
            "url": endpoint,
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "api-key": key,
            },
            "payload": {"messages": messages, "temperature": 0.2},
        }

    # openai / groq / ollama / outros compativeis
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return {
        "url": f"{base}/chat/completions",
        "headers": headers,
        "payload": {"model": model, "messages": messages, "temperature": 0.2},
    }


def _parse_response(provider: str, body: bytes) -> str:
    try:
        data = json.loads(body.decode())
    except (ValueError, UnicodeDecodeError) as e:
        raise AIError(f"resposta invalida da IA: {e}") from None
    try:
        if provider == "anthropic":
            blocks = data.get("content") or []
            return "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise AIError(f"resposta inesperada da IA: {e}") from None


def chat(
    cfg: dict,
    system: str,
    user: str,
    history: list[dict] | None = None,
    timeout: int = 90,
) -> str:
    """Envia a conversa e devolve o texto da resposta."""
    req = build_request(cfg, system, user, history)
    ctx = None if cfg.get("verify", True) else ssl._create_unverified_context()
    request = urllib.request.Request(
        req["url"],
        data=json.dumps(req["payload"]).encode(),
        headers=req["headers"],
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode()[:300]
        except Exception:  # noqa: BLE001
            pass
        raise AIError(f"HTTP {e.code}: {detail or e.reason}") from None
    except Exception as e:  # noqa: BLE001
        raise AIError(str(e)) from None
    return _parse_response((cfg.get("provider") or "openai").lower(), body).strip()


def ping(cfg: dict) -> str:
    """Testa a conexao com a IA (resposta curta)."""
    out = chat(
        cfg,
        "Voce e um assistente de rede. Responda em uma unica palavra.",
        "Responda apenas com: ok",
        timeout=30,
    )
    return (out or "")[:80]
