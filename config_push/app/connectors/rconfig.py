"""Conector rConfig (inventario + status de backup + diff) via API v2.

Autenticacao: header ``apitoken`` (token gerado em Settings > REST API Tokens).

Configuracao por env:
- ``RCONFIG_URL``        (ex.: https://100.120.0.41:8443)
- ``RCONFIG_TOKEN``      (valor do token)
- ``RCONFIG_VERIFY_TLS`` (default: true; use false em self-signed)

Endpoints (rConfig v8, API v2):
- GET /api/v2/devices                      -> inventario
- GET /api/v2/devices/summary              -> resumo de backup
- GET /api/v2/configs                      -> metadados de config (sem conteudo)
- GET /api/v2/config-changes/by-config/{id} -> diff (html) entre versoes

Observacao: a API v2 nao devolve o conteudo bruto da config; usamos o Netmiko
para ler a config ao vivo (o diff/versao historica fica no rConfig).
"""

import json
import os
import ssl
from urllib import request


class RConfigConnector:
    name = "rconfig"

    def __init__(self) -> None:
        self.base = (os.environ.get("RCONFIG_URL") or "").rstrip("/")
        self.token = os.environ.get("RCONFIG_TOKEN") or ""
        self.verify = (os.environ.get("RCONFIG_VERIFY_TLS", "true") or "").lower() not in (
            "0",
            "false",
            "no",
            "off",
        )

    def available(self) -> bool:
        return bool(self.base and self.token)

    def _ctx(self):
        return None if self.verify else ssl._create_unverified_context()

    def _req(self, path: str, method: str = "GET", data=None, accept: str = "application/json") -> bytes:
        url = f"{self.base}{path}"
        body = None
        headers = {"apitoken": self.token, "Accept": accept}
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=body, headers=headers, method=method)
        with request.urlopen(req, timeout=60, context=self._ctx()) as resp:
            return resp.read()

    # -- inventario ----------------------------------------------------------
    def list_devices(self) -> list[dict]:
        if not self.available():
            return []
        try:
            data = json.loads(self._req("/api/v2/devices").decode())
        except Exception:  # noqa: BLE001
            return []
        rows = data.get("data", []) if isinstance(data, dict) else (data or [])
        out = []
        for d in rows:
            vendor = d.get("vendor")
            if isinstance(vendor, list) and vendor and isinstance(vendor[0], dict):
                vendor = vendor[0].get("vendorName")
            last = d.get("last_config") or {}
            out.append(
                {
                    "name": d.get("device_name") or "",
                    "ip": d.get("device_ip") or "",
                    "vendor": vendor or "",
                    "model": d.get("device_model") or "",
                    "port": d.get("device_port_override") or "",
                    "source": self.name,
                    "external_id": str(d.get("id") or ""),
                    "last_config_id": str(last.get("id") or ""),
                }
            )
        return out

    # -- backup (status/diff via rConfig) ------------------------------------
    def summary(self) -> dict:
        if not self.available():
            return {}
        try:
            data = json.loads(self._req("/api/v2/devices/summary").decode())
            return data.get("data", {}) if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def diff_html(self, config_id: str) -> str:
        if not self.available() or not config_id:
            return ""
        try:
            data = json.loads(
                self._req(f"/api/v2/config-changes/by-config/{config_id}").decode()
            )
            inner = data.get("data", {}) if isinstance(data, dict) else {}
            return inner.get("config_diff") or ""
        except Exception:  # noqa: BLE001
            return ""

    # -- nao disponivel na v2: o conteudo bruto e lido via Netmiko -----------
    def get_config(self, external_id: str) -> str:
        return ""

    def trigger_backup(self, external_id: str) -> bool:
        # v2 nao expoe "download-now"; o rConfig faz backup pelo agendamento dele.
        return False
