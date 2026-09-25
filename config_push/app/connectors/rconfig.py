"""Conector rConfig (inventario + backup via API v2).

Autenticacao: header ``apitoken`` (token gerado em Settings > REST API Tokens).

Configuracao por env:
- ``RCONFIG_URL``        (ex.: https://100.120.0.41:8443)
- ``RCONFIG_TOKEN``      (valor do token)
- ``RCONFIG_VERIFY_TLS`` (default: true; use false em self-signed)

O rConfig e' a fonte de verdade do **backup**: o Config Push apenas **consulta**
(status/versoes/diff) e **dispara** a coleta (quem executa e' o rConfig).

Endpoints usados (verificados no rConfig v8 do `.41`):
- GET  /api/v2/devices                          -> inventario
- GET  /api/v2/devices/summary                  -> resumo de backup
- GET  /api/v2/config-changes/by-config/{id}    -> diff (html) entre versoes
- GET  /api/v1/download-now/{id}                -> dispara backup de 1 device
- GET  /api/v1/configs/all-by-deviceid/{id}     -> todas as versoes do device
- GET  /api/v1/configs/{id}                     -> metadados de uma config

⚠️ A API v2 NAO expoe "download-now" nem "all-by-deviceid" (so a v1). A v1/v2
NAO devolvem o conteudo bruto da config (so metadados + `config_location`);
o diff entre versoes vem pelo `config-changes/by-config`.

⚠️ A API ``/devices`` devolve ``device_password``/``device_enable_password`` em
texto: NUNCA repassamos esses campos (``_slim_device`` remove).
"""

import json
import os
import ssl
from urllib import request


class RConfigConnector:
    name = "rconfig"

    # campos sensiveis que a API devolve e que jamais devem vazar/ser guardados
    _SECRET_FIELDS = (
        "device_password",
        "device_enable_password",
        "device_username",
        "ssh_key_id",
    )

    def __init__(self, base: str | None = None, token: str | None = None, verify: bool | None = None) -> None:
        env_base = os.environ.get("RCONFIG_URL") or ""
        env_verify = (os.environ.get("RCONFIG_VERIFY_TLS", "true") or "").lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
        self.base = ((base if base is not None else env_base) or "").rstrip("/")
        self.token = token if token is not None else (os.environ.get("RCONFIG_TOKEN") or "")
        self.verify = env_verify if verify is None else bool(verify)

    def available(self) -> bool:
        return bool(self.base and self.token)

    def _ctx(self):
        return None if self.verify else ssl._create_unverified_context()

    def ping(self) -> str:
        """Valida a conexao. Levanta excecao com o erro real se falhar."""
        data = json.loads(self._req("/api/v2/devices").decode())
        rows = data.get("data", []) if isinstance(data, dict) else (data or [])
        return f"{len(rows)} device(s)"

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

    def _data(self, payload: bytes):
        try:
            obj = json.loads(payload.decode())
        except Exception:  # noqa: BLE001
            return None
        return obj.get("data", obj) if isinstance(obj, dict) else obj

    @classmethod
    def _slim_device(cls, d: dict) -> dict:
        """Remove campos sensiveis de um device da API."""
        return {k: v for k, v in d.items() if k not in cls._SECRET_FIELDS}

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
        for raw in rows:
            d = self._slim_device(raw)
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

    # -- status / resumo -----------------------------------------------------
    def summary(self) -> dict:
        if not self.available():
            return {}
        try:
            data = json.loads(self._req("/api/v2/devices/summary").decode())
            return data.get("data", {}) if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    # -- disparar backup (quem executa e' o rConfig) -------------------------
    def trigger_backup(self, external_id: str) -> bool:
        """Dispara o backup de um device (GET /api/v1/download-now/{id})."""
        if not self.available() or not str(external_id).strip():
            return False
        try:
            raw = self._req(f"/api/v1/download-now/{int(external_id)}")
        except Exception:  # noqa: BLE001
            return False
        try:
            data = json.loads(raw.decode())
        except Exception:  # noqa: BLE001
            return False
        if isinstance(data, dict):
            return bool(data.get("success", False)) or "start" in str(data.get("message", "")).lower()
        return False

    def trigger_backup_many(self, external_ids: list[str]) -> bool:
        """Dispara backup em lote (sequencia GET /download-now de cada um)."""
        ids = [str(x) for x in external_ids if str(x).strip().isdigit()]
        if not self.available() or not ids:
            return False
        ok_any = False
        for ext in ids:
            ok_any = self.trigger_backup(ext) or ok_any
        return ok_any

    # -- versoes -------------------------------------------------------------
    def versions(self, external_id: str) -> list[dict]:
        """Todas as versoes de config do device (GET v1 all-by-deviceid)."""
        if not self.available() or not str(external_id).strip():
            return []
        try:
            data = self._data(self._req(f"/api/v1/configs/all-by-deviceid/{int(external_id)}"))
        except Exception:  # noqa: BLE001
            return []
        rows = data if isinstance(data, list) else (data or {}).get("configs", [])
        out = [self._slim_config(c) for c in rows if isinstance(c, dict)]
        # mais recente primeiro (por id desc)
        out.sort(key=lambda c: int(c["id"] or 0), reverse=True)
        return out

    def latest(self, external_id: str) -> dict:
        """Ultima config do device (a de maior id na lista de versoes)."""
        vs = self.versions(external_id)
        return vs[0] if vs else {}

    @classmethod
    def _slim_config(cls, c: dict) -> dict:
        return {
            "id": str(c.get("id") or ""),
            "device_id": str(c.get("device_id") or ""),
            "command": c.get("command") or "",
            "hash": c.get("config_hash") or "",
            "version": c.get("config_version") or "",
            "filename": c.get("config_filename") or "",
            "filesize": c.get("config_filesize") or 0,
            "status": c.get("download_status"),
            "latest": bool(c.get("latest_version")),
            "started_at": c.get("start_time") or "",
            "finished_at": c.get("end_time") or "",
        }

    # -- diff ----------------------------------------------------------------
    def diff_html(self, config_id: str) -> str:
        """HTML do diff da config (old vs new)."""
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
