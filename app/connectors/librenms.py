"""Conector LibreNMS (descoberta/inventario) via HTTP API.

Configuracao por env:
- ``LIBRENMS_URL``   (ex.: http://librenms:8000)
- ``LIBRENMS_TOKEN`` (X-Auth-Token)

Endpoint usado:
- GET /api/v0/devices -> lista de devices
"""

import json
import os
from urllib import request


class LibreNMSConnector:
    name = "librenms"

    def __init__(self) -> None:
        self.base = (os.environ.get("LIBRENMS_URL") or "").rstrip("/")
        self.token = os.environ.get("LIBRENMS_TOKEN") or ""

    def available(self) -> bool:
        return bool(self.base and self.token)

    def list_devices(self) -> list[dict]:
        if not self.available():
            return []
        try:
            req = request.Request(
                f"{self.base}/api/v0/devices",
                headers={"X-Auth-Token": self.token, "Accept": "application/json"},
            )
            with request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            return []
        out = []
        for d in data.get("devices", []):
            out.append(
                {
                    "name": d.get("sysName") or d.get("hostname") or "",
                    "ip": d.get("hostname") or "",
                    "vendor": d.get("vendor") or "",
                    "model": d.get("hardware") or "",
                    "os": d.get("os") or "",
                    "source": self.name,
                    "external_id": str(d.get("device_id") or ""),
                }
            )
        return out

    def get_config(self, external_id: str) -> str:
        return ""  # LibreNMS nao guarda config

    def trigger_backup(self, external_id: str) -> bool:
        return False
