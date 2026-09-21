"""Conector LibreNMS (descoberta/inventario) via HTTP API.

Configuracao por env:
- ``LIBRENMS_URL``   (ex.: http://librenms:8000)
- ``LIBRENMS_TOKEN`` (X-Auth-Token)

Endpoint usado:
- GET /api/v0/devices -> lista de devices

O ``vendor`` do LibreNMS costuma vir vazio; derivamos **vendor/modelo do
catalogo** a partir do campo ``os`` (e da versao, no caso do Dell).
"""

import json
import os
import ssl
from urllib import request

# os (LibreNMS) -> (vendor do catalogo, modelo/plataforma do catalogo)
_OS_VENDOR_MODEL: dict[str, tuple[str, str]] = {
    "procurve": ("Aruba", "ArubaOS-Switch (ProCurve/16xx/29xx)"),
    "arubaos": ("Aruba", "ArubaOS (Controladora Wireless)"),
    "arubaos-cx": ("Aruba", "ArubaOS-CX (CX 6000/6300/8xxx)"),
    "comware": ("HP", "Comware (3Com/H3C)"),
    "hp_comware": ("HP", "Comware (3Com/H3C)"),
    "3com": ("HP", "Comware (3Com/H3C)"),
    "h3c": ("HP", "Comware (3Com/H3C)"),
    "fortigate": ("Fortinet", "FortiGate (FortiOS)"),
    "fortios": ("Fortinet", "FortiGate (FortiOS)"),
    "ios": ("Cisco", "IOS / IOS-XE (Catalyst, ISR)"),
    "iosxe": ("Cisco", "IOS / IOS-XE (Catalyst, ISR)"),
    "nxos": ("Cisco", "NX-OS (Nexus)"),
    "iosxr": ("Cisco", "IOS-XR"),
    "asa": ("Cisco", "ASA"),
    "eos": ("Arista", "EOS"),
    "junos": ("Juniper", "JunOS"),
    "vrp": ("Huawei", "VRP (S/CE)"),
    "routeros": ("MikroTik", "RouterOS"),
    "panos": ("Palo Alto", "PAN-OS"),
    "vyos": ("VyOS", "VyOS"),
    "exos": ("Extreme", "EXOS (Summit)"),
}


def _vendor_model(os_name: str, version: str) -> tuple[str, str] | None:
    o = (os_name or "").strip().lower()
    if o == "powerconnect":
        # Dell PowerConnect: versao 6.x => familia OS6
        ver = (version or "").strip()
        return ("Dell", "OS6") if ver.startswith("6") else ("Dell", "PowerConnect")
    return _OS_VENDOR_MODEL.get(o)


class LibreNMSConnector:
    name = "librenms"

    def __init__(self, base: str | None = None, token: str | None = None, verify: bool | None = None) -> None:
        env_base = os.environ.get("LIBRENMS_URL") or ""
        env_verify = (os.environ.get("LIBRENMS_VERIFY_TLS", "true") or "").lower() not in (
            "0", "false", "no", "off",
        )
        self.base = ((base if base is not None else env_base) or "").rstrip("/")
        self.token = token if token is not None else (os.environ.get("LIBRENMS_TOKEN") or "")
        self.verify = env_verify if verify is None else bool(verify)

    def available(self) -> bool:
        return bool(self.base and self.token)

    def _ctx(self):
        return None if self.verify else ssl._create_unverified_context()

    def ping(self) -> str:
        """Valida a conexao. Levanta excecao com o erro real se falhar."""
        req = request.Request(
            f"{self.base}/api/v0/devices",
            headers={"X-Auth-Token": self.token, "Accept": "application/json"},
        )
        with request.urlopen(req, timeout=20, context=self._ctx()) as resp:
            data = json.loads(resp.read().decode())
        return f"{len(data.get('devices', []))} device(s)"

    def list_devices(self) -> list[dict]:
        if not self.available():
            return []
        try:
            req = request.Request(
                f"{self.base}/api/v0/devices",
                headers={"X-Auth-Token": self.token, "Accept": "application/json"},
            )
            with request.urlopen(req, timeout=60, context=self._ctx()) as resp:
                data = json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            return []
        out = []
        for d in data.get("devices", []):
            os_name = d.get("os") or ""
            version = d.get("version") or ""
            mapped = _vendor_model(os_name, version)
            if mapped:
                vendor, model = mapped
            else:
                vendor = d.get("vendor") or ""
                model = d.get("hardware") or ""
            out.append(
                {
                    "name": d.get("sysName") or d.get("hostname") or "",
                    "ip": d.get("hostname") or "",
                    "vendor": vendor,
                    "model": model,
                    "os": os_name,
                    "version": version,
                    "source": self.name,
                    "external_id": str(d.get("device_id") or ""),
                }
            )
        return out

    def get_config(self, external_id: str) -> str:
        return ""  # LibreNMS nao guarda config

    def trigger_backup(self, external_id: str) -> bool:
        return False
