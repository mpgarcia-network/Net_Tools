"""Conector rConfig (import de inventario). Stub inicial.

Configuracao por env:
- ``RCONFIG_URL``  (ex.: https://rconfig:8443)
- ``RCONFIG_TOKEN`` (API token)

Uso previsto: importar inventario (nome/IP/vendor/modelo) uma vez, para
migrar clientes que ja usam rConfig. Nao faz backup nem push.
"""

import os


class RConfigConnector:
    name = "rconfig"

    def __init__(self) -> None:
        self.base = (os.environ.get("RCONFIG_URL") or "").rstrip("/")
        self.token = os.environ.get("RCONFIG_TOKEN") or ""

    def available(self) -> bool:
        return bool(self.base and self.token)

    def list_devices(self) -> list[dict]:
        # TODO: implementar chamada /api/v2/devices e mapear campos.
        return []

    def get_config(self, external_id: str) -> str:
        return ""

    def trigger_backup(self, external_id: str) -> bool:
        return False
