"""Interface comum dos conectores externos."""

from typing import Protocol


class Connector(Protocol):
    """Contrato minimo de um conector de fonte externa."""

    name: str

    def available(self) -> bool:
        """True se o conector esta configurado e acessivel."""
        ...

    def list_devices(self) -> list[dict]:
        """Devices normalizados: name, ip, vendor, model, source, external_id."""
        ...

    def get_config(self, external_id: str) -> str:
        """Config atual (se a fonte guardar config; senao, string vazia)."""
        ...

    def trigger_backup(self, external_id: str) -> bool:
        """Pede a fonte para recoletar a config (se suportar)."""
        ...
