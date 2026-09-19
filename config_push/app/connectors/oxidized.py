"""Conector Oxidized (backup/versionamento de config) via HTTP API.

Configuracao por env:
- ``OXIDIZED_URL``   (ex.: http://oxidized:8888)
- ``OXIDIZED_TOKEN`` (opcional; envia como Authorization Bearer)

Endpoints usados (padrao oxidized-web/sinatra):
- GET  /nodes                       -> lista de nodes
- GET  /node/show/<node>?format=txt -> config atual
- GET  /node/version/<node>         -> versoes (json)
- GET  /node/version/diffs?node=<n>&oid1=<a>&oid2=<b>&format=txt
- POST /node/fetch/<node>           -> dispara coleta
"""

import json
import os
from urllib import parse, request


class OxidizedConnector:
    name = "oxidized"

    def __init__(self) -> None:
        self.base = (os.environ.get("OXIDIZED_URL") or "").rstrip("/")
        self.token = os.environ.get("OXIDIZED_TOKEN") or ""

    def available(self) -> bool:
        return bool(self.base)

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _get(self, path: str, accept: str = "application/json") -> bytes:
        req = request.Request(self.base + path, headers={**self._headers(), "Accept": accept})
        with request.urlopen(req, timeout=20) as resp:
            return resp.read()

    def list_nodes(self) -> list[str]:
        if not self.available():
            return []
        try:
            data = json.loads(self._get("/nodes?format=json").decode())
            return [n.get("name") for n in data if n.get("name")]
        except Exception:  # noqa: BLE001
            return []

    def get_config(self, node: str) -> str:
        if not self.available():
            return ""
        try:
            q = parse.urlencode({"format": "txt"})
            return self._get(f"/node/show/{parse.quote(node)}?{q}", accept="text/plain").decode(
                "utf-8", "replace"
            )
        except Exception:  # noqa: BLE001
            return ""

    def get_diff(self, node: str, oid1: str, oid2: str) -> str:
        if not self.available():
            return ""
        try:
            q = parse.urlencode(
                {"node": node, "oid1": oid1, "oid2": oid2, "format": "txt"}
            )
            return self._get(f"/node/version/diffs?{q}", accept="text/plain").decode(
                "utf-8", "replace"
            )
        except Exception:  # noqa: BLE001
            return ""

    def trigger_backup(self, node: str) -> bool:
        if not self.available():
            return False
        try:
            req = request.Request(
                f"{self.base}/node/fetch/{parse.quote(node)}",
                data=b"",
                headers=self._headers(),
                method="POST",
            )
            with request.urlopen(req, timeout=60) as resp:
                return resp.status < 400
        except Exception:  # noqa: BLE001
            return False
