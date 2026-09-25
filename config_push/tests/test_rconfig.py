"""Testes do conector rConfig (parsing/filtro, sem rede).

O conector e' a peca central do item 3: o Config Push consulta/dispara no
rConfig. Aqui validamos que os campos sensiveis NUNCA vazam e que os
payloads/metodos dos endpoints estao corretos.
"""

import json

from app.connectors.rconfig import RConfigConnector


def _conn():
    return RConfigConnector(base="https://rconfig.local", token="tok", verify=False)


def test_available():
    assert RConfigConnector(base="https://x", token="t").available() is True
    assert RConfigConnector(base="", token="").available() is False
    assert RConfigConnector(base="https://x", token="").available() is False


def test_slim_device_remove_senhas():
    raw = {
        "id": 7,
        "device_name": "SW-01",
        "device_ip": "10.0.0.1",
        "device_username": "admin",
        "device_password": "segredo123",
        "device_enable_password": "enable123",
        "ssh_key_id": 42,
        "device_model": "CX6300",
    }
    slim = RConfigConnector._slim_device(raw)
    assert "device_password" not in slim
    assert "device_enable_password" not in slim
    assert "device_username" not in slim
    assert "ssh_key_id" not in slim
    assert slim["device_name"] == "SW-01"
    assert slim["device_model"] == "CX6300"


def test_list_devices_nao_vaza_senha(monkeypatch):
    c = _conn()
    payload = {
        "data": [
            {
                "id": 1,
                "device_name": "CORE",
                "device_ip": "10.0.0.1",
                "device_password": "VAZOU",
                "vendor": [{"vendorName": "Aruba"}],
                "last_config": {"id": 11},
            }
        ]
    }
    monkeypatch.setattr(c, "_req", lambda *a, **k: json.dumps(payload).encode())
    rows = c.list_devices()
    assert len(rows) == 1
    assert rows[0]["name"] == "CORE"
    assert rows[0]["vendor"] == "Aruba"
    assert rows[0]["external_id"] == "1"
    assert rows[0]["last_config_id"] == "11"
    assert "VAZOU" not in str(rows)


def test_trigger_backup_payload(monkeypatch):
    c = _conn()
    seen = {}

    def fake_req(path, method="GET", data=None, accept="application/json"):
        seen["path"] = path
        seen["method"] = method
        return b'{"success":true,"message":"Download started for device 5"}'

    monkeypatch.setattr(c, "_req", fake_req)
    assert c.trigger_backup("5") is True
    assert seen["path"] == "/api/v1/download-now/5"
    assert seen["method"] == "GET"


def test_trigger_backup_falha(monkeypatch):
    c = _conn()
    monkeypatch.setattr(c, "_req", lambda *a, **k: b'{"success":false}')
    assert c.trigger_backup("5") is False


def test_trigger_backup_many(monkeypatch):
    c = _conn()
    seen = []

    def fake_req(path, method="GET", data=None, accept=""):
        seen.append(path)
        return b'{"success":true,"message":"Download started"}'

    monkeypatch.setattr(c, "_req", fake_req)
    assert c.trigger_backup_many(["1", "2", "x"]) is True
    assert "/api/v1/download-now/1" in seen
    assert "/api/v1/download-now/2" in seen


def test_trigger_backup_sem_id():
    c = RConfigConnector(base="https://x", token="t")
    assert c.trigger_backup("") is False
    assert c.trigger_backup_many([]) is False


def test_versions_parse(monkeypatch):
    c = _conn()
    payload = {
        "data": [
            {
                "id": 4,
                "device_id": 2,
                "command": "display current-configuration",
                "config_hash": "abc123",
                "config_version": 7,
                "latest_version": 1,
            },
            {
                "id": 11,
                "device_id": 2,
                "command": "display current-configuration",
                "config_hash": "def456",
                "config_version": 8,
                "latest_version": 0,
            },
        ]
    }
    monkeypatch.setattr(c, "_req", lambda *a, **k: json.dumps(payload).encode())
    v = c.versions("2")
    # mais recente (maior id) primeiro
    assert v[0]["id"] == "11"
    assert v[0]["hash"] == "def456"
    assert v[1]["id"] == "4"


def test_latest(monkeypatch):
    c = _conn()
    payload = {
        "data": [
            {"id": 4, "device_id": 2, "config_hash": "old"},
            {"id": 11, "device_id": 2, "config_hash": "new"},
        ]
    }
    monkeypatch.setattr(c, "_req", lambda *a, **k: json.dumps(payload).encode())
    assert c.latest("2")["id"] == "11"


def test_diff_html_parse(monkeypatch):
    c = _conn()
    payload = {"data": {"config_diff": "<table>diff</table>"}}
    monkeypatch.setattr(c, "_req", lambda *a, **k: json.dumps(payload).encode())
    assert c.diff_html("11") == "<table>diff</table>"
