"""Testes de integracao via TestClient: login, API v1 (tokens, devices,
rate-limit) e paginas principais."""


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_login_admin(auth_client):
    r = auth_client.get("/devices", follow_redirects=False)
    assert r.status_code == 200


def test_api_sem_token_401(client):
    r = client.get("/api/v1/me")
    assert r.status_code == 401
    assert "error" in r.json()


def test_api_token_invalido_401(client):
    r = client.get("/api/v1/me", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_api_me(client, api_headers):
    r = client.get("/api/v1/me", headers=api_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["user"] == "admin"
    assert body["role"] == "admin"


def test_api_devices_paginado(client, api_headers):
    r = client.get("/api/v1/devices", headers=api_headers)
    assert r.status_code == 200
    body = r.json()
    assert "total" in body and "page" in body and "page_size" in body
    assert body["page"] == 1


def test_api_device_crud(client, api_headers):
    # cria
    payload = {
        "name": "pytest-sw-01",
        "ip": "10.0.0.250",
        "vendor": "Cisco",
        "protocol": "ssh",
        "port": 22,
        "site": "Teste",
        "site_role": "acesso",
    }
    r = client.post("/api/v1/devices", json=payload, headers=api_headers)
    assert r.status_code == 201, r.text
    dev = r.json()
    did = dev["id"]
    assert dev["name"] == "pytest-sw-01"
    assert dev["device_type"] == "cisco_ios"

    # detalhe
    r = client.get(f"/api/v1/devices/{did}", headers=api_headers)
    assert r.status_code == 200
    assert r.json()["ip"] == "10.0.0.250"

    # edita (parcial)
    r = client.patch(
        f"/api/v1/devices/{did}", json={"site": "Teste2"}, headers=api_headers
    )
    assert r.status_code == 200
    assert r.json()["site"] == "Teste2"

    # IP duplicado -> 400
    client.post(
        "/api/v1/devices",
        json={"name": "pytest-sw-02", "ip": "10.0.0.251", "vendor": "Cisco"},
        headers=api_headers,
    )
    r = client.post(
        "/api/v1/devices",
        json={"name": "pytest-sw-03", "ip": "10.0.0.251", "vendor": "Cisco"},
        headers=api_headers,
    )
    assert r.status_code == 400

    # remove
    r = client.delete(f"/api/v1/devices/{did}", headers=api_headers)
    assert r.status_code == 200
    assert r.json()["deleted"] is True
    r = client.get(f"/api/v1/devices/{did}", headers=api_headers)
    assert r.status_code == 404


def test_api_device_body_invalido_422(client, api_headers):
    r = client.post("/api/v1/devices", json={"name": "sem-ip"}, headers=api_headers)
    assert r.status_code == 422


def test_api_run_creation_dry_run(client, api_headers):
    # cria device e roda um dry-run (nao conecta)
    r = client.post(
        "/api/v1/devices",
        json={"name": "pytest-run-01", "ip": "10.0.0.252", "vendor": "Cisco"},
        headers=api_headers,
    )
    did = r.json()["id"]
    r = client.post(
        "/api/v1/runs",
        json={"device_ids": [did], "commands": "display version", "dry_run": True},
        headers=api_headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["dry_run"] is True
    assert r.json()["status"] in ("approved", "pending_approval")


def test_api_policies_e_backups(client, api_headers):
    r = client.get("/api/v1/policies", headers=api_headers)
    assert r.status_code == 200
    assert "policies" in r.json()
    r = client.get("/api/v1/backups", headers=api_headers)
    assert r.status_code == 200
    assert "backups" in r.json()


def test_paginas_principais_renderizam(auth_client):
    for path in ("/", "/devices", "/snippets", "/runs", "/compliance", "/account"):
        r = auth_client.get(path, follow_redirects=False)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


def test_account_tokens_pagina(auth_client):
    r = auth_client.get("/account")
    assert r.status_code == 200
    assert "Tokens de API" in r.text
