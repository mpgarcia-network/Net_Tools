"""Configuracao de testes.

IMPORTANTE: as variaveis de ambiente sao definidas ANTES de importar o app,
porque `app.config.settings` le o ambiente no momento do import (e cria o
diretorio de dados/DB). Usamos um diretorio temporario por sessao.
"""

import os
import tempfile
from pathlib import Path

# --- ambiente isolado (precisa vir antes de importar o app) -----------------
# ATENCAO: forcar (nao setdefault) para nunca usar o DATA_DIR/senha de producao.
_TMP = Path(tempfile.mkdtemp(prefix="ssu-cp-test-"))
os.environ["DATA_DIR"] = str(_TMP)
os.environ["SECRET_KEY"] = "test-secret-key-0123456789"
os.environ["SESSION_SECRET"] = "test-session-secret-0123456789"
os.environ["ADMIN_USER"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-admin-pass"
os.environ["REQUIRE_APPROVAL"] = "true"
# desliga integracoes/externos que poderiam vazar para o ambiente
for _var in ("LIBRENMS_URL", "LIBRENMS_TOKEN", "RCONFIG_URL", "RCONFIG_TOKEN"):
    os.environ.pop(_var, None)

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def client():
    """TestClient do FastAPI com o banco inicializado (startup)."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_client(client):
    """Cliente logado como admin (sessao por cookie)."""
    r = client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-pass"},
        follow_redirects=False,
    )
    assert r.status_code in (303, 302), r.text
    return client


@pytest.fixture()
def api_token(client):
    """Cria um token de API (admin) direto no banco e devolve o valor puro."""
    from app.db import SessionLocal
    from app.models import ApiToken
    from app.security import generate_api_token

    raw, token_hash, prefix = generate_api_token()
    db = SessionLocal()
    try:
        db.add(
            ApiToken(
                name="pytest",
                prefix=prefix,
                token_hash=token_hash,
                owner="admin",
                role="admin",
                created_by="pytest",
            )
        )
        db.commit()
    finally:
        db.close()
    return raw


@pytest.fixture()
def api_headers(api_token):
    return {"Authorization": f"Bearer {api_token}"}
