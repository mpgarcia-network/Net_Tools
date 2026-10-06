"""Testes do item 6: 2FA (TOTP) e trilha imutavel (hash encadeado)."""

from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app
from app.models import User
from app.security import (
    chain_hash,
    encrypt_secret,
    generate_totp_secret,
    hash_password,
    totp_code,
    totp_uri,
    verify_totp,
)
from app.service import audit, verify_audit_chain
from app.settings_store import get_settings


def test_totp_gera_e_verifica():
    secret = generate_totp_secret()
    code = totp_code(secret)
    assert len(code) == 6
    assert verify_totp(secret, code)


def test_totp_rejeita_codigo_invalido():
    secret = generate_totp_secret()
    assert verify_totp(secret, "12345") is False  # tamanho errado
    assert verify_totp(secret, "abcdef") is False  # nao numerico


def test_totp_uri():
    assert "otpauth://totp/" in totp_uri("ABCDEF", "admin")


def test_qr_svg():
    from app.main import _qr_svg

    svg = _qr_svg("otpauth://totp/Teste:admin?secret=ABCDEFGHIJKLMNOP")
    assert "<svg" in svg


def test_backup_codes():
    from app.security import generate_backup_codes, hash_backup_code

    codes = generate_backup_codes()
    assert len(codes) == 8
    assert len(set(codes)) == 8  # unicos
    assert hash_backup_code(codes[0]) == hash_backup_code(codes[0].lower())
    assert hash_backup_code(codes[0]) != hash_backup_code(codes[1])


def test_consume_backup_code():
    import json

    from app.main import _consume_backup_code
    from app.security import hash_backup_code

    db = SessionLocal()
    try:
        u = User(
            username="backup-user",
            password_hash=hash_password("x"),
            role="operator",
            active=True,
        )
        code = "ABCD-EFGH-IJKL"
        u.backup_codes = json.dumps([hash_backup_code(code)])
        db.add(u)
        db.commit()
        assert _consume_backup_code(db, u, code) is True
        assert _consume_backup_code(db, u, code) is False  # uso unico
    finally:
        db.close()


def test_chain_hash_deterministic_e_encadeado():
    ts = "2026-01-01 00:00:00.000000"
    h1 = chain_hash("", "u", "login", "ok", ts)
    assert h1 == chain_hash("", "u", "login", "ok", ts)
    h2 = chain_hash(h1, "u", "logout", "ok", ts)
    assert h2 != h1


def test_chain_tamper_detected():
    # simula o encadeamento e a deteccao de adulteracao (sem tocar no DB)
    ts = "2026-01-01 00:00:00.000000"
    entries = [("u1", "login", "ok"), ("u2", "logout", "ok"), ("u3", "edit", "x")]
    prev = ""
    chain = []
    for u, a, d in entries:
        h = chain_hash(prev, u, a, d, ts)
        chain.append((u, a, d, ts, h))
        prev = h
    # adultera o registro do meio (mantendo o hash antigo)
    chain[1] = ("u2", "logout", "TAMPERED", ts, chain[1][4])
    prev = ""
    detected = False
    for u, a, d, ts_, h in chain:
        if chain_hash(prev, u, a, d, ts_) != h:
            detected = True
            break
        prev = h
    assert detected


def test_audit_chain_intacto():
    db = SessionLocal()
    try:
        audit(db, "u1", "login", "ok")
        db.commit()
        audit(db, "u2", "logout", "ok")
        db.commit()
        ok, detail = verify_audit_chain(db)
        assert ok, detail
    finally:
        db.close()


def test_login_flow_com_2fa():
    secret = generate_totp_secret()
    db = SessionLocal()
    try:
        db.add(
            User(
                username="mfa-user",
                password_hash=hash_password("senha123"),
                role="admin",
                totp_secret_enc=encrypt_secret(secret),
                totp_enabled=True,
                active=True,
            )
        )
        db.commit()
    finally:
        db.close()

    with TestClient(app) as c:
        r = c.post(
            "/login",
            data={"username": "mfa-user", "password": "senha123"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/mfa"

        r = c.post("/mfa", data={"code": totp_code(secret)}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"


def test_mfa_obrigatorio_forca_setup():
    db = SessionLocal()
    try:
        get_settings(db).mfa_required = True
        db.add(
            User(
                username="op-user",
                password_hash=hash_password("senha123"),
                role="operator",
                active=True,
            )
        )
        db.commit()
    finally:
        db.close()

    try:
        with TestClient(app) as c:
            r = c.post(
                "/login",
                data={"username": "op-user", "password": "senha123"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert r.headers["location"] == "/mfa/setup"
    finally:
        db = SessionLocal()
        try:
            get_settings(db).mfa_required = False
            db.commit()
        finally:
            db.close()
