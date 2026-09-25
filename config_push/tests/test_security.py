"""Testes de hash de senha, cifra de segredos e tokens de API."""

from app.security import (
    decrypt_secret,
    encrypt_secret,
    generate_api_token,
    hash_api_token,
    hash_password,
    verify_api_token,
    verify_password,
)


def test_hash_password_roundtrip():
    h = hash_password("senha-forte-123")
    assert h.startswith("pbkdf2$")
    assert verify_password("senha-forte-123", h) is True
    assert verify_password("errada", h) is False


def test_hash_password_salt_unico():
    assert hash_password("x" * 10) != hash_password("x" * 10)


def test_encrypt_decrypt_secret():
    plain = "minha-senha-secreta"
    enc = encrypt_secret(plain)
    assert enc and enc != plain
    assert decrypt_secret(enc) == plain


def test_decrypt_invalido_retorna_vazio():
    assert decrypt_secret("isto-nao-e-um-token-fernet") == ""
    assert decrypt_secret("") == ""
    assert encrypt_secret("") == ""


def test_api_token_geracao_e_verificacao():
    raw, token_hash, prefix = generate_api_token()
    assert raw.startswith("ssu_")
    assert len(raw) > 20
    assert prefix == raw[:12]
    assert token_hash == hash_api_token(raw)
    assert verify_api_token(raw, token_hash) is True
    assert verify_api_token(raw + "x", token_hash) is False
    assert verify_api_token("", token_hash) is False


def test_api_token_hash_nao_revela_token():
    raw, token_hash, _ = generate_api_token()
    assert raw not in token_hash
