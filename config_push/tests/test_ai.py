"""Testes sem rede do conector de IA do Assistente."""

import json

import pytest

from app import ai


def test_mask_config_masks_snmp_and_passwords():
    text = "\n".join(
        (
            "hostname sw-01",
            "snmp-server community public ro",
            "snmp-agent community read monitoramentoti",
            "local-user admin password cipher Secret123",
        )
    )
    masked = ai.mask_config(text)
    assert "hostname sw-01" in masked
    assert "public" not in masked
    assert "monitoramentoti" not in masked
    assert "Secret123" not in masked
    assert masked.count(ai.MASK) == 3


def test_build_request_openai_compatible():
    cfg = {
        "provider": "openai",
        "base": "https://api.example.test/v1/",
        "key": "token-test",
        "model": "test-model",
        "verify": True,
    }
    req = ai.build_request(cfg, "system", "pergunta", [{"role": "user", "content": "antes"}])
    assert req["url"] == "https://api.example.test/v1/chat/completions"
    assert req["headers"]["Authorization"] == "Bearer token-test"
    assert req["payload"]["model"] == "test-model"
    assert req["payload"]["messages"][-1]["content"] == "pergunta"


def test_build_request_anthropic():
    cfg = {
        "provider": "anthropic",
        "base": "https://api.anthropic.com",
        "key": "anthropic-test",
        "model": "claude-test",
    }
    req = ai.build_request(cfg, "system", "pergunta")
    assert req["url"] == "https://api.anthropic.com/v1/messages"
    assert req["headers"]["x-api-key"] == "anthropic-test"
    assert req["payload"]["system"] == "system"


def test_build_request_azure_full_endpoint():
    cfg = {
        "provider": "azure",
        "base": "https://resource.test/openai/deployments/net/chat/completions?api-version=2025-01-01",
        "key": "azure-test",
        "model": "deployment-is-in-url",
    }
    req = ai.build_request(cfg, "system", "pergunta")
    assert req["url"] == cfg["base"]
    assert req["headers"]["api-key"] == "azure-test"


def test_build_request_requires_url_and_model():
    with pytest.raises(ai.AIError):
        ai.build_request({"provider": "openai", "base": "", "model": ""}, "s", "u")


def test_chat_parses_openai_response(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "resposta"}}]}).encode()

    monkeypatch.setattr(ai.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    result = ai.chat(
        {"provider": "openai", "base": "https://ai.test/v1", "key": "k", "model": "m"},
        "system",
        "pergunta",
    )
    assert result == "resposta"


def test_chat_parses_anthropic_response(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"content": [{"type": "text", "text": "resposta"}]}).encode()

    monkeypatch.setattr(ai.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    result = ai.chat(
        {"provider": "anthropic", "base": "https://ai.test", "key": "k", "model": "m"},
        "system",
        "pergunta",
    )
    assert result == "resposta"
