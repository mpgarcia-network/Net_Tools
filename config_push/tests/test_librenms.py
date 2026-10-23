"""Testes do conector LibreNMS (derivacao de vendor/modelo a partir do OS)."""

from app.connectors.librenms import _vendor_model


def test_vendor_model_comware():
    # Comware V7 => moderno
    assert _vendor_model("comware", "7.1.070") == ("HP", "Comware V5/V7 (H3C/HPE moderno)")
    # Comware sem versao => legado (_cmdline)
    assert _vendor_model("comware", "") == ("HP", "3Com/H3C antigo (exige _cmdline-mode)")
    # 3Com (V5) => legado
    assert _vendor_model("3com", "5.20 Release 2208P01") == (
        "HP",
        "3Com/H3C antigo (exige _cmdline-mode)",
    )
    # H3C => legado
    assert _vendor_model("h3c", "") == ("HP", "3Com/H3C antigo (exige _cmdline-mode)")


def test_vendor_model_dell_powerconnect():
    assert _vendor_model("powerconnect", "6.5.1.8") == ("Dell", "OS6")
    assert _vendor_model("powerconnect", "5.0.0.0") == ("Dell", "PowerConnect")


def test_vendor_model_desconhecido():
    assert _vendor_model("os-inexistente", "1.0") is None
