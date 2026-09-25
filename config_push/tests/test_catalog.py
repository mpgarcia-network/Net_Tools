"""Testes do catalogo (vendor/modelo -> driver) e Comware legado."""

from app.catalog import (
    all_drivers,
    driver_label,
    is_legacy_comware,
    resolve_driver,
    resolve_os_driver,
)


def test_resolve_driver_explicito():
    assert resolve_driver("Qualquer", "", "cisco_ios") == "cisco_ios"


def test_resolve_driver_por_vendor():
    assert resolve_driver("Cisco", "IOS / IOS-XE (Catalyst, ISR)") == "cisco_ios"
    assert resolve_driver("HP", "Comware V5/V7 (H3C/HPE moderno)") == "hp_comware"


def test_resolve_driver_default():
    # vendor conhecido sem modelo -> default explicito do vendor (Cisco = IOS)
    assert resolve_driver("Cisco", "") == "cisco_ios"
    # vendor desconhecido -> autodetect
    assert resolve_driver("Fabricante-Inexistente", "Modelo-X") == "autodetect"


def test_resolve_os_driver():
    assert resolve_os_driver("ios") == "cisco_ios"
    assert resolve_os_driver("nxos") == "cisco_nxos"
    assert resolve_os_driver("os-desconhecido") == ""


def test_is_legacy_comware():
    assert is_legacy_comware("HP", "3Com/H3C antigo (exige _cmdline-mode)") is True
    assert is_legacy_comware("3Com", "qualquer") is True
    assert is_legacy_comware("HP", "Comware V5/V7 (H3C/HPE moderno)") is False


def test_all_drivers_sem_duplicatas():
    drivers = [d for d, _ in all_drivers()]
    assert len(drivers) == len(set(drivers))


def test_driver_label_tem_fallback():
    assert driver_label("cisco_ios")
    assert driver_label("driver-que-nao-existe") == "driver-que-nao-existe"
