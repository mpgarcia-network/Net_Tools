"""Testes das funcoes puras do engine (parse de comandos, save por driver,
pre-comandos automaticos do Comware legado)."""

from app.engine import (
    _auto_pre_commands,
    _preprocess,
    parse_actions,
    save_cmd,
)
from app.security import encrypt_secret


def test_parse_actions_basico():
    body = "conf t\nvlan 100\n name Engenharia\nexit"
    actions = parse_actions(body)
    assert actions == [
        ("cmd", "conf t"),
        ("cmd", "vlan 100"),
        ("cmd", "name Engenharia"),
        ("cmd", "exit"),
    ]


def test_parse_actions_sleep_e_comentarios():
    body = "cmd1\n#[sleep 30]\n# comentario\ncmd2\n\n"
    actions = parse_actions(body)
    assert ("sleep", "30") in actions
    assert ("cmd", "cmd1") in actions
    assert ("cmd", "cmd2") in actions
    # comentario (# ...) e linha vazia sao ignorados
    assert all(a[1] != "# comentario" for a in actions)


def test_preprocess_remove_modo_e_separa_save():
    actions = [("cmd", "conf t"), ("cmd", "vlan 100"), ("cmd", "wr mem"), ("cmd", "end")]
    cfg, saves = _preprocess(actions, "cisco_ios")
    cfg_vals = [v for _, v in cfg]
    assert "conf t" not in cfg_vals
    assert "end" not in cfg_vals
    assert "vlan 100" in cfg_vals
    assert saves == ["wr mem"]


def test_preprocess_fortinet_passthrough():
    actions = [("cmd", "config system interface"), ("cmd", "end")]
    cfg, saves = _preprocess(actions, "fortinet")
    cfg_vals = [v for _, v in cfg]
    assert "config system interface" in cfg_vals
    assert "end" in cfg_vals
    assert saves == []


def test_save_cmd_por_driver():
    assert save_cmd("hp_comware") == "save force"
    assert save_cmd("juniper_junos") == "commit"
    assert save_cmd("fortinet") == "execute cfg save"
    assert save_cmd("aruba_aoscx") == "copy running-config startup-config"
    assert save_cmd("cisco_ios") == "write memory"
    assert save_cmd("hp_comware_telnet") == "save force"


def test_auto_pre_commands_comware_legado():
    dev = {
        "device_type": "hp_comware",
        "vendor": "HP",
        "model": "3Com/H3C antigo (exige _cmdline-mode)",
        "protocol": "ssh",
        "maintenance_password_enc": encrypt_secret("512900"),
    }
    pre = _auto_pre_commands(dev)
    assert pre == "_cmdline-mode on\nY\n512900"


def test_auto_pre_commands_comware_moderno_sem_pre():
    dev = {
        "device_type": "hp_comware",
        "vendor": "HP",
        "model": "Comware V5/V7 (H3C/HPE moderno)",
        "protocol": "ssh",
        "maintenance_password_enc": encrypt_secret("512900"),
    }
    assert _auto_pre_commands(dev) == ""


def test_auto_pre_commands_legado_sem_senha():
    dev = {
        "device_type": "hp_comware",
        "vendor": "3Com",
        "model": "3Com/H3C antigo (exige _cmdline-mode)",
        "protocol": "ssh",
        "maintenance_password_enc": "",
    }
    assert _auto_pre_commands(dev) == ""
