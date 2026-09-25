"""Testes do templating (Jinja) de comandos por device/site."""

import pytest

from app.templating import (
    TemplateVarError,
    build_context,
    has_template,
    parse_vars,
    render,
)

DEV = {
    "name": "sw-01",
    "ip": "10.0.0.1",
    "vendor": "HP",
    "model": "5130",
    "device_type": "hp_comware",
    "protocol": "ssh",
    "port": 22,
    "site": "HU1",
    "site_role": "acesso",
    "tags": "acesso,ti",
}

VARS = {
    "globals": {"ntp": "10.0.0.10", "vlan_mgmt": "1"},
    "sites": {"HU1": {"vlan_mgmt": "100"}, "CB": {"vlan_mgmt": "200"}},
}


def test_render_device_fields():
    out = render("hostname {{ name }} ip {{ ip }} drv {{ driver }}", DEV, VARS)
    assert out == "hostname sw-01 ip 10.0.0.1 drv hp_comware"


def test_render_var_global_and_site_override():
    out = render("ntp {{ var.ntp }} vlan {{ var.vlan_mgmt }}", DEV, VARS)
    # var.vlan_mgmt e' sobrescrito pelo site HU1 (100)
    assert out == "ntp 10.0.0.10 vlan 100"


def test_render_site_vars_not_applied_for_other_site():
    dev = dict(DEV, site="ZZ")
    out = render("vlan {{ var.vlan_mgmt }}", dev, VARS)
    # sem o site ZZ, cai no global (1)
    assert out == "vlan 1"


def test_render_plain_text_untouched():
    body = "conf t\nend"
    assert has_template(body) is False
    assert render(body, DEV, VARS) == body


def test_render_missing_var_raises():
    with pytest.raises(TemplateVarError):
        render("hostname {{ nao_existe }}", DEV, VARS)


def test_render_syntax_error_raises():
    with pytest.raises(TemplateVarError):
        render("{% for x in tags %}{{ x }}", DEV, VARS)


def test_parse_vars_invalid_json():
    with pytest.raises(TemplateVarError):
        parse_vars("{invalido")


def test_parse_vars_empty():
    assert parse_vars("") == {"globals": {}, "sites": {}}


def test_build_context_tags_list():
    ctx = build_context(DEV, VARS)
    assert ctx["site"] == "HU1"
    assert "acesso" in ctx["tags"]
    assert ctx["var"]["vlan_mgmt"] == "100"
    assert ctx["device"]["ip"] == "10.0.0.1"
