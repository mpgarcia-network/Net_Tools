"""Testes da avaliacao de conformidade (regras require/forbid/regex)."""

from app.compliance import evaluate

CONFIG = """
hostname SW-01
service password-encryption
snmp-server community public RO
interface Vlan1
 ip address 10.0.0.1 255.255.255.0
"""


def test_require_ok():
    rules = [{"kind": "require", "pattern": "service password-encryption"}]
    assert evaluate(CONFIG, rules) == []


def test_require_ausente():
    rules = [{"kind": "require", "pattern": "ntp server"}]
    findings = evaluate(CONFIG, rules)
    assert len(findings) == 1
    assert findings[0]["kind"] == "require"
    assert findings[0]["pattern"] == "ntp server"


def test_forbid_encontrado():
    rules = [{"kind": "forbid", "pattern": "snmp-server community public"}]
    findings = evaluate(CONFIG, rules)
    assert len(findings) == 1
    assert findings[0]["kind"] == "forbid"
    assert findings[0]["lines"] == [4]


def test_forbid_ausente_ok():
    rules = [{"kind": "forbid", "pattern": "telnet"}]
    assert evaluate(CONFIG, rules) == []


def test_regex_ok():
    rules = [{"kind": "regex", "pattern": r"ip address \d+\.\d+\.\d+\.\d+"}]
    assert evaluate(CONFIG, rules) == []


def test_regex_invalida():
    rules = [{"kind": "regex", "pattern": "("}]
    findings = evaluate(CONFIG, rules)
    assert len(findings) == 1
    assert findings[0]["invalid"]


def test_case_insensitive_por_padrao():
    rules = [{"kind": "require", "pattern": "SERVICE PASSWORD-ENCRYPTION"}]
    assert evaluate(CONFIG, rules) == []


def test_case_sensitive():
    rules = [
        {"kind": "require", "pattern": "SERVICE PASSWORD-ENCRYPTION", "case_sensitive": True}
    ]
    assert len(evaluate(CONFIG, rules)) == 1


def test_pattern_vazio_ignorado():
    rules = [{"kind": "require", "pattern": ""}]
    assert evaluate(CONFIG, rules) == []
