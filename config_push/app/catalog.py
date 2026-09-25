"""Catalogo de vendors -> modelos/plataformas -> driver do Netmiko.

Objetivo: o operador escolhe Vendor e Modelo em listas e o driver e resolvido
automaticamente (a prova de erros). VENDORS e ordenado alfabeticamente.
"""

# vendor -> lista de (modelo/plataforma, driver netmiko)
_VENDORS: dict[str, list[tuple[str, str]]] = {
    "A10": [("A10 ACOS", "a10")],
    "Adtran": [("AOS", "adtran_os")],
    "Alcatel-Lucent": [("AOS (OmniSwitch)", "alcatel_aos"), ("SR OS (7750)", "alcatel_sros")],
    "Arista": [("EOS", "arista_eos")],
    "Aruba": [
        ("ArubaOS-CX (CX 6000/6300/8xxx)", "aruba_aoscx"),
        ("ArubaOS-Switch (ProCurve/16xx/29xx)", "hp_procurve"),
        ("ArubaOS (Controladora Wireless)", "aruba_os"),
    ],
    "Avaya": [("ERS / VSP", "avaya_ers")],
    "Check Point": [("Gaia OS", "checkpoint_gaia")],
    "Ciena": [("SAOS", "ciena_saos")],
    "Cisco": [
        ("IOS / IOS-XE (Catalyst, ISR)", "cisco_ios"),
        ("NX-OS (Nexus)", "cisco_nxos"),
        ("IOS-XR", "cisco_xr"),
        ("ASA", "cisco_asa"),
        ("WLC (AireOS)", "cisco_wlc"),
        ("Small Business (SG/SF)", "cisco_s300"),
    ],
    "Dell": [
        ("OS10", "dell_os10"),
        ("OS9", "dell_os9"),
        ("OS6", "dell_os6"),
        ("PowerConnect", "dell_powerconnect"),
    ],
    "Extreme": [
        ("EXOS (Summit)", "extreme_exos"),
        ("NetIron", "extreme_netiron"),
        ("SLX", "extreme_slx"),
    ],
    "F5": [("BIG-IP (tmsh)", "f5_tmsh")],
    "Fortinet": [("FortiGate (FortiOS)", "fortinet")],
    "HP": [
        ("ProCurve / ArubaOS-Switch", "hp_procurve"),
        ("Comware V5/V7 (H3C/HPE moderno)", "hp_comware"),
        ("3Com/H3C antigo (exige _cmdline-mode)", "hp_comware"),
    ],
    "Huawei": [("VRP (S/CE)", "huawei")],
    "Juniper": [("JunOS", "juniper_junos")],
    "Linux": [("Linux (ssh)", "linux")],
    "MikroTik": [("RouterOS", "mikrotik_routeros")],
    "Nokia": [("SR OS (7750)", "nokia_sros")],
    "Opengear": [("Opengear", "opengear")],
    "Palo Alto": [("PAN-OS", "paloalto_panos")],
    "pfSense": [("pfSense", "pfsense")],
    "Ruckus": [("FastIron (ICX)", "ruckus_fastiron")],
    "SonicWall": [("SonicOS", "sonicwall")],
    "Ubiquiti": [("EdgeSwitch (EdgeOS)", "ubiquiti_edgeswitch")],
    "VyOS": [("VyOS", "vyos")],
    "Outro / Detectar automaticamente": [("Detectar automaticamente", "autodetect")],
}

# ordena vendors e seus modelos
VENDORS: dict[str, list[tuple[str, str]]] = {
    v: sorted(_VENDORS[v], key=lambda x: x[0]) for v in sorted(_VENDORS.keys(), key=str.lower)
}

# nome amigavel do driver
DRIVER_LABELS: dict[str, str] = {
    "aruba_aoscx": "Aruba AOS-CX",
    "hp_procurve": "HP ProCurve / ArubaOS-Switch",
    "hp_comware": "HP Comware / 3Com / H3C",
    "aruba_os": "ArubaOS (Wireless)",
    "cisco_ios": "Cisco IOS / IOS-XE",
    "cisco_nxos": "Cisco NX-OS",
    "cisco_xr": "Cisco IOS-XR",
    "cisco_asa": "Cisco ASA",
    "cisco_wlc": "Cisco WLC (AireOS)",
    "cisco_s300": "Cisco Small Business",
    "fortinet": "Fortinet FortiOS",
    "huawei": "Huawei VRP",
    "juniper_junos": "Juniper JunOS",
    "mikrotik_routeros": "MikroTik RouterOS",
    "paloalto_panos": "Palo Alto PAN-OS",
    "vyos": "VyOS",
    "autodetect": "Detectar automaticamente",
}

_DEFAULT_DRIVER = "autodetect"


def vendor_names() -> list[str]:
    return list(VENDORS.keys())


def models_for(vendor: str) -> list[tuple[str, str]]:
    return VENDORS.get(vendor, [])


def resolve_driver(vendor: str, model: str = "", explicit: str = "") -> str:
    """Resolve o driver netmiko a partir de vendor/modelo (ou explicito)."""
    if explicit:
        return explicit.strip()
    vendor_key = _norm(vendor)
    model_key = _norm(model)
    for vname, models in VENDORS.items():
        if _norm(vname) != vendor_key:
            continue
        for m, driver in models:
            if _norm(m) == model_key:
                return driver
        if models:
            return models[0][1]
    return _DEFAULT_DRIVER


def _norm(value: str) -> str:
    return " ".join((value or "").strip().lower().split())


def driver_label(driver: str) -> str:
    return DRIVER_LABELS.get(driver, driver)


# ---------------------------------------------------------------------------
# Mapa de OS (slug do LibreNMS) -> driver Netmiko.
# Usado no import: o campo 'os' do LibreNMS e' bem mais confiavel que o vendor.
# ---------------------------------------------------------------------------
OS_DRIVER_MAP: dict[str, str] = {
    "ios": "cisco_ios",
    "iosxe": "cisco_ios",
    "ios_xe": "cisco_ios",
    "iosxr": "cisco_xr",
    "ios_xr": "cisco_xr",
    "nxos": "cisco_nxos",
    "asa": "cisco_asa",
    "wlc": "cisco_wlc",
    "aireos": "cisco_wlc",
    "eos": "arista_eos",
    "arista_eos": "arista_eos",
    "arubaos": "aruba_os",
    "arubaos_cx": "aruba_aoscx",
    "arubacx": "aruba_aoscx",
    "aoscx": "aruba_aoscx",
    "procurve": "hp_procurve",
    "hp_procurve": "hp_procurve",
    "comware": "hp_comware",
    "hp_comware": "hp_comware",
    "3com": "hp_comware",
    "h3c": "hp_comware",
    "fortios": "fortinet",
    "fortigate": "fortinet",
    "junos": "juniper_junos",
    "vrp": "huawei",
    "routeros": "mikrotik_routeros",
    "mikrotik": "mikrotik_routeros",
    "panos": "paloalto_panos",
    "paloalto": "paloalto_panos",
    "vyos": "vyos",
    "sonicwall": "sonicwall",
    "sonicwallos": "sonicwall",
    "exos": "extreme_exos",
    "extreme": "extreme_exos",
    "dnos": "dell_os10",
    "os10": "dell_os10",
    "dellos10": "dell_os10",
    "dell_os10": "dell_os10",
    "dell_os6": "dell_os6",
    "powerconnect": "dell_os6",
    "linux": "linux",
    "edgeswitch": "ubiquiti_edgeswitch",
    "ubiquiti": "ubiquiti_edgeswitch",
}


def resolve_os_driver(os_name: str) -> str:
    """Resolve o driver Netmiko a partir do 'os' (LibreNMS). Vazio se desconhecido."""
    key = _norm(os_name).replace(" ", "_").replace("-", "_")
    return OS_DRIVER_MAP.get(key, "")


def is_legacy_comware(vendor: str, model: str, driver: str = "") -> bool:
    """True se o device e' um Comware/3Com/H3C ANTIGO (exige '_cmdline-mode on').

    Marca apenas quando o MODELO escolhido indica legado (evita casar o Comware
    moderno, cujo nome cita '3Com/H3C'). Vendor 3Com puro tambem entra.
    """
    m = (model or "").strip().lower()
    if "legacy" in m or "_cmdline" in m or "antigo" in m:
        return True
    if (vendor or "").strip().lower() == "3com":
        return True
    return False


def all_drivers() -> list[tuple[str, str]]:
    """Lista (driver, label) unica e ordenada por label, para selecao em snippets."""
    seen: dict[str, str] = {}
    for models in VENDORS.values():
        for _m, d in models:
            seen.setdefault(d, driver_label(d))
    return sorted(seen.items(), key=lambda x: x[1].lower())
