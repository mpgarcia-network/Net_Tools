import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

# ---------------------------------------------------------------------------
# Senhas de usuario (pbkdf2-sha256, sem dependencia externa)
# ---------------------------------------------------------------------------
_ITER = 200_000
MIN_PASSWORD_LEN = 8


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)
    return f"pbkdf2${_ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Cifra de segredos dos devices (Fernet; chave derivada de SECRET_KEY)
# ---------------------------------------------------------------------------
def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, Exception):
        return ""


# ---------------------------------------------------------------------------
# Mapeamento vendor/protocolo -> device_type do Netmiko
# ---------------------------------------------------------------------------
VENDOR_MAP = {
    "cisco": "cisco_ios",
    "cisco_ios": "cisco_ios",
    "cisco_xe": "cisco_ios",
    "cisco_nxos": "cisco_nxos",
    "ios": "cisco_ios",
    "iosxe": "cisco_ios",
    "nxos": "cisco_nxos",
    "arista": "arista_eos",
    "aruba": "aruba_os",
    "aruba_os": "aruba_os",
    "aruba_aoscx": "aruba_aoscx",
    "aoscx": "aruba_aoscx",
    "aruba_cx": "aruba_aoscx",
    "hp": "hp_procurve",
    "hp_procurve": "hp_procurve",
    "procurve": "hp_procurve",
    "hp_comware": "hp_comware",
    "comware": "hp_comware",
    "3com": "hp_comware",
    "h3c": "hp_comware",
    "huawei": "huawei",
    "juniper": "juniper_junos",
    "junos": "juniper_junos",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "vyos": "vyos",
    "mikrotik": "mikrotik_routeros",
    "dell": "dell_os10",
    "dell_os10": "dell_os10",
    "dell_os6": "dell_os6",
    "extreme": "extreme_exos",
    "paloalto": "paloalto_panos",
    "palo-alto": "paloalto_panos",
}


# Sentinela: o driver sera detectado em runtime (engine usa SSHDetect).
AUTODETECT = "autodetect"
_AUTODETECT_ALIASES = {"", "auto", AUTODETECT, "detectar automaticamente"}


def resolve_device_type(vendor: str, protocol: str, explicit: str = "") -> str:
    """Resolve o driver Netmiko a partir de vendor/protocolo/driver explicito.

    Retorna AUTODETECT quando nao da para inferir (o engine usa SSHDetect).
    """
    base = (explicit or "").strip()
    if base.lower() in _AUTODETECT_ALIASES:
        base = VENDOR_MAP.get((vendor or "").strip().lower(), "")
    proto = (protocol or "ssh").strip().lower()
    if not base:
        # SSHDetect nao existe para telnet: cai no driver generico cisco_ios_telnet
        base = "cisco_ios" if proto == "telnet" else AUTODETECT
    if proto == "telnet" and not base.endswith("_telnet"):
        # Netmiko: a maioria dos drivers aceita sufixo _telnet
        return f"{base}_telnet"
    return base
