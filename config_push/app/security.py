import base64
import hashlib
import hmac
import os
import time

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
# Tokens de API (Bearer) — guardamos apenas o hash (sha256 do token puro)
# ---------------------------------------------------------------------------
API_TOKEN_PREFIX = "ssu_"


def generate_api_token() -> tuple[str, str, str]:
    """Gera um token novo.

    Retorna (token_puro, token_hash, prefixo). O token puro so deve ser
    exibido uma vez; o banco guarda apenas o hash.
    """
    raw = API_TOKEN_PREFIX + os.urandom(24).hex()
    return raw, hash_api_token(raw), raw[:12]


def hash_api_token(raw: str) -> str:
    return hashlib.sha256((raw or "").encode()).hexdigest()


def verify_api_token(raw: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_token(raw), stored_hash or "")


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
    "fortiswitch": "fortinet",
    "fortiswitch_os": "fortinet",
    "vyos": "vyos",
    "mikrotik": "mikrotik_routeros",
    "dell": "dell_os10",
    "dell_os10": "dell_os10",
    "dell_os6": "dell_os6",
    "extreme": "extreme_exos",
    "paloalto": "paloalto_panos",
    "palo-alto": "paloalto_panos",
}


# ---------------------------------------------------------------------------
# 2FA (TOTP - RFC 6238) e hash encadeado da auditoria (trilha imutavel)
# ---------------------------------------------------------------------------
TOTP_DIGITS = 6
TOTP_PERIOD = 30


def generate_totp_secret() -> str:
    """Gera um segredo TOTP (base32, 20 bytes) para o app autenticador."""
    return base64.b32encode(os.urandom(20)).decode()


def totp_uri(secret: str, account: str, issuer: str = "Config Push") -> str:
    return (
        f"otpauth://totp/{issuer}:{account}"
        f"?secret={secret}&issuer={issuer}&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


def totp_code(secret: str, counter: int | None = None) -> str:
    """Codigo TOTP de 6 digitos para o contador (default: agora)."""
    if counter is None:
        counter = int(time.time() // TOTP_PERIOD)
    key = base64.b32decode(secret, casefold=True)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Valida um codigo TOTP com tolerancia de ``window`` passos (30s cada)."""
    code = (code or "").strip()
    if not secret or len(code) != TOTP_DIGITS or not code.isdigit():
        return False
    now = int(time.time() // TOTP_PERIOD)
    for i in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret, now + i), code):
            return True
    return False


def chain_hash(prev_hash: str, user: str, action: str, detail: str, created_at: str) -> str:
    """Hash encadeado de um registro de auditoria (anti-tamper)."""
    payload = f"{prev_hash}|{user}|{action}|{detail}|{created_at}"
    return hashlib.sha256(payload.encode()).hexdigest()


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
