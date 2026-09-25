import os
import re
import secrets
import time
from pathlib import Path

from .config import env_bool, settings
from .models import Setting
from .security import decrypt_secret

MEDIA_DIR: Path = settings.data_dir / "media"
MEDIA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_LOGO_LOGIN = "/static/logo.svg"
DEFAULT_LOGO_HEADER = "/static/logo.svg"

# Assinaturas reais de imagem (magic bytes). SVG fica de fora de proposito:
# e XML e pode carregar script (XSS armazenado ao ser servido inline).
_IMAGE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"BM", ".bmp"),
]


def _detect_image_ext(content: bytes) -> str | None:
    for sig, ext in _IMAGE_SIGNATURES:
        if content.startswith(sig):
            return ext
    if len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return ".webp"
    return None


def get_settings(db) -> Setting:
    s = db.get(Setting, 1)
    if s is None:
        s = Setting(
            id=1,
            brand_login=settings.brand_login,
            brand_app=settings.brand_app,
            login_message="",
            logo_login="",
            logo_header="",
        )
        db.add(s)
        db.commit()
        db.refresh(s)
    return s


def logo_login_url(s: Setting) -> str:
    return f"/media/{s.logo_login}" if s.logo_login else DEFAULT_LOGO_LOGIN


def logo_header_url(s: Setting) -> str:
    return f"/media/{s.logo_header}" if s.logo_header else DEFAULT_LOGO_HEADER


def brand_login_of(s: Setting) -> str:
    return s.brand_login or settings.brand_login


def brand_app_of(s: Setting) -> str:
    return s.brand_app or settings.brand_app


def save_media(filename: str, content: bytes) -> str:
    """Grava a imagem validando o conteudo real (nao confia na extensao)."""
    ext = _detect_image_ext(content)
    if ext is None:
        raise ValueError(
            "arquivo nao e uma imagem valida (aceito: PNG, JPG, GIF, WEBP, BMP)"
        )
    name = f"{secrets.token_hex(8)}{ext}"
    (MEDIA_DIR / name).write_bytes(content)
    return name


def media_path(name: str) -> Path | None:
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return None
    p = (MEDIA_DIR / name).resolve()
    if p.parent != MEDIA_DIR.resolve():
        return None
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# Cache do branding (evita abrir/usar a sessao do banco a cada pagina)
# ---------------------------------------------------------------------------
_BRAND_TTL = 15.0
_brand_cache: dict = {"ts": 0.0, "data": None}


def invalidate_branding() -> None:
    _brand_cache["data"] = None


def integration_config(db) -> dict[str, dict]:
    """Conexoes (LibreNMS/rConfig) efetivas: banco primeiro, senao env.

    Devolve ``{"librenms": {base, token, verify}, "rconfig": {...}}``.
    """
    s = get_settings(db)
    ln_url = (s.librenms_url or "").strip()
    rc_url = (s.rconfig_url or "").strip()
    return {
        "librenms": {
            "base": (ln_url or os.environ.get("LIBRENMS_URL") or "").rstrip("/"),
            "token": decrypt_secret(s.librenms_token_enc)
            or (os.environ.get("LIBRENMS_TOKEN") or ""),
            "verify": s.librenms_verify_tls
            if ln_url
            else env_bool("LIBRENMS_VERIFY_TLS", True),
        },
        "rconfig": {
            "base": (rc_url or os.environ.get("RCONFIG_URL") or "").rstrip("/"),
            "token": decrypt_secret(s.rconfig_token_enc)
            or (os.environ.get("RCONFIG_TOKEN") or ""),
            "verify": s.rconfig_verify_tls
            if rc_url
            else env_bool("RCONFIG_VERIFY_TLS", True),
        },
    }


def branding(db) -> dict:
    now = time.monotonic()
    cached = _brand_cache["data"]
    if cached is not None and (now - _brand_cache["ts"]) < _BRAND_TTL:
        return cached
    s = get_settings(db)
    data = {
        "brand_login": brand_login_of(s),
        "brand_app": brand_app_of(s),
        "login_message": s.login_message or "",
        "logo_login_url": logo_login_url(s),
        "logo_header_url": logo_header_url(s),
    }
    _brand_cache.update(ts=now, data=data)
    return data
