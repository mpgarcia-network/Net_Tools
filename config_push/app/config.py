import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "sim")


def env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


class Settings:
    app_name: str = env("APP_NAME", "Net Tools")
    # Branding (textos exibidos). Vazio cai no padrao.
    brand_login: str = os.environ.get("BRAND_LOGIN") or "Net Tools"
    brand_app: str = os.environ.get("BRAND_APP") or "Net Tools"
    # Caminho do banco (volume nomeado montado em /data)
    data_dir: Path = Path(env("DATA_DIR", "/data"))
    database_url: str = ""
    # Chave para cifrar segredos (senhas dos devices) em repouso
    secret_key: str = env("SECRET_KEY", "")
    session_secret: str = env("SESSION_SECRET", "")
    # Sessao: expira por inatividade (segundos) e exige HTTPS se atras de TLS
    session_max_age: int = env_int("SESSION_MAX_AGE", 12 * 3600)
    session_https_only: bool = env_bool("SESSION_HTTPS_ONLY", False)
    # Admin inicial (criado no primeiro start se nao existir)
    admin_user: str = env("ADMIN_USER", "admin")
    admin_password: str = env("ADMIN_PASSWORD", "")
    # Exigir aprovacao para aplicar mudancas (dry-run nunca exige)
    require_approval: bool = env_bool("REQUIRE_APPROVAL", True)
    # Timeouts/concorrencia do Netmiko
    conn_timeout: int = env_int("NETMIKO_CONN_TIMEOUT", 30)
    conn_retries: int = env_int("NETMIKO_RETRIES", 1)
    max_workers: int = env_int("NETMIKO_MAX_WORKERS", 10)
    # Fuso para agendamento/log
    timezone: str = env("TIMEZONE", "America/Sao_Paulo")

    def __init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_url = env(
            "DATABASE_URL", f"sqlite:///{self.data_dir / 'nettools.db'}"
        )
        if not self.secret_key:
            # fallback dev: chave derivada (emitimos aviso no start)
            self.secret_key = "dev-insecure-key-change-me"
        if not self.session_secret:
            self.session_secret = self.secret_key


settings = Settings()
