from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

_IS_SQLITE = settings.database_url.startswith("sqlite")

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if _IS_SQLITE else {},
    pool_pre_ping=True,
)


if _IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
        # WAL + busy_timeout: evita "database is locked" com escritas concorrentes
        # (scheduler + threads de execucao + requisicoes web).
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def now_local() -> datetime:
    """Horario local (TIMEZONE) como datetime naive."""
    try:
        return datetime.now(ZoneInfo(settings.timezone)).replace(tzinfo=None)
    except Exception:
        return datetime.now()


# compat: mantido o nome antigo usado em models/service
def utcnow() -> datetime:
    return now_local()


def ensure_schema() -> None:
    """Ajustes leves de schema (SQLite) para upgrades sem perder dados."""
    insp = inspect(engine)
    if "topo_layout" in insp.get_table_names():
        tcols = {c["name"] for c in insp.get_columns("topo_layout")}
        with engine.begin() as conn:
            if "pinned" not in tcols:
                conn.execute(text("ALTER TABLE topo_layout ADD COLUMN pinned BOOLEAN DEFAULT 1"))
    if "devices" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("devices")}
        with engine.begin() as conn:
            if "enable_password_enc" not in cols:
                conn.execute(
                    text("ALTER TABLE devices ADD COLUMN enable_password_enc TEXT DEFAULT ''")
                )
            if "model" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN model VARCHAR(191) DEFAULT ''"))
            if "source" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN source VARCHAR(20) DEFAULT 'manual'"))
            if "external_id" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN external_id VARCHAR(191) DEFAULT ''"))
            if "site" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN site VARCHAR(80) DEFAULT ''"))
            if "pre_commands" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN pre_commands TEXT DEFAULT ''"))
            if "maintenance_password_enc" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN maintenance_password_enc TEXT DEFAULT ''"))
            if "site_role" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN site_role VARCHAR(20) DEFAULT ''"))
            if "last_config_id" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN last_config_id VARCHAR(191) DEFAULT ''"))
            if "last_config_at" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN last_config_at DATETIME"))
    if "snippets" in insp.get_table_names():
        scols = {c["name"] for c in insp.get_columns("snippets")}
        if "drivers" not in scols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE snippets ADD COLUMN drivers TEXT DEFAULT ''"))
    if "run_targets" in insp.get_table_names():
        tcols = {c["name"] for c in insp.get_columns("run_targets")}
        with engine.begin() as conn:
            if "snippet_name" not in tcols:
                conn.execute(text("ALTER TABLE run_targets ADD COLUMN snippet_name VARCHAR(191) DEFAULT ''"))
            if "commands" not in tcols:
                conn.execute(text("ALTER TABLE run_targets ADD COLUMN commands TEXT DEFAULT ''"))
            if "diff" not in tcols:
                conn.execute(text("ALTER TABLE run_targets ADD COLUMN diff TEXT DEFAULT ''"))
    if "runs" in insp.get_table_names():
        rcols = {c["name"] for c in insp.get_columns("runs")}
        with engine.begin() as conn:
            if "capture_diff" not in rcols:
                conn.execute(text("ALTER TABLE runs ADD COLUMN capture_diff BOOLEAN DEFAULT 0"))
    if "users" in insp.get_table_names():
        ucols = {c["name"] for c in insp.get_columns("users")}
        with engine.begin() as conn:
            if "theme" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN theme VARCHAR(10) DEFAULT 'dark'"))
            if "language" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN language VARCHAR(5) DEFAULT 'pt'"))
            if "email" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(191) DEFAULT ''"))
            if "auth_source" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN auth_source VARCHAR(10) DEFAULT 'local'"))
            if "ldap_dn" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN ldap_dn VARCHAR(255) DEFAULT ''"))
            if "totp_secret_enc" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret_enc TEXT DEFAULT ''"))
            if "totp_enabled" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0"))
    if "settings" in insp.get_table_names():
        setcols = {c["name"] for c in insp.get_columns("settings")}
        with engine.begin() as conn:
            if "default_username" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN default_username VARCHAR(191) DEFAULT ''")
                )
            if "default_password_enc" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN default_password_enc TEXT DEFAULT ''")
                )
            if "default_enable_password_enc" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN default_enable_password_enc TEXT DEFAULT ''")
                )
            if "default_maintenance_password_enc" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN default_maintenance_password_enc TEXT DEFAULT ''")
                )
            if "maintenance_candidates" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN maintenance_candidates VARCHAR(255) DEFAULT '1920,512900'")
                )
            if "notify_webhook_url" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN notify_webhook_url VARCHAR(500) DEFAULT ''")
                )
            for col, ddl in (
                ("pre_commands", "TEXT DEFAULT ''"),
                ("template_vars", "TEXT DEFAULT ''"),
                ("auth_mode", "VARCHAR(10) DEFAULT 'local'"),
                ("mfa_required", "BOOLEAN DEFAULT 0"),
                ("ldap_server", "VARCHAR(255) DEFAULT ''"),
                ("ldap_domain", "VARCHAR(120) DEFAULT ''"),
                ("ldap_base_dn", "VARCHAR(255) DEFAULT ''"),
                ("ldap_bind_dn", "VARCHAR(255) DEFAULT ''"),
                ("ldap_bind_password_enc", "TEXT DEFAULT ''"),
                ("ldap_user_attr", "VARCHAR(40) DEFAULT 'sAMAccountName'"),
                ("ldap_group_attr", "VARCHAR(40) DEFAULT 'memberOf'"),
                ("ldap_verify_tls", "BOOLEAN DEFAULT 1"),
                ("ldap_role_map", "TEXT DEFAULT '{}'"),
                ("ldap_default_role", "VARCHAR(30) DEFAULT 'viewer'"),
            ):
                if col not in setcols:
                    conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {ddl}"))
            for col, ddl in (
                ("smtp_host", "VARCHAR(255) DEFAULT ''"),
                ("smtp_port", "INTEGER DEFAULT 587"),
                ("smtp_user", "VARCHAR(255) DEFAULT ''"),
                ("smtp_password_enc", "TEXT DEFAULT ''"),
                ("smtp_tls", "BOOLEAN DEFAULT 1"),
                ("smtp_ssl", "BOOLEAN DEFAULT 0"),
                ("smtp_from", "VARCHAR(255) DEFAULT ''"),
            ):
                if col not in setcols:
                    conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {ddl}"))
            for col, ddl in (
                ("librenms_url", "VARCHAR(500) DEFAULT ''"),
                ("librenms_token_enc", "TEXT DEFAULT ''"),
                ("librenms_verify_tls", "BOOLEAN DEFAULT 1"),
                ("rconfig_url", "VARCHAR(500) DEFAULT ''"),
                ("rconfig_token_enc", "TEXT DEFAULT ''"),
                ("rconfig_verify_tls", "BOOLEAN DEFAULT 1"),
            ):
                if col not in setcols:
                    conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {ddl}"))
            for col, ddl in (
                ("ai_provider", "VARCHAR(20) DEFAULT 'openai'"),
                ("ai_base_url", "VARCHAR(500) DEFAULT ''"),
                ("ai_api_key_enc", "TEXT DEFAULT ''"),
                ("ai_model", "VARCHAR(120) DEFAULT ''"),
                ("ai_verify_tls", "BOOLEAN DEFAULT 1"),
            ):
                if col not in setcols:
                    conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {ddl}"))
    if "audit_log" in insp.get_table_names():
        acols = {c["name"] for c in insp.get_columns("audit_log")}
        if "chain_hash" not in acols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE audit_log ADD COLUMN chain_hash VARCHAR(64) DEFAULT ''"))
    if _IS_SQLITE and "devices" in insp.get_table_names():
        # indice unico de IP (best-effort: so cria se nao houver duplicatas legadas)
        try:
            with engine.begin() as conn:
                has_dup = conn.execute(
                    text("SELECT 1 FROM devices GROUP BY ip HAVING COUNT(*) > 1 LIMIT 1")
                ).first()
                if has_dup is None:
                    conn.execute(
                        text(
                            "CREATE UNIQUE INDEX IF NOT EXISTS ix_devices_ip_unique "
                            "ON devices(ip)"
                        )
                    )
        except Exception:  # noqa: BLE001
            pass
    _backfill_audit_chain()


def _backfill_audit_chain() -> None:
    """Encadeia os registros de auditoria legados (idempotente, roda no boot)."""
    from .models import AuditLog
    from .security import chain_hash

    db = SessionLocal()
    try:
        rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
        prev = ""
        dirty = False
        for r in rows:
            if not r.chain_hash:
                r.chain_hash = chain_hash(
                    prev,
                    r.user,
                    r.action,
                    r.detail,
                    r.created_at.strftime("%Y-%m-%d %H:%M:%S.%f"),
                )
                dirty = True
            prev = r.chain_hash
        if dirty:
            db.commit()
    finally:
        db.close()

