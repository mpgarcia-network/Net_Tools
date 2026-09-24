from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine, event, inspect, text
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
            if "site_role" not in cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN site_role VARCHAR(20) DEFAULT ''"))
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
            if "notify_webhook_url" not in setcols:
                conn.execute(
                    text("ALTER TABLE settings ADD COLUMN notify_webhook_url VARCHAR(500) DEFAULT ''")
                )
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

