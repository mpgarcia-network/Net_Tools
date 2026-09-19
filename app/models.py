from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # admin | operator | approver | viewer
    role: Mapped[str] = mapped_column(String(20), default="operator")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # dark | light | auto
    theme: Mapped[str] = mapped_column(String(10), default="dark")
    # pt | en | es
    language: Mapped[str] = mapped_column(String(5), default="pt")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(191), index=True)
    ip: Mapped[str] = mapped_column(String(191), index=True, unique=True)
    vendor: Mapped[str] = mapped_column(String(80), default="")
    model: Mapped[str] = mapped_column(String(191), default="")
    # driver netmiko explicito (se vazio, derivamos de vendor/protocol)
    device_type: Mapped[str] = mapped_column(String(80), default="")
    protocol: Mapped[str] = mapped_column(String(20), default="ssh")  # ssh | telnet
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(191), default="")
    password_enc: Mapped[str] = mapped_column(Text, default="")
    enable_password_enc: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Snippet(Base):
    __tablename__ = "snippets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(191), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text, default="")
    # drivers netmiko alvo (CSV). Vazio = serve para qualquer driver.
    drivers: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snippet_id: Mapped[int | None] = mapped_column(ForeignKey("snippets.id"), nullable=True)
    snippet_name: Mapped[str] = mapped_column(String(191), default="")
    commands: Mapped[str] = mapped_column(Text, default="")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    # capturar/validar config (diff antes/depois); em dry-run, conecta e mostra a atual
    capture_diff: Mapped[bool] = mapped_column(Boolean, default=False)
    # pending_approval | approved | rejected | running | done | failed | canceled
    status: Mapped[str] = mapped_column(String(20), default="pending_approval", index=True)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    requested_by: Mapped[str] = mapped_column(String(120), default="")
    approved_by: Mapped[str] = mapped_column(String(120), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reject_reason: Mapped[str] = mapped_column(Text, default="")
    schedule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    targets: Mapped[list["RunTarget"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class RunTarget(Base):
    __tablename__ = "run_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_name: Mapped[str] = mapped_column(String(191), default="")
    device_ip: Mapped[str] = mapped_column(String(191), default="")
    snippet_name: Mapped[str] = mapped_column(String(191), default="")
    commands: Mapped[str] = mapped_column(Text, default="")
    # pending | running | success | failed | skipped
    status: Mapped[str] = mapped_column(String(20), default="pending")
    output: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    diff: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    run: Mapped[Run] = relationship(back_populates="targets")


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(191))
    snippet_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    commands: Mapped[str] = mapped_column(Text, default="")
    # lista de device ids em JSON
    device_ids: Mapped[str] = mapped_column(Text, default="[]")
    mode: Mapped[str] = mapped_column(String(20), default="cron")  # cron | once
    cron: Mapped[str] = mapped_column(String(80), default="")
    run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(80), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class Setting(Base):
    """Configuracoes da aplicacao (singleton id=1)."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    brand_login: Mapped[str] = mapped_column(String(191), default="")
    brand_app: Mapped[str] = mapped_column(String(191), default="")
    login_message: Mapped[str] = mapped_column(Text, default="")
    logo_login: Mapped[str] = mapped_column(String(255), default="")   # arquivo em media/
    logo_header: Mapped[str] = mapped_column(String(255), default="")  # arquivo em media/
    # Credencial padrao (TACACS/AAA): usada quando o device nao tem credencial propria
    default_username: Mapped[str] = mapped_column(String(191), default="")
    default_password_enc: Mapped[str] = mapped_column(Text, default="")
    default_enable_password_enc: Mapped[str] = mapped_column(Text, default="")
    # webhook para notificacao (Teams/Slack/generico). Vazio = desligado.
    notify_webhook_url: Mapped[str] = mapped_column(String(500), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

