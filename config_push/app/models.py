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
    # Origem do cadastro: manual | librenms | rconfig | xlsx
    source: Mapped[str] = mapped_column(String(20), default="manual", index=True)
    # ID na fonte externa (correlacao entre ferramentas)
    external_id: Mapped[str] = mapped_column(String(191), default="")
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


class Backup(Base):
    """Registro de uma coleta de config (backup) de um device.

    O conteudo versionado fica em Git (app/backup.py); aqui guardamos o
    metadado para relatorios de cobertura/status.
    """

    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    device_name: Mapped[str] = mapped_column(String(191), default="")
    device_ip: Mapped[str] = mapped_column(String(191), default="")
    # ok | failed
    status: Mapped[str] = mapped_column(String(20), default="ok", index=True)
    config_hash: Mapped[str] = mapped_column(String(64), default="")
    changed: Mapped[bool] = mapped_column(Boolean, default=False)
    message: Mapped[str] = mapped_column(Text, default="")
    # manual | schedule | push
    source: Mapped[str] = mapped_column(String(20), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(80), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class Policy(Base):
    """Politica de conformidade (golden config): regras + alvo de aplicacao."""

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(191), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    # Seletores (combinam entre si; vazio = nao filtra). Lista explicita de ids
    # em JSON restringe ainda mais quando preenchida.
    vendor: Mapped[str] = mapped_column(String(80), default="")
    driver: Mapped[str] = mapped_column(String(80), default="")
    tag: Mapped[str] = mapped_column(String(191), default="")
    device_ids: Mapped[str] = mapped_column(Text, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[list["PolicyRule"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="PolicyRule.id"
    )


class PolicyRule(Base):
    """Regra de uma politica: require (deve existir), forbid (nao pode existir)
    ou regex (deve casar alguma linha)."""

    __tablename__ = "policy_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="require")
    pattern: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    # error | warn
    severity: Mapped[str] = mapped_column(String(10), default="error")
    case_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    policy: Mapped["Policy"] = relationship(back_populates="rules")


class ComplianceRun(Base):
    """Execucao de uma politica de conformidade em um conjunto de devices."""

    __tablename__ = "compliance_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    policy_name: Mapped[str] = mapped_column(String(191), default="")
    # running | done | failed
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)
    requested_by: Mapped[str] = mapped_column(String(120), default="")
    total: Mapped[int] = mapped_column(Integer, default=0)
    compliant: Mapped[int] = mapped_column(Integer, default=0)
    violations: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    results: Mapped[list["ComplianceResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ComplianceResult(Base):
    """Resultado da avaliacao de um device numa execucao de conformidade."""

    __tablename__ = "compliance_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("compliance_runs.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    device_name: Mapped[str] = mapped_column(String(191), default="")
    device_ip: Mapped[str] = mapped_column(String(191), default="")
    # compliant | violation | error
    status: Mapped[str] = mapped_column(String(20), default="compliant", index=True)
    # lista JSON de regras violadas (kind/pattern/lines/severity/...)
    findings: Mapped[str] = mapped_column(Text, default="[]")
    config_hash: Mapped[str] = mapped_column(String(64), default="")
    changed: Mapped[bool] = mapped_column(Boolean, default=False)
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    run: Mapped["ComplianceRun"] = relationship(back_populates="results")


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

