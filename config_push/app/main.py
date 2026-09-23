import csv
import json
import logging
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from io import StringIO
from urllib.parse import urlsplit

from croniter import croniter
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import selectinload
from starlette.middleware.sessions import SessionMiddleware

from .config import BASE_DIR, settings
from .catalog import VENDORS, all_drivers, resolve_driver, resolve_os_driver
from .access import (
    ADMIN_ROLES,
    ALL_ROLES,
    APPROVER_ROLES,
    AUDIT_ROLES,
    MANAGE_ROLES,
    RUN_ROLES,
    SITE_ROLES,
    allowed_site_roles,
    can_target,
    normalize_site_role,
)
from .connectors.librenms import LibreNMSConnector
from .connectors.rconfig import RConfigConnector
from .db import Base, SessionLocal, engine, ensure_schema, utcnow
from .i18n import LANGS, t as translate, translator
from .importer import parse_devices
from .models import (
    AuditLog,
    Backup,
    ComplianceResult,
    ComplianceRun,
    Device,
    Policy,
    PolicyRule,
    Run,
    RunTarget,
    Schedule,
    Snippet,
    User,
)
from .compliance import select_devices, start_policy_async
from .security import (
    MIN_PASSWORD_LEN,
    encrypt_secret,
    hash_password,
    verify_password,
)
from .service import (
    audit,
    collect_backup,
    create_run,
    notify,
    recover_orphans,
    schedule_has_pending,
    schedule_next,
    start_backup_all_async,
    start_run_async,
)
from .settings_store import (
    branding,
    get_settings,
    integration_config,
    invalidate_branding,
    media_path,
    save_media,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    recover_orphans()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",
    https_only=settings.session_https_only,
    max_age=settings.session_max_age,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

ROLES = ALL_ROLES
PER_PAGE = 50


def _static_version() -> str:
    """Versao dos estáticos (mtime) para cache-busting no navegador."""
    files = [BASE_DIR / "static" / n for n in ("app.js", "app.css")]
    try:
        return str(int(max(f.stat().st_mtime for f in files if f.exists())))
    except ValueError:
        return "0"


STATIC_V = _static_version()

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'; "
    "base-uri 'self'; form-action 'self'"
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Defesa anti-CSRF (alem do SameSite=Lax): bloqueia POST cross-origin.
    if request.method not in SAFE_METHODS:
        origin = request.headers.get("origin") or request.headers.get("referer")
        host = request.headers.get("host")
        if origin and host:
            netloc = urlsplit(origin).netloc
            if netloc and netloc != host:
                return HTMLResponse(
                    "<h3>403</h3><p>Origem da requisicao nao permitida.</p>",
                    status_code=403,
                )
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        # sempre revalida (evita JS/CSS antigos em cache apos um deploy)
        response.headers["Cache-Control"] = "no-cache"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", _CSP)
    if settings.session_https_only:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema()
    db = SessionLocal()
    try:
        if settings.secret_key == "dev-insecure-key-change-me":
            log.warning(
                "SECRET_KEY nao definida: usando chave de desenvolvimento. "
                "Defina SECRET_KEY no .env antes de cadastrar devices."
            )
        if db.scalar(select(func.count()).select_from(User)) == 0:
            password = settings.admin_password or secrets.token_urlsafe(12)
            db.add(
                User(
                    username=settings.admin_user,
                    password_hash=hash_password(password),
                    role="admin",
                )
            )
            db.commit()
            if not settings.admin_password:
                log.warning(
                    "admin '%s' criado com senha temporaria: %s "
                    "(defina ADMIN_PASSWORD no .env)",
                    settings.admin_user,
                    password,
                )
        get_settings(db)
        # migracao: o antigo papel generico 'operator' vira 'operator_advanced'
        db.execute(text("UPDATE users SET role='operator_advanced' WHERE role='operator'"))
        now = utcnow()
        for sch in db.scalars(select(Schedule)).all():
            if (
                sch.mode == "once"
                and sch.enabled
                and sch.run_at
                and sch.run_at < now
                and sch.last_run_at is None
            ):
                # pontual perdida durante o downtime: nao dispara no boot
                sch.enabled = False
                log.warning("agendamento '%s' (once) no passado foi desabilitado", sch.name)
            schedule_next(sch)
        db.commit()
    finally:
        db.close()


def scheduler_loop() -> None:
    while True:
        try:
            db = SessionLocal()
            try:
                now = utcnow()
                due = db.scalars(
                    select(Schedule).where(
                        Schedule.enabled == True,  # noqa: E712
                        Schedule.next_run_at.is_not(None),
                        Schedule.next_run_at <= now,
                    )
                ).all()
                for sch in due:
                    device_ids = json.loads(sch.device_ids or "[]")
                    devices = (
                        db.scalars(select(Device).where(Device.id.in_(device_ids))).all()
                        if device_ids
                        else []
                    )
                    # revalida a alcada pelo papel atual de quem criou o agendamento
                    creator = (
                        db.scalar(select(User).where(User.username == sch.created_by))
                        if sch.created_by
                        else None
                    )
                    creator_role = creator.role if creator else "viewer"
                    devices = [d for d in devices if can_target(creator_role, d.site_role)]
                    if devices and not (
                        sch.require_approval and schedule_has_pending(db, sch.id)
                    ):
                        run = create_run(
                            db,
                            snippet_id=sch.snippet_id,
                            snippet_name=sch.name,
                            commands=sch.commands,
                            devices=list(devices),
                            dry_run=sch.dry_run,
                            require_approval=sch.require_approval,
                            requested_by=f"schedule:{sch.name}",
                            schedule_id=sch.id,
                        )
                        if run.status == "approved":
                            start_run_async(run.id)
                    sch.last_run_at = now
                    schedule_next(sch)
                    if sch.mode == "once":
                        sch.enabled = False
                db.commit()
            finally:
                db.close()
        except Exception as e:  # noqa: BLE001
            log.exception("scheduler erro: %s", e)
        time.sleep(20)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user(request: Request):
    sess = request.session.get("user")
    if not sess:
        return None
    # revalida contra o banco: usuario removido/desativado perde o acesso na hora
    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.username == sess.get("name")))
        active = bool(u and u.active)
    finally:
        db.close()
    if not active:
        request.session.clear()
        return None
    sess["role"] = u.role
    sess["theme"] = u.theme or "dark"
    sess["language"] = u.language or "pt"
    request.session["user"] = sess
    return sess


def require_login(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


# ---------------------------------------------------------------------------
# Rate-limit de login (em memoria; 1 replica)
# ---------------------------------------------------------------------------
_LOGIN_MAX_FAILS = 5
_LOGIN_WINDOW = 300.0  # 5 min
_login_fails: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _login_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "?"
    return f"{ip}|{username.strip().lower()}"


def _login_blocked(key: str) -> bool:
    with _login_lock:
        now = time.monotonic()
        fails = [t for t in _login_fails.get(key, []) if now - t < _LOGIN_WINDOW]
        _login_fails[key] = fails
        return len(fails) >= _LOGIN_MAX_FAILS


def _login_register_fail(key: str) -> None:
    with _login_lock:
        _login_fails.setdefault(key, []).append(time.monotonic())


def _login_clear(key: str) -> None:
    with _login_lock:
        _login_fails.pop(key, None)


def require_role(request: Request, roles: set[str]):
    user = require_login(request)
    if user["role"] not in roles:
        raise HTTPException(status_code=403, detail="sem permissao")
    return user


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    db = SessionLocal()
    try:
        ctx.setdefault("cfg", branding(db))
    finally:
        db.close()
    ctx.setdefault("user", current_user(request))
    ctx.setdefault("app_name", settings.app_name)
    ctx.setdefault("roles", ROLES)
    ctx.setdefault("static_v", STATIC_V)
    u = ctx.get("user")
    ctx.setdefault("theme", (u or {}).get("theme") or "auto")
    lang = _lang(request)
    ctx.setdefault("lang", lang)
    ctx.setdefault("langs", LANGS)
    ctx.setdefault("t", translator(lang))
    return templates.TemplateResponse(request, name, ctx)


def _lang(request: Request) -> str:
    """Idioma: preferencia do usuario; sem login, usa Accept-Language."""
    u = current_user(request)
    if u:
        return u.get("language") or "pt"
    al = (request.headers.get("accept-language") or "").lower()
    if al.startswith("es"):
        return "es"
    if al.startswith("en"):
        return "en"
    return "pt"


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if exc.status_code == 307 and "Location" in (exc.headers or {}):
        return RedirectResponse(exc.headers["Location"], status_code=303)
    return HTMLResponse(
        f"<h3>Erro {exc.status_code}</h3><p>{exc.detail}</p>", status_code=exc.status_code
    )


# ---------------------------------------------------------------------------
# Login / account
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html", error=None)


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    key = _login_key(request, username)
    if _login_blocked(key):
        return render(
            request, "login.html", error=translate(_lang(request), "msg.too_many_attempts")
        )
    db = SessionLocal()
    try:
        user = db.scalar(select(User).where(User.username == username))
        if user and user.active and verify_password(password, user.password_hash):
            _login_clear(key)
            request.session["user"] = {"name": user.username, "role": user.role}
            audit(db, user.username, "login", "ok")
            db.commit()
            return RedirectResponse("/", status_code=303)
        _login_register_fail(key)
        if user:
            audit(db, username, "login", "senha invalida")
            db.commit()
    finally:
        db.close()
    return render(request, "login.html", error=translate(_lang(request), "msg.login_invalid"))


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/account", response_class=HTMLResponse)
def account(request: Request):
    require_login(request)
    return render(request, "account.html", error=None, ok=None)


@app.post("/account/password")
def account_password(
    request: Request,
    current: str = Form(...),
    new1: str = Form(...),
    new2: str = Form(...),
):
    user = require_login(request)
    lang = user.get("language") or "pt"
    if new1 != new2:
        return render(
            request, "account.html", error=translate(lang, "msg.password_mismatch"), ok=None
        )
    if len(new1) < MIN_PASSWORD_LEN:
        return render(
            request,
            "account.html",
            error=translate(lang, "msg.password_short", n=MIN_PASSWORD_LEN),
            ok=None,
        )
    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.username == user["name"]))
        if not u or not verify_password(current, u.password_hash):
            return render(
                request, "account.html", error=translate(lang, "msg.password_current"), ok=None
            )
        u.password_hash = hash_password(new1)
        audit(db, user["name"], "password_change", "self")
        db.commit()
    finally:
        db.close()
    return render(
        request, "account.html", error=None, ok=translate(lang, "msg.password_changed")
    )


@app.post("/account/theme")
def account_theme(request: Request, theme: str = Form("dark")):
    user = require_login(request)
    if theme not in ("dark", "light", "auto"):
        raise HTTPException(400, "tema invalido")
    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.username == user["name"]))
        if u:
            u.theme = theme
        audit(db, user["name"], "theme_change", theme)
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/account", status_code=303)


@app.post("/account/language")
def account_language(request: Request, language: str = Form("pt")):
    user = require_login(request)
    if language not in LANGS:
        raise HTTPException(400, "idioma invalido")
    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.username == user["name"]))
        if u:
            u.language = language
        audit(db, user["name"], "language_change", language)
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/account", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    require_login(request)
    db = SessionLocal()
    try:
        counts = {
            "devices": db.scalar(select(func.count()).select_from(Device)) or 0,
            "snippets": db.scalar(select(func.count()).select_from(Snippet)) or 0,
            "pending": db.scalar(
                select(func.count()).select_from(Run).where(Run.status == "pending_approval")
            )
            or 0,
            "runs": db.scalar(select(func.count()).select_from(Run)) or 0,
        }
        recent = db.scalars(select(Run).order_by(Run.id.desc()).limit(8)).all()
        next_schedules = db.scalars(
            select(Schedule)
            .where(Schedule.enabled == True, Schedule.next_run_at.is_not(None))  # noqa: E712
            .order_by(Schedule.next_run_at)
            .limit(5)
        ).all()
        recent_failures = db.scalars(
            select(Run)
            .where(Run.status.in_(("failed", "partial")))
            .order_by(Run.id.desc())
            .limit(5)
        ).all()
    finally:
        db.close()
    return render(
        request,
        "dashboard.html",
        counts=counts,
        recent=recent,
        next_schedules=next_schedules,
        recent_failures=recent_failures,
    )


# ---------------------------------------------------------------------------
# Media (logos enviados)
# ---------------------------------------------------------------------------
@app.get("/media/{name}")
def media(name: str):
    p = media_path(name)
    if not p:
        raise HTTPException(404, "arquivo nao encontrado")
    return FileResponse(p)


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------
@app.get("/devices", response_class=HTMLResponse)
def devices_list(
    request: Request,
    q: str = "",
    vendor: str = "",
    driver: str = "",
    protocol: str = "",
    active: str = "",
    site: str = "",
    site_role: str = "",
    sort: str = "name",
    dir: str = "asc",
    page: int = 1,
):
    require_login(request)
    page = max(1, page)
    sort_cols = {
        "id": Device.id,
        "name": Device.name,
        "ip": Device.ip,
        "vendor": Device.vendor,
        "model": Device.model,
        "device_type": Device.device_type,
        "protocol": Device.protocol,
        "port": Device.port,
        "username": Device.username,
        "tags": Device.tags,
        "site": Device.site,
        "site_role": Device.site_role,
        "enabled": Device.enabled,
    }
    if sort not in sort_cols:
        sort = "name"
    dir = "desc" if dir == "desc" else "asc"
    order = sort_cols[sort].desc() if dir == "desc" else sort_cols[sort].asc()
    conds = []
    if q.strip():
        like = f"%{q.strip()}%"
        conds.append(
            or_(Device.name.ilike(like), Device.ip.ilike(like), Device.tags.ilike(like))
        )
    if vendor.strip():
        conds.append(Device.vendor == vendor.strip())
    if driver.strip():
        conds.append(Device.device_type == driver.strip())
    if protocol.strip():
        conds.append(Device.protocol == protocol.strip())
    if active in ("1", "0"):
        conds.append(Device.enabled == (active == "1"))
    if site.strip():
        conds.append(Device.site == site.strip())
    if site_role == "_none":
        conds.append(Device.site_role == "")
    elif site_role.strip():
        conds.append(Device.site_role == normalize_site_role(site_role))
    db = SessionLocal()
    try:
        total = db.scalar(select(func.count()).select_from(Device).where(*conds)) or 0
        devices = db.scalars(
            select(Device)
            .where(*conds)
            .order_by(order, Device.name)
            .offset((page - 1) * PER_PAGE)
            .limit(PER_PAGE)
        ).all()
        driver_opts = [
            d
            for d in db.scalars(
                select(Device.device_type).distinct().order_by(Device.device_type)
            ).all()
            if d
        ]
        sites = [
            s
            for s in db.scalars(
                select(Device.site).distinct().order_by(Device.site)
            ).all()
            if s
        ]
    finally:
        db.close()
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render(
        request,
        "devices.html",
        devices=devices,
        q=q,
        vendor=vendor,
        driver=driver,
        protocol=protocol,
        active=active,
        site=site,
        site_role=site_role,
        page=page,
        pages=pages,
        total=total,
        vendors=list(VENDORS.keys()),
        drivers=driver_opts,
        site_roles=SITE_ROLES,
        sites=sites,
        sort=sort,
        dir=dir,
    )


@app.get("/devices/new", response_class=HTMLResponse)
def device_new(request: Request):
    require_role(request, MANAGE_ROLES)
    return render(request, "device_form.html", device=None, vendors=VENDORS, site_roles=SITE_ROLES)


@app.get("/devices/{device_id}/edit", response_class=HTMLResponse)
def device_edit(request: Request, device_id: int):
    require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
    finally:
        db.close()
    if not device:
        raise HTTPException(404, "device nao encontrado")
    return render(request, "device_form.html", device=device, vendors=VENDORS, site_roles=SITE_ROLES)


@app.post("/devices/save")
def device_save(
    request: Request,
    device_id: str = Form(""),
    name: str = Form(...),
    ip: str = Form(...),
    vendor: str = Form(""),
    model: str = Form(""),
    device_type: str = Form(""),
    protocol: str = Form("ssh"),
    port: int = Form(22),
    username: str = Form(""),
    password: str = Form(""),
    enable_password: str = Form(""),
    tags: str = Form(""),
    site: str = Form(""),
    site_role: str = Form(""),
    enabled: str = Form(""),
):
    user = require_role(request, MANAGE_ROLES)
    lang = user.get("language") or "pt"
    name = name.strip()
    ip = ip.strip()
    protocol = protocol.strip().lower()
    if not name or not ip:
        raise HTTPException(400, translate(lang, "msg.device_required"))
    if protocol not in ("ssh", "telnet"):
        raise HTTPException(400, translate(lang, "msg.protocol_invalid"))
    if not (1 <= int(port) <= 65535):
        raise HTTPException(400, translate(lang, "msg.port_invalid"))
    db = SessionLocal()
    try:
        if device_id:
            device = db.get(Device, int(device_id))
            if not device:
                raise HTTPException(404, "device nao encontrado")
        else:
            device = Device()
            db.add(device)
        # unicidade de IP (e nome) para nao gerar duplicatas no inventario
        dup = db.scalar(
            select(Device).where(Device.ip == ip, Device.id != (device.id or 0))
        )
        if dup:
            raise HTTPException(400, translate(lang, "msg.dup_ip", ip=ip))
        dup_name = db.scalar(
            select(Device).where(Device.name == name, Device.id != (device.id or 0))
        )
        if dup_name:
            raise HTTPException(400, translate(lang, "msg.dup_name", name=name))
        device.name = name
        device.ip = ip
        device.vendor = vendor.strip()
        device.model = model.strip()
        device.device_type = resolve_driver(device.vendor, device.model, device_type.strip())
        device.protocol = protocol.strip().lower()
        device.port = int(port)
        device.username = username.strip()
        if password:
            device.password_enc = encrypt_secret(password)
        if enable_password:
            device.enable_password_enc = encrypt_secret(enable_password)
        device.tags = tags.strip()
        device.site = site.strip()
        device.site_role = normalize_site_role(site_role)
        device.enabled = bool(enabled)
        audit(db, user["name"], "device_save", f"{device.name} ({device.ip})")
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/devices", status_code=303)


@app.post("/devices/test")
def device_test(
    request: Request,
    device_id: str = Form(""),
    ip: str = Form(""),
    vendor: str = Form(""),
    model: str = Form(""),
    device_type: str = Form(""),
    protocol: str = Form("ssh"),
    port: int = Form(22),
    username: str = Form(""),
    password: str = Form(""),
    enable_password: str = Form(""),
):
    """Testa a conexao sem gravar. Usa a credencial global quando vazio."""
    require_role(request, MANAGE_ROLES)
    ip = ip.strip()
    if not ip:
        raise HTTPException(400, "informe o IP")
    db = SessionLocal()
    try:
        base = db.get(Device, int(device_id)) if device_id else None
        s = get_settings(db)
        eff_user = (username.strip() or (base.username if base else "") or s.default_username)
        eff_pwd_enc = (
            encrypt_secret(password)
            if password
            else (base.password_enc if base else "") or s.default_password_enc
        )
        eff_en_enc = (
            encrypt_secret(enable_password)
            if enable_password
            else (base.enable_password_enc if base else "") or s.default_enable_password_enc
        )
    finally:
        db.close()
    dev = {
        "ip": ip,
        "vendor": vendor.strip(),
        "device_type": device_type.strip(),
        "protocol": (protocol or "ssh").strip().lower(),
        "port": int(port),
        "username": eff_user,
        "password_enc": eff_pwd_enc,
        "enable_password_enc": eff_en_enc,
    }
    from .engine import test_connection

    res = test_connection(dev)
    return JSONResponse(res)


@app.post("/devices/{device_id}/delete")
def device_delete(request: Request, device_id: int):
    user = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if device:
            audit(db, user["name"], "device_delete", f"{device.name} ({device.ip})")
            db.delete(device)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/devices", status_code=303)


@app.post("/devices/bulk_edit")
def devices_bulk_edit(
    request: Request,
    scope_q: str = Form(""),
    scope_vendor: str = Form(""),
    scope_driver: str = Form(""),
    scope_protocol: str = Form(""),
    scope_active: str = Form(""),
    scope_site: str = Form(""),
    scope_site_role: str = Form(""),
    port: str = Form(""),
    protocol: str = Form(""),
    device_type: str = Form(""),
    tags: str = Form(""),
    site: str = Form(""),
    site_role: str = Form(""),
    enabled: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    enable_password: str = Form(""),
):
    """Edita em massa os devices que casam com o escopo (filtros da lista)."""
    user = require_role(request, MANAGE_ROLES)
    lang = user.get("language") or "pt"
    conds = []
    if scope_q.strip():
        like = f"%{scope_q.strip()}%"
        conds.append(
            or_(Device.name.ilike(like), Device.ip.ilike(like), Device.tags.ilike(like))
        )
    if scope_vendor.strip():
        conds.append(Device.vendor == scope_vendor.strip())
    if scope_driver.strip():
        conds.append(Device.device_type == scope_driver.strip())
    if scope_protocol.strip():
        conds.append(Device.protocol == scope_protocol.strip())
    if scope_active in ("1", "0"):
        conds.append(Device.enabled == (scope_active == "1"))
    if scope_site.strip():
        conds.append(Device.site == scope_site.strip())
    if scope_site_role == "_none":
        conds.append(Device.site_role == "")
    elif scope_site_role.strip():
        conds.append(Device.site_role == normalize_site_role(scope_site_role))
    if not (
        port.strip()
        or protocol.strip()
        or device_type.strip()
        or tags.strip()
        or site.strip()
        or site_role.strip()
        or enabled != ""
        or username.strip()
        or password
        or enable_password
    ):
        raise HTTPException(400, translate(lang, "msg.bulk_need_field"))
    port_val = None
    if port.strip():
        try:
            port_val = int(port)
        except ValueError:
            raise HTTPException(400, translate(lang, "msg.port_invalid")) from None
        if not (1 <= port_val <= 65535):
            raise HTTPException(400, translate(lang, "msg.port_invalid"))
    proto = protocol.strip().lower()
    if proto and proto not in ("ssh", "telnet"):
        raise HTTPException(400, translate(lang, "msg.protocol_invalid"))
    db = SessionLocal()
    try:
        devs = db.scalars(select(Device).where(*conds)).all()
        n = 0
        for d in devs:
            if port_val is not None:
                d.port = port_val
            if proto:
                d.protocol = proto
            if device_type.strip():
                d.device_type = device_type.strip()
            if tags.strip():
                d.tags = tags.strip()
            if site.strip():
                d.site = site.strip()
            if site_role.strip():
                d.site_role = normalize_site_role(site_role)
            if enabled != "":
                d.enabled = enabled == "1"
            if username.strip():
                d.username = username.strip()
            if password:
                d.password_enc = encrypt_secret(password)
            if enable_password:
                d.enable_password_enc = encrypt_secret(enable_password)
            n += 1
        audit(
            db,
            user["name"],
            "devices_bulk_edit",
            f"scope_vendor={scope_vendor} scope_q={scope_q} scope_driver={scope_driver} "
            f"scope_protocol={scope_protocol} scope_active={scope_active} n={n} "
            f"port={port} protocol={protocol} driver={device_type} tags={tags} "
            f"site={site} site_role={site_role} enabled={enabled} "
            f"username={username} password={'set' if password else '-'} "
            f"enable={'set' if enable_password else '-'}",
        )
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/devices", status_code=303)


CONNECTORS = {"librenms": LibreNMSConnector, "rconfig": RConfigConnector}
# OS que nao sao alvo de push de config (servidores) — ignorados no sync
SYNC_SKIP_OS = {"windows", "linux"}


def _connector_for(db, source: str):
    """Instancia o conector com a conexao configurada (Settings; fallback env)."""
    cfg = integration_config(db).get(source, {})
    return CONNECTORS[source](**cfg)


@app.post("/devices/sync")
def devices_sync(request: Request, source: str = Form("")):
    """Importa/atualiza o inventario a partir de uma fonte externa."""
    user = require_role(request, MANAGE_ROLES)
    lang = user.get("language") or "pt"
    src = source.strip().lower()
    if src not in CONNECTORS:
        raise HTTPException(400, translate(lang, "msg.source_invalid"))
    db = SessionLocal()
    created = updated = 0
    try:
        conn = _connector_for(db, src)
        if not conn.available():
            raise HTTPException(400, translate(lang, "msg.connector_unavailable"))
        rows = conn.list_devices()
        for row in rows:
            ip = (row.get("ip") or "").strip()
            name = (row.get("name") or "").strip()
            if not ip and not name:
                continue
            row_os = str(row.get("os") or "").strip().lower()
            if row_os in SYNC_SKIP_OS:
                continue
            target = None
            ext = str(row.get("external_id") or "").strip()
            if ext:
                target = db.scalar(
                    select(Device).where(Device.source == src, Device.external_id == ext)
                )
            if target is None and ip:
                target = db.scalar(select(Device).where(Device.ip == ip))
            is_new = target is None
            if is_new:
                target = Device()
                db.add(target)
            if name:
                target.name = name
            if ip:
                target.ip = ip
            if row.get("vendor"):
                target.vendor = str(row["vendor"])
            if row.get("model"):
                target.model = str(row["model"])
            if row.get("port"):
                try:
                    target.port = int(row["port"])
                except (TypeError, ValueError):
                    pass
            target.source = src
            if ext:
                target.external_id = ext
            os_name = str(row.get("os") or "").strip()
            if target.vendor and target.model:
                target.device_type = resolve_driver(target.vendor, target.model, "")
            else:
                target.device_type = resolve_os_driver(os_name) or resolve_driver(
                    target.vendor, target.model, ""
                )
            if is_new:
                created += 1
            else:
                updated += 1
        audit(db, user["name"], "devices_sync", f"source={src} created={created} updated={updated}")
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/devices", status_code=303)


@app.get("/devices/template.xlsx")
def device_template(request: Request):
    require_login(request)
    from io import BytesIO

    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.append(
        ["Nome do switch", "IP do switch", "Vendor", "Modelo", "Usuario", "Senha",
         "Senha de enable", "Protocolo", "Porta"]
    )
    ws.append(["SW-CORE-01", "10.0.0.1", "Cisco", "IOS / IOS-XE (Catalyst, ISR)",
               "admin", "senha", "", "ssh", 22])
    buf = BytesIO()
    wb.save(buf)
    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=modelo_devices.xlsx"},
    )


IMPORT_DIR = settings.data_dir / "imports"
IMPORT_DIR.mkdir(parents=True, exist_ok=True)


def _import_path(token: str):
    import re as _re

    if not token or not _re.fullmatch(r"[A-Za-z0-9_-]{10,64}", token):
        return None
    p = (IMPORT_DIR / f"{token}.bin").resolve()
    if p.parent != IMPORT_DIR.resolve():
        return None
    return p if p.exists() else None


def _preview_rows(db, parsed: list[dict]) -> list[dict]:
    """Monta as linhas do preview: driver resolvido e conflitos de IP/nome."""
    rows = []
    for row in parsed:
        existing = db.scalar(select(Device).where(Device.ip == row["ip"]))
        by_name = db.scalar(select(Device).where(Device.name == row["name"]))
        name_conflict = bool(by_name and by_name.ip != row["ip"])
        driver = resolve_driver(
            row["vendor"], row.get("model", ""), row.get("device_type", "")
        )
        rows.append(
            {
                "name": row["name"],
                "ip": row["ip"],
                "vendor": row["vendor"],
                "model": row.get("model", ""),
                "os": row.get("os", ""),
                "driver": driver,
                "protocol": row["protocol"],
                "port": row["port"],
                "username": row["username"],
                "existing": existing is not None,
                "current_name": existing.name if existing else "",
                "name_conflict": name_conflict,
                "conflict_ip": by_name.ip if name_conflict else "",
            }
        )
    return rows


def _render_preview(request, preview, errors, test_results=None):
    return render(
        request,
        "devices_import_preview.html",
        preview=preview,
        errors=errors,
        results=test_results or {},
        created=sum(1 for p in preview if not p["existing"]),
        updated=sum(1 for p in preview if p["existing"]),
        conflicts=sum(1 for p in preview if p.get("name_conflict")),
    )


def _test_parsed(db, parsed: list[dict]) -> dict:
    """Testa conexao de todas as linhas (concorrente). Devolve {idx: resultado}."""
    from concurrent.futures import ThreadPoolExecutor

    from .engine import test_connection

    s = get_settings(db)
    devs = []
    for i, row in enumerate(parsed):
        devs.append(
            (
                i,
                {
                    "ip": row["ip"],
                    "vendor": row["vendor"],
                    "device_type": row.get("device_type", ""),
                    "protocol": row["protocol"],
                    "port": row["port"],
                    "username": row.get("username") or s.default_username,
                    "password_enc": encrypt_secret(row["password"])
                    if row.get("password")
                    else s.default_password_enc,
                    "enable_password_enc": encrypt_secret(row["enable"])
                    if row.get("enable")
                    else s.default_enable_password_enc,
                },
            )
        )
    results: dict[int, dict] = {}
    if not devs:
        return results
    workers = max(1, min(settings.max_workers, len(devs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(test_connection, d): i for i, d in devs}
        for fut in futs:
            idx = futs[fut]
            try:
                results[idx] = fut.result()
            except Exception as e:  # noqa: BLE001
                results[idx] = {"status": "failed", "error": str(e), "driver": ""}
    return results


@app.post("/devices/import")
async def devices_import(request: Request, file: UploadFile = File(...)):
    """Primeira etapa: le a planilha/CSV e mostra um preview (nao grava nada)."""
    require_role(request, MANAGE_ROLES)
    content = await file.read()
    name = file.filename or ""
    parsed, errors = parse_devices(name, content)
    token = secrets.token_urlsafe(18)
    (IMPORT_DIR / f"{token}.bin").write_bytes(content)
    request.session["import_token"] = token
    request.session["import_name"] = name
    db = SessionLocal()
    try:
        preview = _preview_rows(db, parsed)
    finally:
        db.close()
    return _render_preview(request, preview, errors)


@app.post("/devices/import/test")
def devices_import_test(request: Request):
    require_role(request, MANAGE_ROLES)
    token = request.session.get("import_token", "")
    path = _import_path(token)
    if not path:
        raise HTTPException(400, "nenhuma importacao pendente (refaca o upload)")
    parsed, errors = parse_devices(request.session.get("import_name", ""), path.read_bytes())
    db = SessionLocal()
    try:
        preview = _preview_rows(db, parsed)
        results = _test_parsed(db, parsed)
    finally:
        db.close()
    return _render_preview(request, preview, errors, test_results=results)


@app.post("/devices/import/confirm")
def devices_import_confirm(request: Request):
    user = require_role(request, MANAGE_ROLES)
    token = request.session.pop("import_token", "")
    name = request.session.pop("import_name", "")
    path = _import_path(token)
    if not path:
        raise HTTPException(400, "nenhuma importacao pendente (refaca o upload)")
    content = path.read_bytes()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    parsed, errors = parse_devices(name, content)
    db = SessionLocal()
    created = updated = skipped = 0
    try:
        for row in parsed:
            existing = db.scalar(select(Device).where(Device.ip == row["ip"]))
            if not existing:
                # nome ja existe com outro IP: nao cria duplicata de nome
                by_name = db.scalar(select(Device).where(Device.name == row["name"]))
                if by_name is not None:
                    errors.append(
                        f"nome '{row['name']}' ja existe com o IP {by_name.ip}; "
                        f"linha {row['ip']} ignorada"
                    )
                    skipped += 1
                    continue
            target = existing or Device()
            if not existing:
                db.add(target)
            target.name = row["name"]
            target.ip = row["ip"]
            target.vendor = row["vendor"]
            target.model = row.get("model", "")
            target.device_type = resolve_driver(
                row["vendor"], row.get("model", ""), row.get("device_type", "")
            )
            target.protocol = row["protocol"]
            target.port = row["port"]
            target.username = row["username"]
            if row["password"]:
                target.password_enc = encrypt_secret(row["password"])
            if row.get("enable"):
                target.enable_password_enc = encrypt_secret(row["enable"])
            target.tags = row["tags"]
            if existing:
                updated += 1
            else:
                created += 1
        audit(
            db,
            user["name"],
            "devices_import",
            f"created={created} updated={updated} skipped={skipped}",
        )
        db.commit()
    finally:
        db.close()
    db = SessionLocal()
    try:
        devices = db.scalars(select(Device).order_by(Device.name).limit(PER_PAGE)).all()
        total = db.scalar(select(func.count()).select_from(Device)) or 0
    finally:
        db.close()
    lang = user.get("language") or "pt"
    notice = translate(lang, "msg.import_done", c=created, u=updated)
    if skipped:
        notice += translate(lang, "msg.import_skipped", s=skipped)
    return render(
        request,
        "devices.html",
        devices=devices,
        q="",
        page=1,
        pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
        total=total,
        notice=notice + ".",
        import_errors=errors,
        vendors=list(VENDORS.keys()),
        vendor="",
        driver="",
        protocol="",
        active="",
        drivers=[],
    )


# ---------------------------------------------------------------------------
# Snippets
# ---------------------------------------------------------------------------
@app.get("/snippets", response_class=HTMLResponse)
def snippets_list(request: Request, q: str = ""):
    require_login(request)
    conds = []
    if q.strip():
        like = f"%{q.strip()}%"
        conds.append(or_(Snippet.name.ilike(like), Snippet.description.ilike(like)))
    db = SessionLocal()
    try:
        snippets = db.scalars(
            select(Snippet).where(*conds).order_by(Snippet.name)
        ).all()
    finally:
        db.close()
    return render(request, "snippets.html", snippets=snippets, q=q)


@app.post("/snippets/{snippet_id}/duplicate")
def snippet_duplicate(request: Request, snippet_id: int):
    user = require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        src = db.get(Snippet, snippet_id)
        if src:
            db.add(
                Snippet(
                    name=f"{src.name} (copia)",
                    description=src.description,
                    body=src.body,
                    drivers=src.drivers,
                    created_by=user["name"],
                )
            )
            audit(db, user["name"], "snippet_duplicate", src.name)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/snippets", status_code=303)


@app.get("/snippets/new", response_class=HTMLResponse)
def snippet_new(request: Request):
    require_role(request, MANAGE_ROLES)
    return render(request, "snippet_form.html", snippet=None, drivers=all_drivers())


@app.get("/snippets/{snippet_id}/edit", response_class=HTMLResponse)
def snippet_edit(request: Request, snippet_id: int):
    require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        snippet = db.get(Snippet, snippet_id)
    finally:
        db.close()
    if not snippet:
        raise HTTPException(404, translate(_lang(request), "msg.model_not_found"))
    return render(request, "snippet_form.html", snippet=snippet, drivers=all_drivers())


@app.post("/snippets/save")
def snippet_save(
    request: Request,
    snippet_id: str = Form(""),
    name: str = Form(...),
    description: str = Form(""),
    body: str = Form(...),
    drivers: list[str] = Form([]),
):
    user = require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        if snippet_id:
            snippet = db.get(Snippet, int(snippet_id))
        else:
            snippet = Snippet(created_by=user["name"])
            db.add(snippet)
        snippet.name = name.strip()
        snippet.description = description.strip()
        snippet.body = body
        snippet.drivers = ",".join(d.strip() for d in drivers if d.strip())
        audit(db, user["name"], "snippet_save", snippet.name)
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/snippets", status_code=303)


@app.post("/snippets/{snippet_id}/delete")
def snippet_delete(request: Request, snippet_id: int):
    user = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        snippet = db.get(Snippet, snippet_id)
        if snippet:
            audit(db, user["name"], "snippet_delete", snippet.name)
            db.delete(snippet)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/snippets", status_code=303)


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------
RUN_STATUSES = (
    "pending_approval",
    "approved",
    "running",
    "done",
    "partial",
    "failed",
    "rejected",
    "canceled",
)


@app.get("/runs", response_class=HTMLResponse)
def runs_list(request: Request, status: str = "", page: int = 1):
    require_login(request)
    page = max(1, page)
    status = status.strip()
    conds = [Run.status == status] if status in RUN_STATUSES else []
    db = SessionLocal()
    try:
        total = db.scalar(select(func.count()).select_from(Run).where(*conds)) or 0
        runs = db.scalars(
            select(Run)
            .options(selectinload(Run.targets))
            .where(*conds)
            .order_by(Run.id.desc())
            .offset((page - 1) * PER_PAGE)
            .limit(PER_PAGE)
        ).all()
    finally:
        db.close()
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render(
        request,
        "runs.html",
        runs=runs,
        status=status,
        statuses=RUN_STATUSES,
        page=page,
        pages=pages,
        total=total,
    )


@app.get("/runs/new", response_class=HTMLResponse)
def run_new(request: Request):
    user = require_role(request, RUN_ROLES)
    allowed = allowed_site_roles(user["role"])
    db = SessionLocal()
    try:
        snippets = db.scalars(select(Snippet).order_by(Snippet.name)).all()
        devices = [
            d
            for d in db.scalars(
                select(Device).where(Device.enabled == True).order_by(Device.name)  # noqa: E712
            ).all()
            if (d.site_role or "") in allowed
        ]
    finally:
        db.close()
    all_tags = sorted(
        {t.strip() for d in devices for t in (d.tags or "").split(",") if t.strip()},
        key=str.lower,
    )
    return render(
        request,
        "run_form.html",
        snippets=snippets,
        devices=devices,
        tags=all_tags,
        driver_labels=dict(all_drivers()),
        snippet_drivers={
            s.id: ", ".join(
                dict(all_drivers()).get(d, d)
                for d in [x.strip() for x in (s.drivers or "").split(",") if x.strip()]
            )
            or "qualquer driver"
            for s in snippets
        },
    )


@app.post("/runs/create")
def run_create(
    request: Request,
    snippet_ids: list[int] = Form([]),
    commands: str = Form(""),
    device_ids: list[int] = Form([]),
    dry_run: str = Form(""),
    capture_diff: str = Form(""),
):
    user = require_role(request, RUN_ROLES)
    lang = user.get("language") or "pt"
    db = SessionLocal()
    try:
        if not device_ids:
            raise HTTPException(400, translate(lang, "msg.select_device"))
        devices = list(db.scalars(select(Device).where(Device.id.in_(device_ids))).all())
        blocked = [d for d in devices if not can_target(user["role"], d.site_role)]
        if blocked:
            raise HTTPException(400, translate(lang, "msg.out_of_scope", n=len(blocked)))
        snippets = (
            list(
                db.scalars(
                    select(Snippet).where(Snippet.id.in_(snippet_ids)).order_by(Snippet.name)
                ).all()
            )
            if snippet_ids
            else []
        )

        per_device: dict[int, tuple[str, str]] = {}
        unmatched: list[Device] = []

        if snippets:
            by_driver: dict[str, Snippet] = {}
            generic: list[Snippet] = []
            for s in snippets:
                dlist = [x.strip() for x in (s.drivers or "").split(",") if x.strip()]
                if dlist:
                    for d in dlist:
                        by_driver[d] = s
                else:
                    generic.append(s)
            for dev in devices:
                drv = (dev.device_type or "").strip()
                s = by_driver.get(drv) or (generic[0] if generic else None)
                if s is not None:
                    per_device[dev.id] = (s.name, s.body)
                else:
                    unmatched.append(dev)
            if not per_device:
                raise HTTPException(
                    400, translate(lang, "msg.no_model_driver")
                )
            if len(snippets) == 1:
                run_snippet_name = snippets[0].name
                run_commands = snippets[0].body
            else:
                run_snippet_name = "(auto por driver)"
                run_commands = "(comandos por device)"
            matched = [d for d in devices if d.id in per_device]
        else:
            if not commands.strip():
                raise HTTPException(400, translate(lang, "msg.select_model"))
            matched = devices
            run_snippet_name = "(comandos avulsos)"
            run_commands = commands

        run = create_run(
            db,
            snippet_id=snippets[0].id if len(snippets) == 1 else None,
            snippet_name=run_snippet_name,
            commands=run_commands,
            devices=matched,
            dry_run=bool(dry_run),
            require_approval=settings.require_approval,
            requested_by=user["name"],
            per_device=per_device or None,
            # admin auto-aprova (registrado em approved_by); demais aguardam
            auto_approve=(user["role"] == "admin"),
            capture_diff=bool(capture_diff),
        )
        for dev in unmatched:
            db.add(
                RunTarget(
                    run_id=run.id,
                    device_id=dev.id,
                    device_name=dev.name,
                    device_ip=dev.ip,
                    snippet_name="(sem modelo)",
                    status="skipped",
                    error=f"sem modelo para o driver '{dev.device_type or '?'}'",
                )
            )
        audit(db, user["name"], "run_create", f"run={run.id} status={run.status}")
        db.commit()
        run_id = run.id
        should_start = run.status == "approved"
    finally:
        db.close()
    if should_start:
        start_run_async(run_id)
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: int):
    require_login(request)
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if not run:
            raise HTTPException(404, "run nao encontrado")
        targets = db.scalars(
            select(RunTarget).where(RunTarget.run_id == run_id).order_by(RunTarget.id)
        ).all()
    finally:
        db.close()
    counts: dict[str, int] = {}
    for t in targets:
        counts[t.status] = counts.get(t.status, 0) + 1
    return render(request, "run_detail.html", run=run, targets=targets, counts=counts)


def _run_counts(targets) -> dict:
    counts: dict[str, int] = {}
    for t in targets:
        counts[t.status] = counts.get(t.status, 0) + 1
    return counts


@app.get("/api/runs/{run_id}")
def run_status_api(request: Request, run_id: int):
    require_login(request)
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if not run:
            raise HTTPException(404, "run nao encontrado")
        data = {
            "id": run.id,
            "status": run.status,
            "dry_run": run.dry_run,
            "capture_diff": run.capture_diff,
            "counts": _run_counts(run.targets),
            "targets": [
                {
                    "id": t.id,
                    "name": t.device_name,
                    "ip": t.device_ip,
                    "status": t.status,
                    "error": t.error,
                    "output": (t.output or "")[-4000:],
                    "diff": (t.diff or "")[-4000:],
                }
                for t in run.targets
            ],
        }
    finally:
        db.close()
    return JSONResponse(data)


@app.get("/runs/{run_id}/export.csv")
def run_export(request: Request, run_id: int):
    require_login(request)
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if not run:
            raise HTTPException(404, "run nao encontrado")
        targets = db.scalars(
            select(RunTarget).where(RunTarget.run_id == run_id).order_by(RunTarget.id)
        ).all()
    finally:
        db.close()
    buf = StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(
        ["run", "status_run", "device", "ip", "modelo", "status", "erro", "inicio", "fim"]
    )
    for t in targets:
        writer.writerow(
            [
                run.id,
                run.status,
                t.device_name,
                t.device_ip,
                t.snippet_name,
                t.status,
                t.error,
                t.started_at.strftime("%Y-%m-%d %H:%M:%S") if t.started_at else "",
                t.finished_at.strftime("%Y-%m-%d %H:%M:%S") if t.finished_at else "",
            ]
        )
    data = "\ufeff" + buf.getvalue()
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=execucao-{run_id}.csv"},
    )


@app.post("/runs/{run_id}/approve")
def run_approve(request: Request, run_id: int):
    user = require_role(request, {"admin", "approver"})
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run and run.status == "pending_approval":
            run.status = "approved"
            run.approved_by = user["name"]
            run.approved_at = utcnow()
            audit(db, user["name"], "run_approve", f"run={run.id}")
            db.commit()
            notify(
                {
                    "event": "run_approved",
                    "run_id": run.id,
                    "by": user["name"],
                    "snippet": run.snippet_name,
                }
            )
            start_run_async(run.id)
    finally:
        db.close()
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.post("/runs/{run_id}/reject")
def run_reject(request: Request, run_id: int, reason: str = Form("")):
    user = require_role(request, {"admin", "approver"})
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run and run.status == "pending_approval":
            run.status = "rejected"
            run.reject_reason = reason
            run.approved_by = user["name"]
            audit(db, user["name"], "run_reject", f"run={run.id} motivo={reason}")
            db.commit()
            notify(
                {
                    "event": "run_rejected",
                    "run_id": run.id,
                    "by": user["name"],
                    "reason": reason,
                }
            )
    finally:
        db.close()
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.post("/runs/{run_id}/cancel")
def run_cancel(request: Request, run_id: int):
    user = require_role(request, RUN_ROLES | APPROVER_ROLES)
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run and run.status == "pending_approval":
            run.status = "canceled"
            run.approved_by = user["name"]
            run.finished_at = utcnow()
            audit(db, user["name"], "run_cancel", f"run={run.id}")
            db.commit()
    finally:
        db.close()
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.post("/runs/{run_id}/retry")
def run_retry(request: Request, run_id: int):
    user = require_role(request, RUN_ROLES)
    lang = user.get("language") or "pt"
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run and run.status in ("failed", "partial", "done", "canceled"):
            dev_ids = [t.device_id for t in run.targets if t.device_id]
            devs = (
                list(db.scalars(select(Device).where(Device.id.in_(dev_ids))).all())
                if dev_ids
                else []
            )
            if any(not can_target(user["role"], d.site_role) for d in devs):
                raise HTTPException(403, translate(lang, "msg.out_of_scope", n=1))
            pending = 0
            for t in run.targets:
                if t.status == "failed":
                    t.status = "pending"
                    t.output = ""
                    t.error = ""
                    t.started_at = None
                    t.finished_at = None
                    pending += 1
            if pending:
                run.status = "approved"
                run.started_at = None
                run.finished_at = None
                audit(db, user["name"], "run_retry", f"run={run.id} alvos={pending}")
                db.commit()
                start_run_async(run.id)
    finally:
        db.close()
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.post("/runs/{run_id}/rerun")
def run_rerun(request: Request, run_id: int):
    """Reexecuta TODOS os alvos validos do run (nao apenas os que falharam)."""
    user = require_role(request, RUN_ROLES)
    lang = user.get("language") or "pt"
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run and run.status in ("failed", "partial", "done", "canceled"):
            dev_ids = [t.device_id for t in run.targets if t.device_id]
            devs = (
                list(db.scalars(select(Device).where(Device.id.in_(dev_ids))).all())
                if dev_ids
                else []
            )
            if any(not can_target(user["role"], d.site_role) for d in devs):
                raise HTTPException(403, translate(lang, "msg.out_of_scope", n=1))
            n = 0
            for t in run.targets:
                if t.commands:  # ignora alvos sem comando (sem snippet)
                    t.status = "pending"
                    t.output = ""
                    t.error = ""
                    t.diff = ""
                    t.started_at = None
                    t.finished_at = None
                    n += 1
            if n:
                run.status = "approved"
                run.started_at = None
                run.finished_at = None
                audit(db, user["name"], "run_rerun", f"run={run.id} alvos={n}")
                db.commit()
                start_run_async(run.id)
    finally:
        db.close()
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.post("/approvals/approve-all")
def approvals_approve_all(request: Request):
    user = require_role(request, {"admin", "approver"})
    db = SessionLocal()
    try:
        pending = db.scalars(
            select(Run).where(Run.status == "pending_approval").order_by(Run.id)
        ).all()
        started: list[int] = []
        for run in pending:
            run.status = "approved"
            run.approved_by = user["name"]
            run.approved_at = utcnow()
            started.append(run.id)
        if started:
            audit(db, user["name"], "approve_all", f"runs={started}")
            db.commit()
            for rid in started:
                start_run_async(rid)
    finally:
        db.close()
    return RedirectResponse("/approvals", status_code=303)


@app.get("/healthz")
def healthz():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    finally:
        db.close()
    return JSONResponse({"status": "ok", "app": settings.app_name})


# ---------------------------------------------------------------------------
# Backups (coleta + versionamento + diff)
# ---------------------------------------------------------------------------
BACKUP_STALE_HOURS = 24


@app.get("/backups", response_class=HTMLResponse)
def backups_list(request: Request):
    require_login(request)
    db = SessionLocal()
    try:
        devices = db.scalars(select(Device).order_by(Device.name)).all()
        rows = db.scalars(
            select(Backup).order_by(Backup.id.desc()).limit(5000)
        ).all()
    finally:
        db.close()
    last: dict[int, Backup] = {}
    for b in rows:
        if b.device_id and b.device_id not in last:
            last[b.device_id] = b
    now = utcnow()
    items = []
    counts = {"ok": 0, "failed": 0, "stale": 0, "never": 0}
    for d in devices:
        b = last.get(d.id)
        if b is None:
            state = "never"
        elif b.status != "ok":
            state = "failed"
        elif b.created_at and (now - b.created_at) > timedelta(hours=BACKUP_STALE_HOURS):
            state = "stale"
        else:
            state = "ok"
        counts[state] += 1
        items.append({"device": d, "last": b, "state": state})
    return render(
        request,
        "backups.html",
        items=items,
        counts=counts,
        stale_hours=BACKUP_STALE_HOURS,
    )


@app.post("/backups/collect-all")
def backups_collect_all(request: Request):
    user = require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        audit(db, user["name"], "backup_all", "coleta em lote")
        db.commit()
    finally:
        db.close()
    start_backup_all_async("manual", user["name"])
    return RedirectResponse("/backups", status_code=303)


@app.post("/backups/collect/{device_id}")
def backups_collect(request: Request, device_id: int):
    user = require_role(request, MANAGE_ROLES)
    collect_backup(device_id, "manual", user["name"])
    return RedirectResponse(f"/backups/{device_id}", status_code=303)


@app.get("/backups/{device_id}", response_class=HTMLResponse)
def backup_detail(request: Request, device_id: int):
    require_login(request)
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if not device:
            raise HTTPException(404, "device nao encontrado")
        history = db.scalars(
            select(Backup)
            .where(Backup.device_id == device_id)
            .order_by(Backup.id.desc())
            .limit(100)
        ).all()
    finally:
        db.close()
    from . import backup as bk

    versions = bk.versions(device.name)
    diff = bk.diff(device.name)
    return render(
        request,
        "backup_detail.html",
        device=device,
        history=history,
        versions=versions,
        diff=diff,
    )


@app.get("/approvals", response_class=HTMLResponse)
def approvals(request: Request):
    require_login(request)
    db = SessionLocal()
    try:
        pending = db.scalars(
            select(Run)
            .options(selectinload(Run.targets))
            .where(Run.status == "pending_approval")
            .order_by(Run.id)
        ).all()
    finally:
        db.close()
    return render(request, "approvals.html", pending=pending)


def _audit_filters(user: str, action: str, date_from: str, date_to: str) -> list:
    conds = []
    if user.strip():
        conds.append(AuditLog.user.ilike(f"%{user.strip()}%"))
    if action.strip():
        conds.append(AuditLog.action.ilike(f"%{action.strip()}%"))
    if date_from:
        try:
            conds.append(AuditLog.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.fromisoformat(date_to)
            if len(date_to.strip()) <= 10:
                end = end + timedelta(days=1)
            conds.append(AuditLog.created_at < end)
        except ValueError:
            pass
    return conds


@app.get("/audit", response_class=HTMLResponse)
def audit_view(
    request: Request,
    user: str = "",
    action: str = "",
    date_from: str = "",
    date_to: str = "",
    page: int = 1,
):
    require_role(request, AUDIT_ROLES)
    page = max(1, page)
    conds = _audit_filters(user, action, date_from, date_to)
    db = SessionLocal()
    try:
        total = db.scalar(select(func.count()).select_from(AuditLog).where(*conds)) or 0
        rows = db.scalars(
            select(AuditLog)
            .where(*conds)
            .order_by(AuditLog.id.desc())
            .offset((page - 1) * PER_PAGE)
            .limit(PER_PAGE)
        ).all()
    finally:
        db.close()
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render(
        request,
        "audit.html",
        rows=rows,
        filters={"user": user, "action": action, "date_from": date_from, "date_to": date_to},
        page=page,
        pages=pages,
        total=total,
    )


@app.get("/audit/export.csv")
def audit_export(
    request: Request,
    user: str = "",
    action: str = "",
    date_from: str = "",
    date_to: str = "",
):
    require_role(request, AUDIT_ROLES)
    conds = _audit_filters(user, action, date_from, date_to)
    db = SessionLocal()
    try:
        rows = db.scalars(
            select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).limit(50_000)
        ).all()
    finally:
        db.close()
    buf = StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["id", "data_hora", "usuario", "acao", "detalhe"])
    for r in rows:
        writer.writerow(
            [
                r.id,
                r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
                r.user,
                r.action,
                r.detail,
            ]
        )
    data = "\ufeff" + buf.getvalue()
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=auditoria.csv"},
    )


# ---------------------------------------------------------------------------
# Usuarios
# ---------------------------------------------------------------------------
@app.get("/users", response_class=HTMLResponse)
def users_list(request: Request):
    require_role(request, {"admin"})
    db = SessionLocal()
    try:
        users = db.scalars(select(User).order_by(User.username)).all()
    finally:
        db.close()
    return render(request, "users.html", users=users)


@app.get("/users/new", response_class=HTMLResponse)
def user_new(request: Request):
    require_role(request, {"admin"})
    return render(request, "user_form.html", edit_user=None)


@app.get("/users/{user_id}/edit", response_class=HTMLResponse)
def user_edit(request: Request, user_id: int):
    require_role(request, {"admin"})
    db = SessionLocal()
    try:
        edit_user = db.get(User, user_id)
    finally:
        db.close()
    if not edit_user:
        raise HTTPException(404, "usuario nao encontrado")
    return render(request, "user_form.html", edit_user=edit_user)


@app.post("/users/save")
def user_save(
    request: Request,
    user_id: str = Form(""),
    username: str = Form(...),
    role: str = Form("operator_basic"),
    password: str = Form(""),
    active: str = Form(""),
):
    actor = require_role(request, {"admin"})
    if role not in ROLES:
        raise HTTPException(400, "role invalida")
    if password and len(password) < MIN_PASSWORD_LEN:
        raise HTTPException(400, f"senha muito curta (min. {MIN_PASSWORD_LEN})")
    db = SessionLocal()
    try:
        if user_id:
            u = db.get(User, int(user_id))
            if not u:
                raise HTTPException(404, "usuario nao encontrado")
        else:
            if not password:
                raise HTTPException(400, "senha obrigatoria para novo usuario")
            if db.scalar(select(User).where(User.username == username)):
                raise HTTPException(400, "usuario ja existe")
            u = User(username=username.strip())
            db.add(u)
        # nao deixar remover o ultimo admin ativo
        if u.role == "admin" and (role != "admin" or not active):
            admins = db.scalar(
                select(func.count()).select_from(User).where(User.role == "admin", User.active)
            )
            if admins and admins <= 1:
                raise HTTPException(400, "nao e possivel remover o ultimo admin")
        u.username = username.strip()
        u.role = role
        u.active = bool(active)
        if password:
            u.password_hash = hash_password(password)
        audit(db, actor["name"], "user_save", f"{u.username} role={role} active={u.active}")
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/delete")
def user_delete(request: Request, user_id: int):
    actor = require_role(request, {"admin"})
    if actor["name"] == (request.session.get("user") or {}).get("name") and user_id == 0:
        raise HTTPException(400, "invalido")
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            raise HTTPException(404, "usuario nao encontrado")
        if u.username == actor["name"]:
            raise HTTPException(400, "nao e possivel remover o proprio usuario")
        if u.role == "admin":
            admins = db.scalar(
                select(func.count()).select_from(User).where(User.role == "admin", User.active)
            )
            if admins and admins <= 1:
                raise HTTPException(400, "nao e possivel remover o ultimo admin")
        audit(db, actor["name"], "user_delete", u.username)
        db.delete(u)
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/users", status_code=303)


# ---------------------------------------------------------------------------
# Configuracoes (branding / logos / mensagem)
# ---------------------------------------------------------------------------
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    require_role(request, {"admin"})
    db = SessionLocal()
    try:
        s = get_settings(db)
        data = {
            "brand_login": s.brand_login,
            "brand_app": s.brand_app,
            "login_message": s.login_message,
            "logo_login": s.logo_login,
            "logo_header": s.logo_header,
            "default_username": s.default_username,
            "has_default_password": bool(s.default_password_enc),
            "has_default_enable": bool(s.default_enable_password_enc),
            "notify_webhook_url": s.notify_webhook_url,
            "librenms_url": s.librenms_url,
            "has_librenms_token": bool(s.librenms_token_enc),
            "librenms_verify_tls": s.librenms_verify_tls,
            "rconfig_url": s.rconfig_url,
            "has_rconfig_token": bool(s.rconfig_token_enc),
            "rconfig_verify_tls": s.rconfig_verify_tls,
        }
    finally:
        db.close()
    return render(request, "settings.html", settings=data, notice=None)


@app.post("/settings/notify")
def settings_notify(request: Request, notify_webhook_url: str = Form("")):
    """Webhook (Teams/Slack/generico) para avisos de execucao/aprovacao."""
    actor = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        s = get_settings(db)
        s.notify_webhook_url = notify_webhook_url.strip()
        audit(db, actor["name"], "settings_notify", s.notify_webhook_url or "(vazio)")
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/credentials")
def settings_credentials(
    request: Request,
    default_username: str = Form(""),
    default_password: str = Form(""),
    default_enable_password: str = Form(""),
    clear_password: str = Form(""),
    clear_enable: str = Form(""),
):
    """Credencial padrao (TACACS/AAA) usada por devices sem credencial propria."""
    actor = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        s = get_settings(db)
        s.default_username = default_username.strip()
        if clear_password:
            s.default_password_enc = ""
        elif default_password:
            s.default_password_enc = encrypt_secret(default_password)
        if clear_enable:
            s.default_enable_password_enc = ""
        elif default_enable_password:
            s.default_enable_password_enc = encrypt_secret(default_enable_password)
        audit(db, actor["name"], "settings_credentials", s.default_username or "(vazio)")
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/integrations/{source}")
def settings_integration(
    request: Request,
    source: str,
    url: str = Form(""),
    token: str = Form(""),
    verify: str = Form(""),
    clear_token: str = Form(""),
):
    """Conexao de API (LibreNMS/rConfig). Token vazio = mantem o atual."""
    actor = require_role(request, {"admin"})
    if source not in CONNECTORS:
        raise HTTPException(400, "integracao invalida")
    db = SessionLocal()
    try:
        s = get_settings(db)
        setattr(s, f"{source}_url", url.strip())
        if clear_token:
            setattr(s, f"{source}_token_enc", "")
        elif token:
            setattr(s, f"{source}_token_enc", encrypt_secret(token))
        setattr(s, f"{source}_verify_tls", verify == "1")
        audit(db, actor["name"], "settings_integration", f"{source} url={url.strip() or '(vazio)'}")
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/integrations/{source}/test")
def settings_integration_test(
    request: Request,
    source: str,
    url: str = Form(""),
    token: str = Form(""),
    verify: str = Form("0"),
):
    """Testa a conexao com os valores informados (ou os salvos, se em branco)."""
    require_role(request, {"admin"})
    if source not in CONNECTORS:
        raise HTTPException(400, "integracao invalida")
    db = SessionLocal()
    try:
        stored = integration_config(db).get(source, {})
    finally:
        db.close()
    base = (url.strip() or stored.get("base") or "").rstrip("/")
    auth = token or stored.get("token") or ""
    conn = CONNECTORS[source](base=base, token=auth, verify=(verify == "1"))
    if not conn.available():
        return JSONResponse({"status": "failed", "error": "URL/token nao configurados"})
    try:
        return JSONResponse({"status": "success", "message": conn.ping()})
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"status": "failed", "error": str(e)[:300]})


@app.post("/settings")
def settings_save(
    request: Request,
    brand_login: str = Form(""),
    brand_app: str = Form(""),
    login_message: str = Form(""),
):
    actor = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        s = get_settings(db)
        s.brand_login = brand_login.strip()
        s.brand_app = brand_app.strip()
        s.login_message = login_message.strip()
        audit(db, actor["name"], "settings_save", "branding")
        db.commit()
    finally:
        db.close()
    invalidate_branding()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/logo/{kind}")
async def settings_logo(request: Request, kind: str, file: UploadFile = File(...)):
    actor = require_role(request, {"admin"})
    lang = actor.get("language") or "pt"
    if kind not in ("login", "header"):
        raise HTTPException(400, "tipo invalido")
    content = await file.read()
    if len(content) > 2_000_000:
        raise HTTPException(400, translate(lang, "msg.image_too_big"))
    try:
        name = save_media(file.filename or "logo.png", content)
    except ValueError:
        raise HTTPException(400, translate(lang, "msg.image_invalid")) from None
    db = SessionLocal()
    try:
        s = get_settings(db)
        if kind == "login":
            s.logo_login = name
        else:
            s.logo_header = name
        audit(db, actor["name"], "settings_logo", f"{kind}={name}")
        db.commit()
    finally:
        db.close()
    invalidate_branding()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/logo/{kind}/reset")
def settings_logo_reset(request: Request, kind: str):
    actor = require_role(request, {"admin"})
    if kind not in ("login", "header"):
        raise HTTPException(400, "tipo invalido")
    db = SessionLocal()
    try:
        s = get_settings(db)
        if kind == "login":
            s.logo_login = ""
        else:
            s.logo_header = ""
        audit(db, actor["name"], "settings_logo_reset", kind)
        db.commit()
    finally:
        db.close()
    invalidate_branding()
    return RedirectResponse("/settings", status_code=303)


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------
@app.get("/schedules", response_class=HTMLResponse)
def schedules_list(request: Request):
    require_login(request)
    db = SessionLocal()
    try:
        schedules = db.scalars(select(Schedule).order_by(Schedule.name)).all()
    finally:
        db.close()
    return render(request, "schedules.html", schedules=schedules)


@app.get("/schedules/new", response_class=HTMLResponse)
def schedule_new(request: Request):
    require_role(request, RUN_ROLES)
    db = SessionLocal()
    try:
        snippets = db.scalars(select(Snippet).order_by(Snippet.name)).all()
        devices = db.scalars(select(Device).order_by(Device.name)).all()
    finally:
        db.close()
    return render(request, "schedule_form.html", schedule=None, snippets=snippets, devices=devices)


@app.get("/schedules/{schedule_id}/edit", response_class=HTMLResponse)
def schedule_edit(request: Request, schedule_id: int):
    require_role(request, RUN_ROLES)
    db = SessionLocal()
    try:
        schedule = db.get(Schedule, schedule_id)
        snippets = db.scalars(select(Snippet).order_by(Snippet.name)).all()
        devices = db.scalars(select(Device).order_by(Device.name)).all()
    finally:
        db.close()
    if not schedule:
        raise HTTPException(404, "agenda nao encontrada")
    selected = json.loads(schedule.device_ids or "[]")
    return render(
        request,
        "schedule_form.html",
        schedule=schedule,
        snippets=snippets,
        devices=devices,
        selected=selected,
    )


@app.post("/schedules/save")
def schedule_save(
    request: Request,
    schedule_id: str = Form(""),
    name: str = Form(...),
    snippet_id: str = Form(""),
    commands: str = Form(""),
    device_ids: list[int] = Form([]),
    mode: str = Form("cron"),
    cron: str = Form(""),
    run_at: str = Form(""),
    dry_run: str = Form(""),
    require_approval: str = Form(""),
    enabled: str = Form(""),
):
    user = require_role(request, RUN_ROLES)
    lang = user.get("language") or "pt"
    mode = mode if mode in ("cron", "once") else "cron"
    cron = cron.strip()
    if mode == "cron" and (not cron or not croniter.is_valid(cron)):
        raise HTTPException(400, "expressao cron invalida")
    run_at_dt = None
    if run_at:
        try:
            run_at_dt = datetime.fromisoformat(run_at)
        except ValueError:
            raise HTTPException(400, "data/hora invalida") from None
    db = SessionLocal()
    try:
        if device_ids:
            devs = list(db.scalars(select(Device).where(Device.id.in_(device_ids))).all())
            blocked = [d for d in devs if not can_target(user["role"], d.site_role)]
            if blocked:
                raise HTTPException(400, translate(lang, "msg.out_of_scope", n=len(blocked)))
        snippet = db.get(Snippet, int(snippet_id)) if snippet_id else None
        body = snippet.body if snippet else commands
        if schedule_id:
            schedule = db.get(Schedule, int(schedule_id))
        else:
            schedule = Schedule(created_by=user["name"])
            db.add(schedule)
        schedule.name = name.strip()
        schedule.snippet_id = snippet.id if snippet else None
        schedule.commands = body
        schedule.device_ids = json.dumps(device_ids)
        schedule.mode = mode
        schedule.cron = cron
        schedule.run_at = run_at_dt
        schedule.dry_run = bool(dry_run)
        schedule.require_approval = bool(require_approval)
        schedule.enabled = bool(enabled)
        schedule_next(schedule)
        audit(db, user["name"], "schedule_save", schedule.name)
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/schedules", status_code=303)


@app.post("/schedules/{schedule_id}/toggle")
def schedule_toggle(request: Request, schedule_id: int):
    require_role(request, RUN_ROLES)
    db = SessionLocal()
    try:
        schedule = db.get(Schedule, schedule_id)
        if schedule:
            schedule.enabled = not schedule.enabled
            if schedule.enabled:
                schedule_next(schedule)
            audit(db, request.session["user"]["name"], "schedule_toggle", f"{schedule.id}")
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/schedules", status_code=303)


@app.post("/schedules/{schedule_id}/delete")
def schedule_delete(request: Request, schedule_id: int):
    user = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        schedule = db.get(Schedule, schedule_id)
        if schedule:
            audit(db, user["name"], "schedule_delete", schedule.name)
            db.delete(schedule)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/schedules", status_code=303)


# ---------------------------------------------------------------------------
# Conformidade (golden config) e drift
# ---------------------------------------------------------------------------
def _policy_target_label(policy: Policy) -> str:
    parts = []
    if policy.vendor:
        parts.append(f"vendor={policy.vendor}")
    if policy.driver:
        parts.append(f"driver={policy.driver}")
    if policy.tag:
        parts.append(f"tag={policy.tag}")
    try:
        n = len(json.loads(policy.device_ids or "[]"))
    except (ValueError, TypeError):
        n = 0
    if n:
        parts.append(f"{n} device(s)")
    return " · ".join(parts) or "-"


def _findings(raw: str) -> list:
    try:
        data = json.loads(raw or "[]")
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


@app.get("/compliance", response_class=HTMLResponse)
def compliance_list(request: Request):
    require_login(request)
    db = SessionLocal()
    try:
        policies = db.scalars(select(Policy).order_by(Policy.name)).all()
        items = []
        for p in policies:
            last = db.scalar(
                select(ComplianceRun)
                .where(ComplianceRun.policy_id == p.id)
                .order_by(ComplianceRun.id.desc())
                .limit(1)
            )
            items.append(
                {
                    "policy": p,
                    "rule_count": len(p.rules),
                    "last": last,
                    "target_label": _policy_target_label(p),
                }
            )
        runs = db.scalars(
            select(ComplianceRun).order_by(ComplianceRun.id.desc()).limit(30)
        ).all()
    finally:
        db.close()
    return render(
        request,
        "compliance.html",
        policies=items,
        runs=runs,
        notice=request.query_params.get("notice", ""),
    )


@app.get("/compliance/policies/new", response_class=HTMLResponse)
def policy_new(request: Request):
    require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        devices = db.scalars(select(Device).order_by(Device.name)).all()
    finally:
        db.close()
    return render(
        request,
        "policy_form.html",
        policy=None,
        vendors=list(VENDORS.keys()),
        drivers=all_drivers(),
        devices=devices,
        selected_ids=[],
    )


@app.get("/compliance/policies/{policy_id}/edit", response_class=HTMLResponse)
def policy_edit(request: Request, policy_id: int):
    require_role(request, MANAGE_ROLES)
    db = SessionLocal()
    try:
        policy = db.scalar(
            select(Policy)
            .options(selectinload(Policy.rules))
            .where(Policy.id == policy_id)
        )
        if not policy:
            raise HTTPException(404, "politica nao encontrada")
        devices = db.scalars(select(Device).order_by(Device.name)).all()
        try:
            selected_ids = [int(x) for x in json.loads(policy.device_ids or "[]")]
        except (ValueError, TypeError):
            selected_ids = []
    finally:
        db.close()
    return render(
        request,
        "policy_form.html",
        policy=policy,
        vendors=list(VENDORS.keys()),
        drivers=all_drivers(),
        devices=devices,
        selected_ids=selected_ids,
    )


@app.post("/compliance/policies/save")
async def policy_save(request: Request):
    user = require_role(request, MANAGE_ROLES)
    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "nome obrigatorio")
    db = SessionLocal()
    try:
        pid = (form.get("policy_id") or "").strip()
        policy = db.get(Policy, int(pid)) if pid.isdigit() else None
        if pid and not policy:
            raise HTTPException(404, "politica nao encontrada")
        if policy is None:
            policy = Policy(created_by=user["name"])
            db.add(policy)
        policy.name = name
        policy.description = (form.get("description") or "").strip()
        policy.vendor = (form.get("vendor") or "").strip()
        policy.driver = (form.get("driver") or "").strip()
        policy.tag = (form.get("tag") or "").strip()
        policy.enabled = (form.get("enabled") or "1") == "1"
        policy.device_ids = json.dumps(
            [int(x) for x in form.getlist("device_ids") if str(x).isdigit()]
        )
        policy.rules.clear()
        kinds = form.getlist("rule_kind")
        patterns = form.getlist("rule_pattern")
        severities = form.getlist("rule_severity")
        cases = form.getlist("rule_case")
        descs = form.getlist("rule_description")
        for i, pat in enumerate(patterns):
            pat = (pat or "").strip()
            if not pat:
                continue
            kind = kinds[i] if i < len(kinds) else "require"
            severity = severities[i] if i < len(severities) else "error"
            policy.rules.append(
                PolicyRule(
                    kind=kind if kind in ("require", "forbid", "regex") else "require",
                    pattern=pat,
                    severity=severity if severity in ("error", "warn") else "error",
                    case_sensitive=(cases[i] if i < len(cases) else "0") == "1",
                    description=(descs[i] if i < len(descs) else "").strip(),
                )
            )
        audit(db, user["name"], "policy_save", policy.name)
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/compliance", status_code=303)


@app.post("/compliance/policies/{policy_id}/run")
def policy_run(request: Request, policy_id: int):
    user = require_role(request, MANAGE_ROLES)
    try:
        run_id = start_policy_async(policy_id, user["name"])
    except ValueError:
        raise HTTPException(404, "politica nao encontrada")
    return RedirectResponse(f"/compliance/runs/{run_id}", status_code=303)


@app.post("/compliance/policies/{policy_id}/delete")
def policy_delete(request: Request, policy_id: int):
    user = require_role(request, {"admin"})
    db = SessionLocal()
    try:
        policy = db.get(Policy, policy_id)
        if policy:
            audit(db, user["name"], "policy_delete", policy.name)
            db.delete(policy)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/compliance", status_code=303)


@app.get("/compliance/runs", response_class=HTMLResponse)
def compliance_runs_list(request: Request):
    require_login(request)
    db = SessionLocal()
    try:
        runs = db.scalars(
            select(ComplianceRun).order_by(ComplianceRun.id.desc()).limit(200)
        ).all()
    finally:
        db.close()
    return render(request, "compliance_runs.html", runs=runs)


@app.get("/compliance/runs/{run_id}", response_class=HTMLResponse)
def compliance_run_detail(request: Request, run_id: int):
    require_login(request)
    db = SessionLocal()
    try:
        run = db.get(ComplianceRun, run_id)
        if not run:
            raise HTTPException(404, "execucao nao encontrada")
        rows = db.scalars(
            select(ComplianceResult)
            .where(ComplianceResult.run_id == run_id)
            .order_by(ComplianceResult.device_name)
        ).all()
        results = [
            {
                "id": r.id,
                "device_id": r.device_id,
                "device_name": r.device_name,
                "device_ip": r.device_ip,
                "status": r.status,
                "changed": r.changed,
                "message": r.message,
                "findings": _findings(r.findings),
            }
            for r in rows
        ]
    finally:
        db.close()
    return render(request, "compliance_run.html", run=run, results=results)


@app.get("/compliance/device/{device_id}", response_class=HTMLResponse)
def compliance_device(request: Request, device_id: int):
    require_login(request)
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if not device:
            raise HTTPException(404, "device nao encontrado")
        rows = db.scalars(
            select(ComplianceResult)
            .where(ComplianceResult.device_id == device_id)
            .order_by(ComplianceResult.id.desc())
            .limit(50)
        ).all()
        results = [
            {
                "id": r.id,
                "run_id": r.run_id,
                "status": r.status,
                "changed": r.changed,
                "message": r.message,
                "created_at": r.created_at,
                "findings": _findings(r.findings),
            }
            for r in rows
        ]
    finally:
        db.close()
    from . import backup as bk

    versions = bk.versions(device.name)
    diff = bk.diff(device.name)
    return render(
        request,
        "compliance_device.html",
        device=device,
        results=results,
        versions=versions,
        diff=diff,
    )
