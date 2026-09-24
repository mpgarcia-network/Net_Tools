import json
import logging
import threading
from datetime import datetime
from urllib import request as urlrequest

from croniter import croniter
from sqlalchemy import select

from .config import settings
from .db import SessionLocal, utcnow
from .engine import run_batch
from .models import AuditLog, Backup, Device, Run, RunTarget, Schedule, Setting, User

log = logging.getLogger("app.service")

# Locks por device: evita dois runs simultaneos aplicando no mesmo equipamento.
_DEVICE_LOCKS: set[int] = set()
_DEVICE_LOCKS_LOCK = threading.Lock()


def _try_lock_devices(device_ids: list[int]) -> set[int]:
    got: set[int] = set()
    with _DEVICE_LOCKS_LOCK:
        for did in device_ids:
            if did not in _DEVICE_LOCKS:
                _DEVICE_LOCKS.add(did)
                got.add(did)
    return got


def _unlock_devices(device_ids) -> None:
    with _DEVICE_LOCKS_LOCK:
        for did in device_ids:
            _DEVICE_LOCKS.discard(did)


def audit(db, user: str, action: str, detail: str) -> None:
    db.add(AuditLog(user=user, action=action, detail=detail, created_at=utcnow()))


# ---------------------------------------------------------------------------
# Notificacoes (webhook configuravel em Settings)
# ---------------------------------------------------------------------------
def _post_json(url: str, payload: dict) -> None:
    try:
        data = json.dumps(payload).encode()
        req = urlrequest.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        urlrequest.urlopen(req, timeout=10).read()
    except Exception as e:  # noqa: BLE001
        log.warning("webhook falhou: %s", e)


def notify(payload: dict) -> None:
    """Dispara webhook (se configurado) + e-mail (se SMTP configurado).

    O e-mail e' roteado conforme ``payload['event']``:
    - run_finished / run_approved / run_rejected -> para o solicitante (e admin).
    - run_pending_approval -> para aprovadores + admin.
    """
    s = SessionLocal()
    try:
        st = s.get(Setting, 1)
        url = (st.notify_webhook_url if st else "") or ""
    finally:
        s.close()
    payload.setdefault("app", settings.app_name)
    if url:
        threading.Thread(target=_post_json, args=(url, payload), daemon=True).start()
    _email_event(payload)


def _users_emails(db, roles: tuple[str, ...]) -> list[str]:
    rows = db.scalars(
        select(User).where(User.active == True, User.role.in_(roles))  # noqa: E712
    ).all()
    return [u.email for u in rows if getattr(u, "email", "")]


def _email_event(payload: dict) -> None:
    """Envia e-mail do evento, se SMTP configurado e houver destinatarios."""
    from . import mailer

    event = payload.get("event", "")
    db = SessionLocal()
    try:
        to: list[str] = []
        if event == "run_pending_approval":
            to = _users_emails(db, ("admin", "approver"))
        elif event in ("run_finished", "run_approved", "run_rejected", "run_created", "run_failed"):
            who = payload.get("requested_by", "")
            if who:
                u = db.scalar(select(User).where(User.username == who))
                if u and getattr(u, "email", ""):
                    to.append(u.email)
            if event in ("run_rejected", "run_failed"):
                to += _users_emails(db, ("admin",))
    finally:
        db.close()
    if not to:
        return
    to = sorted(set(to))
    subject = f"[{settings.app_name}] {_subject_for(event, payload)}"
    body = _body_for(event, payload)
    mailer.send_async(to, subject, body)


def _subject_for(event: str, p: dict) -> str:
    rid = p.get("run_id", "?")
    return {
        "run_pending_approval": f"Execucao #{rid} aguardando aprovacao",
        "run_finished": f"Execucao #{rid} concluida ({p.get('status', '')})",
        "run_approved": f"Execucao #{rid} aprovada",
        "run_rejected": f"Execucao #{rid} rejeitada",
        "run_created": f"Execucao #{rid} criada",
    }.get(event, f"Evento: {event}")


def _body_for(event: str, p: dict) -> str:
    lines = [f"Evento: {event}", f"Execucao: #{p.get('run_id', '?')}"]
    for k in ("snippet", "status", "requested_by", "approved_by", "reason"):
        if p.get(k):
            lines.append(f"{k}: {p[k]}")
    if p.get("counts"):
        lines.append("resultado: " + ", ".join(f"{k}={v}" for k, v in p["counts"].items()))
    lines.append("")
    lines.append("-- Config Push")
    return "\n".join(lines)


def _notify_run(run: Run) -> None:
    counts: dict[str, int] = {}
    for t in run.targets:
        counts[t.status] = counts.get(t.status, 0) + 1
    notify(
        {
            "event": "run_finished",
            "run_id": run.id,
            "status": run.status,
            "snippet": run.snippet_name,
            "requested_by": run.requested_by,
            "finished_at": run.finished_at.isoformat() if run.finished_at else "",
            "counts": counts,
        }
    )


def effective_credentials(db, device: Device) -> tuple[str, str, str]:
    """(username, password_enc, enable_password_enc) efetivos do device.

    Se o device nao tiver credencial propria, usa a credencial global (TACACS)
    configurada em Settings.
    """
    if device.username and device.password_enc:
        return device.username, device.password_enc, device.enable_password_enc
    s = db.get(Setting, 1)
    username = device.username or (s.default_username if s else "")
    password_enc = device.password_enc or (s.default_password_enc if s else "")
    enable_enc = device.enable_password_enc or (s.default_enable_password_enc if s else "")
    return username, password_enc, enable_enc


def device_dict(db, device: Device, target=None) -> dict:
    username, password_enc, enable_enc = effective_credentials(db, device)
    data = {
        "_target_id": target.id if target is not None else None,
        "name": device.name,
        "ip": device.ip,
        "vendor": device.vendor,
        "device_type": device.device_type,
        "protocol": device.protocol,
        "port": device.port,
        "username": username,
        "password_enc": password_enc,
        "enable_password_enc": enable_enc,
    }
    if target is not None and target.commands:
        data["commands"] = target.commands
    return data


def create_run(
    db,
    *,
    snippet_id: int | None,
    snippet_name: str,
    commands: str,
    devices: list[Device],
    dry_run: bool,
    require_approval: bool,
    requested_by: str,
    schedule_id: int | None = None,
    per_device: dict[int, tuple[str, str]] | None = None,
    auto_approve: bool = False,
    capture_diff: bool = False,
) -> Run:
    needs_approval = require_approval and not dry_run
    status = "pending_approval" if (needs_approval and not auto_approve) else "approved"
    run = Run(
        snippet_id=snippet_id,
        snippet_name=snippet_name,
        commands=commands,
        dry_run=dry_run,
        capture_diff=capture_diff,
        status=status,
        require_approval=needs_approval,
        requested_by=requested_by,
        schedule_id=schedule_id,
        created_at=utcnow(),
    )
    if status == "approved" and needs_approval and auto_approve:
        # admin/agendamento: aprovacao implicita (registra quem autorizou)
        run.approved_by = requested_by
        run.approved_at = utcnow()
    db.add(run)
    db.flush()
    for d in devices:
        sn, body = (per_device.get(d.id) if per_device else None) or (snippet_name, commands)
        db.add(
            RunTarget(
                run_id=run.id,
                device_id=d.id,
                device_name=d.name,
                device_ip=d.ip,
                snippet_name=sn,
                commands=body,
                status="pending",
            )
        )
    db.commit()
    db.refresh(run)
    return run


def schedule_has_pending(db, schedule_id: int) -> bool:
    """True se ja existe um run aguardando aprovacao para este agendamento.

    Evita acumular runs pendentes a cada disparo de um agendamento que exige
    aprovacao (e que ninguem aprovou ainda).
    """
    row = db.scalar(
        select(Run.id)
        .where(Run.schedule_id == schedule_id, Run.status == "pending_approval")
        .limit(1)
    )
    return row is not None


def execute_run(run_id: int) -> None:
    """Executa um run em background (thread propria, sessao propria)."""
    db = SessionLocal()
    locked: set[int] = set()
    try:
        run = db.get(Run, run_id)
        # so executa o que foi de fato aprovado (pending nunca roda por aqui)
        if run is None or run.status != "approved":
            return
        run.status = "running"
        run.started_at = utcnow()
        db.commit()

        targets = db.scalars(select(RunTarget).where(RunTarget.run_id == run_id)).all()
        # trava os devices: se ja houver outro run neles, marca como skipped
        pending_ids = [t.device_id for t in targets if t.status == "pending" and t.device_id]
        locked = _try_lock_devices(pending_ids)
        devices: list[dict] = []
        for t in targets:
            # so processa alvos pendentes: permite retomar/retentar sem refazer os ok
            if t.status != "pending":
                continue
            if t.device_id and t.device_id not in locked:
                t.status = "skipped"
                t.error = "device em uso por outro run"
                t.finished_at = utcnow()
                db.commit()
                continue
            dev = db.get(Device, t.device_id) if t.device_id else None
            if dev is None:
                t.status = "failed"
                t.error = "device removido"
                t.finished_at = utcnow()
                db.commit()
                continue
            t.status = "running"
            t.started_at = utcnow()
            db.commit()
            devices.append(device_dict(db, dev, t))

        def on_result(dev, res):
            s = SessionLocal()
            try:
                tgt = s.get(RunTarget, dev.get("_target_id"))
                if tgt is not None:
                    tgt.status = res["status"]
                    tgt.output = (res.get("output") or "")[-20000:]
                    tgt.error = (res.get("error") or "")[:4000]
                    tgt.diff = (res.get("diff") or "")[:40000]
                    tgt.finished_at = utcnow()
                    s.commit()
            finally:
                s.close()

        run_batch(
            devices,
            run.commands,
            run.dry_run,
            on_result,
            capture_diff=run.capture_diff,
        )

        db.expire_all()
        final = db.get(Run, run_id)
        statuses = {t.status for t in final.targets}
        if statuses <= {"success", "skipped"}:
            final.status = "done"
        elif statuses & {"success", "skipped"}:
            final.status = "partial"
        else:
            final.status = "failed"
        final.finished_at = utcnow()
        audit(
            db,
            final.approved_by or final.requested_by,
            "run_executed",
            f"run {final.id} status={final.status}",
        )
        db.commit()
        _notify_run(final)
    except Exception as e:  # noqa: BLE001
        log.exception("execute_run erro: %s", e)
        try:
            run = db.get(Run, run_id)
            if run is not None:
                run.status = "failed"
                run.finished_at = utcnow()
                db.commit()
        except Exception:  # noqa: BLE001
            pass
    finally:
        _unlock_devices(locked)
        db.close()


def recover_orphans() -> int:
    """Marca runs/alvos 'running' orfaos (apos restart) como interrompidos."""
    db = SessionLocal()
    try:
        runs = db.scalars(select(Run).where(Run.status == "running")).all()
        n = 0
        for r in runs:
            r.status = "failed"
            r.finished_at = utcnow()
            for t in r.targets:
                if t.status == "running":
                    t.status = "failed"
                    t.error = (t.error or "") + " [interrompido por reinicio]"
                    t.finished_at = utcnow()
            n += 1
        if n:
            db.commit()
            log.warning("recuperados %d run(s) orfao(s) apos restart", n)
        return n
    finally:
        db.close()


def start_run_async(run_id: int) -> None:
    threading.Thread(target=execute_run, args=(run_id,), daemon=True).start()


def collect_backup(device_id: int, source: str = "manual", author: str = "") -> dict:
    """Coleta a config de um device, versiona em Git e registra em Backup."""
    from . import backup as bk

    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if dev is None:
            return {"status": "failed", "message": "device removido"}
        dev_dict = device_dict(db, dev)
        err = ""
        try:
            content, _dtype = bk.collect(dev_dict)
        except Exception as e:  # noqa: BLE001
            content, err = "", str(e)[:1000]
        now = utcnow()
        if not content or not content.strip():
            row = Backup(
                device_id=dev.id,
                device_name=dev.name,
                device_ip=dev.ip,
                status="failed",
                message=err or "sem resposta/config",
                source=source,
                created_at=now,
            )
            db.add(row)
            db.commit()
            notify(
                {"event": "backup_failed", "device": dev.name, "error": row.message}
            )
            return {"status": "failed", "message": row.message}
        before = bk.latest_hash(dev.name)
        new_hash = bk.commit(dev.name, content, message=f"backup {dev.name} ({source})")
        changed = new_hash is not None
        row = Backup(
            device_id=dev.id,
            device_name=dev.name,
            device_ip=dev.ip,
            status="ok",
            config_hash=new_hash or before or "",
            changed=changed,
            message="alterou" if changed else "sem alteracao",
            source=source,
            created_at=now,
        )
        db.add(row)
        audit(db, author or source, "backup", f"{dev.name} {'alterou' if changed else 'sem alteracao'}")
        db.commit()
        return {"status": "ok", "changed": changed}
    finally:
        db.close()


def collect_all_backups(source: str = "schedule", author: str = "") -> int:
    """Coleta backup de todos os devices ativos (concorrencia limitada)."""
    from concurrent.futures import ThreadPoolExecutor

    db = SessionLocal()
    try:
        ids = [
            d.id
            for d in db.scalars(select(Device).where(Device.enabled == True)).all()  # noqa: E712
        ]
    finally:
        db.close()
    if not ids:
        return 0
    workers = max(1, min(settings.max_workers, len(ids)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda i: collect_backup(i, source, author), ids))
    return len(ids)


def start_backup_all_async(source: str = "manual", author: str = "") -> None:
    threading.Thread(
        target=collect_all_backups, args=(source, author), daemon=True
    ).start()


def save_run_configs(run_id: int, author: str = "", only_target: int | None = None) -> dict:
    """Salva (persiste) a config dos devices de um run que terminaram com sucesso.

    Executa o comando de save adequado ao driver (wr mem / save / commit ...).
    Grava o resultado no output do proprio alvo e na auditoria.

    Devolve {ok: [nomes], failed: [(nome, erro)], skipped: [nomes]} — os
    ``skipped`` sao os alvos que NAO tiveram sucesso (nao sao salvos).
    ``only_target`` restringe a um unico alvo (botao por linha).
    """
    from concurrent.futures import ThreadPoolExecutor

    from .engine import save_config

    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run is None:
            return {"ok": [], "failed": [], "skipped": []}
        rows = [
            {"id": t.id, "device_id": t.device_id, "name": t.device_name, "status": t.status}
            for t in run.targets
        ]
    finally:
        db.close()

    targets = [t for t in rows if only_target is None or t["id"] == only_target]
    to_save = [t for t in targets if t["status"] == "success" and t["device_id"]]
    skipped = [t["name"] for t in targets if t["status"] != "success"]

    ok: list[str] = []
    failed: list[tuple[str, str]] = []

    def _one(t: dict) -> tuple[str, bool, str]:
        s = SessionLocal()
        try:
            dev = s.get(Device, t["device_id"])
            if dev is None:
                return (t["name"], False, "device removido")
            res = save_config(device_dict(s, dev))
            tgt = s.get(RunTarget, t["id"])
            if tgt is not None:
                stamp = utcnow().strftime("%Y-%m-%d %H:%M:%S")
                tgt.output = (tgt.output or "") + (
                    f"\n\n=== salvar config ({stamp}) ===\n"
                    f"{res.get('output', '')}\n"
                    + (f"[erro] {res['error']}" if res.get("error") else "[ok] config salva")
                )[:20000]
                s.commit()
            audit(s, author or "save", "run_save_config", f"{dev.name} {res['status']}")
            s.commit()
            return (t["name"], res["status"] == "success", res.get("error", ""))
        finally:
            s.close()

    if to_save:
        workers = max(1, min(settings.max_workers, len(to_save)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for name, success, err in pool.map(_one, to_save):
                if success:
                    ok.append(name)
                else:
                    failed.append((name, err))
    return {"ok": ok, "failed": failed, "skipped": skipped}


def start_save_run_async(run_id: int, author: str = "") -> None:
    threading.Thread(target=save_run_configs, args=(run_id, author), daemon=True).start()


def schedule_next(schedule: Schedule) -> None:
    if schedule.mode == "once":
        schedule.next_run_at = schedule.run_at
        return
    # base = agora: evita acumular drift/execucoes atrasadas (nao dispara rajada)
    base = utcnow()
    try:
        it = croniter(schedule.cron, base)
        schedule.next_run_at = it.get_next(datetime)
    except Exception:
        schedule.next_run_at = None
