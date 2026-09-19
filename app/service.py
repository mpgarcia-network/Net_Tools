import json
import logging
import threading
from datetime import datetime
from urllib import request as urlrequest

from croniter import croniter
from sqlalchemy import select

from .db import SessionLocal, utcnow
from .engine import run_batch
from .models import AuditLog, Device, Run, RunTarget, Schedule, Setting

log = logging.getLogger("configpush.service")

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
    s = SessionLocal()
    try:
        st = s.get(Setting, 1)
        url = (st.notify_webhook_url if st else "") or ""
    finally:
        s.close()
    if not url:
        return
    payload.setdefault("app", "SSU Config Push")
    threading.Thread(target=_post_json, args=(url, payload), daemon=True).start()


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
