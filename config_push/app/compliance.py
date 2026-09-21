"""Motor de conformidade (golden config) e drift.

Le a config atual de cada device via Netmiko (reusa ``backup.collect``), avalia
as regras da politica (require/forbid/regex) e registra o resultado. Cada
execucao tambem versiona a config no repositorio Git interno (``app/backup.py``),
o que da o historico e o diff (drift) sem armazenamento extra.
"""

import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from . import backup as bk
from .config import settings
from .db import SessionLocal, utcnow
from .models import ComplianceResult, ComplianceRun, Device, Policy, PolicyRule
from .service import audit, device_dict, notify

log = logging.getLogger("app.compliance")

KINDS = ("require", "forbid", "regex")
SEVERITIES = ("error", "warn")
STATUSES = ("compliant", "violation", "error")


def select_devices(db, policy: Policy) -> list[Device]:
    """Devices alvo da politica (seletores combinam; lista explicita restringe)."""
    conds = [Device.enabled == True]  # noqa: E712
    if policy.vendor:
        conds.append(Device.vendor == policy.vendor)
    if policy.driver:
        conds.append(Device.device_type == policy.driver)
    if policy.tag:
        conds.append(Device.tags.ilike(f"%{policy.tag}%"))
    try:
        ids = [int(x) for x in json.loads(policy.device_ids or "[]")]
    except (ValueError, TypeError):
        ids = []
    if ids:
        conds.append(Device.id.in_(ids))
    return list(db.scalars(select(Device).where(*conds).order_by(Device.name)).all())


def evaluate(config: str, rules: list[dict]) -> list[dict]:
    """Avalia as regras contra a config. Devolve os achados (regras que falharam)."""
    lines = (config or "").splitlines()
    findings: list[dict] = []
    for r in rules:
        pattern = (r.get("pattern") or "").strip()
        if not pattern:
            continue
        case_sensitive = bool(r.get("case_sensitive"))
        kind = r.get("kind") or "require"
        hits: list[int] = []
        invalid = ""
        if kind == "regex":
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                rx = re.compile(pattern, flags)
            except re.error as e:
                invalid = str(e)
                rx = None
            if rx is not None:
                hits = [i for i, ln in enumerate(lines, 1) if rx.search(ln)]
            failed = bool(invalid) or not hits
        else:
            needle = pattern if case_sensitive else pattern.lower()
            for i, ln in enumerate(lines, 1):
                hay = ln if case_sensitive else ln.lower()
                if needle in hay:
                    hits.append(i)
            failed = (not hits) if kind == "require" else bool(hits)
        if failed:
            findings.append(
                {
                    "rule_id": r.get("id"),
                    "kind": kind,
                    "severity": r.get("severity") or "error",
                    "pattern": pattern,
                    "description": r.get("description") or "",
                    "lines": hits[:20],
                    "invalid": invalid,
                }
            )
    return findings


def _rule_defs(rules: list[PolicyRule]) -> list[dict]:
    return [
        {
            "id": r.id,
            "kind": r.kind,
            "pattern": r.pattern,
            "description": r.description,
            "severity": r.severity,
            "case_sensitive": r.case_sensitive,
        }
        for r in rules
    ]


def _check(item: dict, rule_defs: list[dict]) -> tuple[dict, dict]:
    """Le a config, avalia as regras e versiona (snapshot). Roda em thread."""
    try:
        content, _dtype = bk.collect(item["dict"])
    except Exception as e:  # noqa: BLE001
        return item, {"status": "error", "message": str(e)[:1000], "findings": [], "hash": "", "changed": False}
    if not content or not content.strip():
        return item, {"status": "error", "message": "sem resposta/config", "findings": [], "hash": "", "changed": False}
    findings = evaluate(content, rule_defs)
    try:
        before = bk.latest_hash(item["name"])
        new_hash = bk.commit(item["name"], content, message=f"compliance {item['name']}")
    except Exception as e:  # noqa: BLE001
        log.warning("snapshot falhou em %s: %s", item["name"], e)
        before, new_hash = None, None
    changed = new_hash is not None
    status = "violation" if findings else "compliant"
    return item, {
        "status": status,
        "message": "",
        "findings": findings,
        "hash": new_hash or before or "",
        "changed": changed,
    }


def _execute_policy(run_id: int, policy_id: int) -> None:
    db = SessionLocal()
    try:
        policy = db.get(Policy, policy_id)
        if policy is None:
            run = db.get(ComplianceRun, run_id)
            if run is not None:
                run.status = "failed"
                run.finished_at = utcnow()
                db.commit()
            return
        rules = list(
            db.scalars(
                select(PolicyRule).where(PolicyRule.policy_id == policy_id).order_by(PolicyRule.id)
            ).all()
        )
        rule_defs = _rule_defs(rules)
        devices = select_devices(db, policy)
        payload = [
            {"id": d.id, "name": d.name, "ip": d.ip, "dict": device_dict(db, d)}
            for d in devices
        ]
        run = db.get(ComplianceRun, run_id)
        run.total = len(payload)
        db.commit()
        author = run.requested_by
        policy_name = run.policy_name
    finally:
        db.close()

    counters = {"compliant": 0, "violation": 0, "error": 0}
    try:
        workers = max(1, min(settings.max_workers, len(payload) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for item, res in pool.map(lambda it: _check(it, rule_defs), payload):
                s = SessionLocal()
                try:
                    s.add(
                        ComplianceResult(
                            run_id=run_id,
                            device_id=item["id"],
                            device_name=item["name"],
                            device_ip=item["ip"],
                            status=res["status"],
                            findings=json.dumps(res["findings"]),
                            config_hash=res["hash"],
                            changed=res["changed"],
                            message=res["message"],
                            created_at=utcnow(),
                        )
                    )
                    s.commit()
                finally:
                    s.close()
                counters[res["status"]] = counters.get(res["status"], 0) + 1
        final_status = "done"
    except Exception as e:  # noqa: BLE001
        log.exception("compliance erro: %s", e)
        final_status = "failed"

    db = SessionLocal()
    try:
        run = db.get(ComplianceRun, run_id)
        if run is not None:
            run.compliant = counters["compliant"]
            run.violations = counters["violation"]
            run.errors = counters["error"]
            run.status = final_status
            run.finished_at = utcnow()
            audit(
                db,
                author or "compliance",
                "compliance_run",
                f"politica '{policy_name}' conformes={run.compliant} "
                f"violacoes={run.violations} erros={run.errors}",
            )
            db.commit()
    finally:
        db.close()
    notify(
        {
            "event": "compliance_finished",
            "policy": policy_name,
            "status": final_status,
            "total": len(payload),
            "compliant": counters["compliant"],
            "violations": counters["violation"],
            "errors": counters["error"],
        }
    )


def start_policy_async(policy_id: int, author: str = "") -> int:
    """Cria a execucao e roda em background. Devolve o id da execucao."""
    db = SessionLocal()
    try:
        policy = db.get(Policy, policy_id)
        if policy is None:
            raise ValueError("politica nao encontrada")
        run = ComplianceRun(
            policy_id=policy.id,
            policy_name=policy.name,
            status="running",
            requested_by=author,
            created_at=utcnow(),
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        run_id = run.id
    finally:
        db.close()
    threading.Thread(target=_execute_policy, args=(run_id, policy_id), daemon=True).start()
    return run_id
