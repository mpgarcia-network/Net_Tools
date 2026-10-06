"""Testes da pagina de relatorios (item 5 do roadmap)."""

from app.db import SessionLocal
from app.main import _report_data
from app.models import Backup


def test_reports_page(auth_client):
    r = auth_client.get("/reports")
    assert r.status_code == 200


def test_reports_export_csv(auth_client):
    r = auth_client.get("/reports/export.csv?type=runs")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.text.startswith("\ufeff")


def test_reports_export_tipo_invalido(auth_client):
    # tipo desconhecido cai no padrao (runs) e segue 200
    r = auth_client.get("/reports/export.csv?type=nao-existe")
    assert r.status_code == 200


def test_report_data_backups():
    db = SessionLocal()
    try:
        db.add(Backup(device_name="sw-teste", device_ip="10.0.0.1", status="ok", source="manual"))
        db.commit()
        columns, rows = _report_data(db, "backups", "", "")
    finally:
        db.close()
    assert "device" in columns
    assert any(r[1] == "sw-teste" for r in rows)
