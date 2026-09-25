"""Motor de backup/versionamento de configuracao.

Guarda uma copia versionada (Git, via dulwich) da config de cada device em
``DATA_DIR/configs/<slug>/``. Cada coleta gera um commit. A tela de Backups
mostra o historico e o diff entre versoes.

dulwich e' Apache-2.0 (sem copyleft), seguro para produto comercial.
"""

import difflib
import re
import time
from pathlib import Path

from dulwich import porcelain
from dulwich.repo import Repo
from netmiko import ConnectHandler

from .config import settings
from .engine import _auto_pre_commands, _read_config, build_conn, run_pre_commands

BACKUP_DIR: Path = settings.data_dir / "configs"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = "running-config"
_AUTHOR = b"Net Tools <nettools@localhost>"


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "").strip())
    return s or "device"


def repo_dir(name: str) -> Path:
    return BACKUP_DIR / _slug(name)


def _ensure_repo(name: str) -> Path:
    p = repo_dir(name)
    if not (p / ".git").exists():
        p.mkdir(parents=True, exist_ok=True)
        porcelain.init(str(p))
    return p


def collect(device: dict) -> tuple[str, str]:
    """Conecta e le a config atual. Devolve (conteudo, device_type)."""
    conn, device_type, _detected, enable_pw = build_conn(device)
    with ConnectHandler(**conn) as ssh:
        if enable_pw:
            try:
                ssh.enable()
            except Exception:  # noqa: BLE001
                pass
        pre_all = "\n".join(
            x for x in (_auto_pre_commands(device), (device.get("pre_commands") or "").strip()) if x
        )
        run_pre_commands(ssh, pre_all)
        cfg = _read_config(ssh, device_type)
    return cfg, device_type


def commit(name: str, content: str, message: str = "") -> str | None:
    """Grava uma nova versao. Retorna o hash ou None se vazio/sem mudanca."""
    if not content or not content.strip():
        return None
    p = _ensure_repo(name)
    f = p / CONFIG_FILE
    old = f.read_text(encoding="utf-8") if f.exists() else None
    if old is not None and old == content:
        return None  # sem mudanca: nao versiona
    f.write_text(content, encoding="utf-8")
    porcelain.add(str(p), paths=[CONFIG_FILE])
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = message or f"backup {name} @ {ts}"
    porcelain.commit(str(p), message=msg.encode(), author=_AUTHOR, committer=_AUTHOR)
    return latest_hash(name)


def latest_hash(name: str) -> str | None:
    p = repo_dir(name)
    if not (p / ".git").exists():
        return None
    r = Repo(str(p))
    try:
        try:
            return r.head().decode()
        except KeyError:
            return None
    finally:
        r.close()


def versions(name: str, limit: int = 100) -> list[dict]:
    """Lista as versoes, mais recente primeiro."""
    p = repo_dir(name)
    if not (p / ".git").exists():
        return []
    r = Repo(str(p))
    out: list[dict] = []
    try:
        if not r.head():
            return []
        for entry in r.get_walker(max_entries=limit):
            c = entry.commit
            out.append(
                {
                    "hash": c.id.decode(),
                    "short": c.id.decode()[:8],
                    "message": c.message.decode("utf-8", "replace").strip(),
                    "time": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(c.commit_time)
                    ),
                }
            )
    except (KeyError, ValueError):
        pass
    finally:
        r.close()
    return out


def read_version(name: str, commit_hash: str | None = None) -> str:
    """Le o conteudo da config numa versao (default: HEAD)."""
    p = repo_dir(name)
    if not (p / ".git").exists():
        return ""
    r = Repo(str(p))
    try:
        head = r.head()
        if not head:
            return ""
        cid = commit_hash.encode() if commit_hash else head
        commit_obj = r[cid]
        tree = r[commit_obj.tree]
        _mode, sha = tree.lookup_path(lambda s: r[s], CONFIG_FILE.encode())
        return r[sha].data.decode("utf-8", "replace")
    except (KeyError, UnicodeDecodeError):
        return ""
    finally:
        r.close()


def diff(name: str, old_hash: str | None = None, new_hash: str | None = None) -> str:
    """Diff unificado entre duas versoes.

    Default: a versao ``new_hash`` (ou HEAD) contra a versao anterior (parent).
    """
    p = repo_dir(name)
    resolved_old = old_hash
    if not resolved_old and (p / ".git").exists():
        r = Repo(str(p))
        try:
            head = r.head()
            if head:
                new_id = new_hash.encode() if new_hash else head
                parents = r[new_id].parents
                if parents:
                    resolved_old = parents[0].decode()
        except (KeyError, ValueError):
            pass
        finally:
            r.close()
    old = read_version(name, resolved_old)
    new = read_version(name, new_hash)
    return "\n".join(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            fromfile=(resolved_old or "anterior")[:8],
            tofile=(new_hash or "HEAD")[:8],
            lineterm="",
        )
    )
