import difflib
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler, SSHDetect
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from .config import settings
from .security import AUTODETECT, decrypt_secret, resolve_device_type

log = logging.getLogger("app.engine")

# Teto global de conexoes simultaneas (somando todos os runs em andamento).
_GLOBAL_SEM = threading.Semaphore(max(1, settings.max_workers))

SLEEP_RE = re.compile(r"^#\[\s*sleep\s+(\d+)\s*\]$", re.IGNORECASE)
# comandos de entrada/saida do modo de configuracao (o motor gerencia)
MODE_ENTER_RE = re.compile(
    r"^(conf(ig(ure)?)?(\s+t(erminal)?)?|config)$", re.IGNORECASE
)
MODE_END_RE = re.compile(r"^(end|exit-config)$", re.IGNORECASE)
# comandos de salvar (rodam no modo exec, apos sair do config)
SAVE_CMDS = {
    "wr",
    "wr mem",
    "wr memory",
    "write",
    "write mem",
    "write memory",
    "copy run start",
    "copy running-config startup-config",
    "save",
    "save force",
    "commit",
}


# Drivers em que o Netmiko NAO gerencia modo de config (NoConfig): os comandos
# vao crus, entao 'config ...'/'end' fazem parte do snippet e NAO podem ser
# removidos (ex.: FortiOS usa blocos "config ... end").
_NO_MODE_PREFIXES = ("fortinet",)


def _preprocess(
    actions: list[tuple[str, str]], device_type: str = ""
) -> tuple[list[tuple[str, str]], list[str]]:
    """Remove comandos de modo e separa os de salvar (executados no fim, em exec).

    Para drivers NoConfig (fortinet) mantem tudo como veio, pois o proprio
    snippet precisa conter 'config ...' e 'end'.
    """
    passthrough = any(device_type.startswith(p) for p in _NO_MODE_PREFIXES)
    cfg_actions: list[tuple[str, str]] = []
    saves: list[str] = []
    for kind, value in actions:
        if kind != "cmd":
            cfg_actions.append((kind, value))
            continue
        v = value.strip()
        if not passthrough:
            if MODE_ENTER_RE.match(v) or MODE_END_RE.match(v):
                continue
            if v.lower() in SAVE_CMDS:
                saves.append(v)
                continue
        cfg_actions.append((kind, value))
    return cfg_actions, saves



def parse_actions(body: str) -> list[tuple[str, str]]:
    """Converte o texto do snippet numa lista de (tipo, valor).

    tipo = 'cmd' | 'sleep'
    Linhas em branco e comentarios (# ...) sao ignorados.
    """
    actions: list[tuple[str, str]] = []
    for raw in (body or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = SLEEP_RE.match(line.strip())
        if m:
            actions.append(("sleep", m.group(1)))
            continue
        if line.strip().startswith("#"):
            continue
        actions.append(("cmd", line.strip()))
    return actions


def _chunks(actions: list[tuple[str, str]]):
    """Agrupa comandos entre sleeps; devolve lista de (comandos, sleep_apos)."""
    chunks: list[tuple[list[str], int]] = []
    cmds: list[str] = []
    for kind, value in actions:
        if kind == "sleep":
            chunks.append((cmds, int(value)))
            cmds = []
        else:
            cmds.append(value)
    if cmds:
        chunks.append((cmds, 0))
    return chunks


# Comando para ler a config atual, por driver (fallback: show running-config)
_CONFIG_CMDS: list[tuple[tuple[str, ...], str]] = [
    (("hp_comware", "huawei"), "display current-configuration"),
    (("juniper_junos",), "show configuration | display set"),
    (("fortinet",), "show"),
    (("mikrotik_routeros",), "export verbose"),
    (("vyos",), "show configuration commands"),
    (("paloalto_panos",), "show config running"),
]
_CONFIG_DEFAULT = "show running-config"


def _config_cmd(device_type: str) -> str:
    base = (device_type or "").replace("_telnet", "")
    for drivers, cmd in _CONFIG_CMDS:
        if base in drivers:
            return cmd
    return _CONFIG_DEFAULT


# Comando de persistencia (salvar config na startup) por driver.
# Fallback: 'write memory' (familia Cisco-like).
_SAVE_CMDS: list[tuple[tuple[str, ...], str]] = [
    (("hp_comware", "huawei", "h3c"), "save force"),
    (("juniper_junos",), "commit"),
    (("fortinet",), "execute cfg save"),
    (("mikrotik_routeros",), "/system backup save name=auto"),
    (("vyos",), "save"),
    (("paloalto_panos",), "commit"),
    (("dell_os6", "dell_powerconnect"), "copy running-config startup-config"),
    (("dell_os9", "dell_os10", "dell_force10"), "copy running-config startup-config"),
    (("aruba_aoscx",), "copy running-config startup-config"),
]
_SAVE_DEFAULT = "write memory"


def save_cmd(device_type: str) -> str:
    base = (device_type or "").replace("_telnet", "")
    for drivers, cmd in _SAVE_CMDS:
        if base in drivers:
            return cmd
    return _SAVE_DEFAULT


def save_config(device: dict) -> dict:
    """Salva a config em execucao na startup do device (persistencia).

    Roda o comando de save adequado ao driver. Nao altera a config em si.
    """
    conn, device_type, detected, enable_pw = build_conn(device)
    cmd = save_cmd(device_type)
    output_parts = [
        f"[driver] {device_type}" + (f" (autodetectado de '{AUTODETECT}')" if detected else ""),
        f"[save] {cmd}",
    ]
    _GLOBAL_SEM.acquire()
    try:
        with ConnectHandler(**conn) as ssh:
            if enable_pw:
                try:
                    ssh.enable()
                except Exception as e:  # noqa: BLE001
                    output_parts.append(f"[enable] aviso: {e}")
            pre_all = "\n".join(
                x for x in (_auto_pre_commands(device), (device.get("pre_commands") or "").strip()) if x
            )
            output_parts += run_pre_commands(ssh, pre_all)
            out = ssh.send_command_timing(cmd, read_timeout=settings.conn_timeout * 4)
            output_parts.append(out)
            # deteccao simples de erro nas respostas mais comuns
            low = (out or "").lower()
            failed = any(
                s in low
                for s in ("invalid input", "unrecognized", "syntax error", "incomplete command")
            )
        return {
            "status": "failed" if failed else "success",
            "output": "\n".join(output_parts),
            "error": "comando de save reportou erro" if failed else "",
        }
    except NetmikoTimeoutException as e:
        return {"status": "failed", "output": "\n".join(output_parts), "error": f"timeout: {e}"}
    except NetmikoAuthenticationException as e:
        return {"status": "failed", "output": "\n".join(output_parts), "error": f"autenticacao: {e}"}
    except Exception as e:  # noqa: BLE001
        log.exception("falha ao salvar config em %s", device.get("ip"))
        return {"status": "failed", "output": "\n".join(output_parts), "error": str(e)[:500]}
    finally:
        _GLOBAL_SEM.release()


def _auto_pre_commands(device: dict) -> str:
    """Pre-comandos automaticos por driver (ex.: Comware/3Com antigo -> _cmdline).

    Se o device for Comware legacy e tiver senha de manutencao, monta:
        _cmdline-mode on
        Y
        <senha>
    """
    from .catalog import is_legacy_comware

    driver = (device.get("device_type") or "") + " " + resolve_device_type(
        device.get("vendor", ""), device.get("protocol", "ssh"), device.get("device_type", "")
    )
    is_comware = "comware" in driver.lower() or "3com" in (device.get("vendor", "") or "").lower()
    if is_comware and is_legacy_comware(device.get("vendor", ""), device.get("model", ""), driver):
        pw = decrypt_secret(device.get("maintenance_password_enc", ""))
        if pw:
            return f"_cmdline-mode on\nY\n{pw}"
    return ""


# NB: nao usar "wrong" (a msg de SUCESSO contem "by wrong use"); idem termos
# genericos que aparecem no aviso de sucesso.
_CMDLINE_ERR = ("invalid password", "incorrect password", "unrecognized", "permission denied")
# Marcador POSITIVO de que a SENHA foi aceita (HP/H3C antigo): apos digitar a
# senha aparece o aviso de "all-command mode". (A frase "All commands can be
# displayed..." aparece ANTES da senha, entao nao serve para validar a senha.)
_CMDLINE_PW_OK = (
    "enter an all-command mode",
    "all-command mode",
    "******",
)


def discover_maintenance_password(device: dict, candidates: list[str]) -> dict:
    """Descobre qual senha de _cmdline-mode funciona no device.

    Fluxo (HP/H3C antigo): '_cmdline-mode on' -> 'Y' -> senha.
    A senha correta faz aparecer o aviso "...enter an all-command mode...".
    Confirma com 'system-view' (prompt vira '[...]'). Devolve {status, password, output}.
    """
    conn, device_type, _detected, enable_pw = build_conn(device)
    candidates = [c.strip() for c in candidates if c and c.strip()]
    if not candidates:
        return {"status": "failed", "password": "", "output": "sem candidatas"}
    _GLOBAL_SEM.acquire()
    try:
        last = ""
        for pw in candidates:
            try:
                with ConnectHandler(**conn) as ssh:
                    ssh.send_command_timing("_cmdline-mode on", read_timeout=settings.conn_timeout * 2)
                    ssh.send_command_timing("Y", read_timeout=settings.conn_timeout * 2)
                    out = ssh.send_command_timing(pw, read_timeout=settings.conn_timeout * 2)
                    last = out
                    low = out.lower()
                    ok = any(k in low for k in _CMDLINE_PW_OK)
                    # o marcador positivo ("enter an all-command mode") so' aparece
                    # com a SENHA CERTA — basta isso para confirmar (o system-view
                    # seguinte pode falhar por pager/timing sem invalidar a senha).
                    if ok and not any(e in low for e in _CMDLINE_ERR):
                        return {
                            "status": "success",
                            "password": pw,
                            "output": f"senha aceita: {pw}\n{out}",
                        }
            except Exception as e:  # noqa: BLE001
                last = f"excecao: {e}"
                log.info("descobrir senha: tentativa falhou (%s)", e)
        return {"status": "failed", "password": "", "output": last or "nenhuma senha funcionou"}
    finally:
        _GLOBAL_SEM.release()


def run_pre_commands(ssh, pre_commands: str) -> list[str]:
    """Executa os pre-comandos (ex.: _cmdline-mode on / Y / senha) apos conectar.

    Usa send_command_timing (comandos interativos com prompts). Um por linha.
    Devolve as linhas para o output do run.
    """
    out_lines: list[str] = []
    lines = [ln.rstrip() for ln in (pre_commands or "").splitlines()]
    lines = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return out_lines
    out_lines.append("[pre] executando comandos de preparacao")
    for cmd in lines:
        try:
            out = ssh.send_command_timing(cmd, read_timeout=settings.conn_timeout * 2)
            out_lines.append(f"$ {cmd}\n{out}")
        except Exception as e:  # noqa: BLE001
            out_lines.append(f"$ {cmd}\n[erro no pre-comando: {e}]")
        time.sleep(0.5)
    return out_lines


def _read_config(ssh, device_type: str) -> str:
    try:
        return ssh.send_command(
            _config_cmd(device_type),
            read_timeout=settings.conn_timeout * 4,
            strip_prompt=False,
            strip_command=False,
        )
    except Exception:  # noqa: BLE001
        return ""


def _unified_diff(before: str, after: str, limit: int = 20000) -> str:
    if before is None or after is None or before == after:
        return ""
    diff = list(
        difflib.unified_diff(
            (before or "").splitlines(),
            (after or "").splitlines(),
            fromfile="antes",
            tofile="depois",
            lineterm="",
        )
    )
    text = "\n".join(diff)
    return text[:limit]


def _detect_driver(conn: dict) -> str:
    """Usa SSHDetect do Netmiko para descobrir o driver. Fallback: cisco_ios."""
    try:
        guesser = SSHDetect(**conn)
        try:
            best = guesser.autodetect()
        finally:
            guesser.disconnect()
        if best:
            return best
    except Exception:  # noqa: BLE001
        pass
    return "cisco_ios"


def build_conn(device: dict) -> tuple[dict, str, str, str]:
    """Monta os parametros do Netmiko.

    Devolve (conn, device_type, detected, enable_pw). Se o driver for
    'autodetect', tenta resolver via SSHDetect e devolve o driver detectado.
    """
    device_type = resolve_device_type(
        device.get("vendor", ""), device.get("protocol", "ssh"), device.get("device_type", "")
    )
    enable_pw = decrypt_secret(device.get("enable_password_enc", ""))
    conn = {
        "device_type": device_type,
        "host": device["ip"],
        "username": device.get("username", ""),
        "password": decrypt_secret(device.get("password_enc", "")),
        "port": int(device.get("port") or 22),
        "conn_timeout": settings.conn_timeout,
        "timeout": settings.conn_timeout,
    }
    if enable_pw:
        conn["secret"] = enable_pw

    detected = ""
    if device_type == AUTODETECT:
        detected = _detect_driver(conn)
        device_type = detected
        conn["device_type"] = detected
    return conn, device_type, detected, enable_pw


def test_connection(device: dict) -> dict:
    """Testa a conexao (auth/alcançabilidade) sem alterar configuracao."""
    conn, device_type, detected, _enable = build_conn(device)
    if not conn.get("username") or not conn.get("password"):
        return {
            "status": "failed",
            "driver": device_type,
            "output": "",
            "error": "sem credencial (device ou global)",
        }
    _GLOBAL_SEM.acquire()
    try:
        with ConnectHandler(**conn) as ssh:
            prompt = ssh.find_prompt()
        return {
            "status": "success",
            "driver": device_type,
            "output": f"conectado (prompt: {prompt})",
            "error": "",
        }
    except NetmikoTimeoutException as e:
        return {"status": "failed", "driver": device_type, "output": "", "error": f"timeout: {e}"}
    except NetmikoAuthenticationException as e:
        return {
            "status": "failed",
            "driver": device_type,
            "output": "",
            "error": f"autenticacao: {e}",
        }
    except Exception as e:  # noqa: BLE001
        log.exception("falha no teste de conexao em %s", device.get("ip"))
        return {"status": "failed", "driver": device_type, "output": "", "error": str(e)[:500]}
    finally:
        _GLOBAL_SEM.release()


def apply_to_device(
    device: dict, body: str, dry_run: bool, capture_diff: bool = False
) -> dict:
    """Executa o snippet num device. Devolve dict com status/output/error/diff."""
    from .templating import TemplateVarError, has_template, render

    raw_body = body or ""
    templated = has_template(raw_body)
    try:
        body = render(raw_body, device, device.get("_vars"))
    except TemplateVarError as e:
        return {"status": "failed", "output": "", "error": f"template: {e}", "diff": ""}
    actions = parse_actions(body)
    resolved_type = resolve_device_type(
        device.get("vendor", ""), device.get("protocol", "ssh"), device.get("device_type", "")
    )
    cfg_actions, saves = _preprocess(actions, resolved_type)
    commands = [v for k, v in cfg_actions if k == "cmd"]
    rendered = "\n".join(f"sleep {v}s" if k == "sleep" else v for k, v in actions)

    if not commands and not saves:
        return {"status": "skipped", "output": "", "error": "sem comandos", "diff": ""}

    # dry-run "puro" (sem captura) nao conecta
    if dry_run and not capture_diff:
        return {
            "status": "success",
            "output": f"[DRY-RUN] comandos que seriam aplicados:\n{rendered}",
            "error": "",
            "diff": "",
        }

    conn, device_type, detected, enable_pw = build_conn(device)

    output_parts: list[str] = [
        f"[driver] {device_type}" + (f" (autodetectado de '{AUTODETECT}')" if detected else "")
    ]
    if templated:
        output_parts.append(
            f"[template] renderizado para {device.get('name')} "
            f"(site={device.get('site') or '-'}):"
        )
        output_parts.append(body)
    # teto global: limita conexoes simultaneas somando todos os runs
    _GLOBAL_SEM.acquire()
    try:
        with ConnectHandler(**conn) as ssh:
            if enable_pw:
                try:
                    ssh.enable()
                    output_parts.append("[enable] modo privilegiado ativado")
                except Exception as e:  # noqa: BLE001
                    output_parts.append(f"[enable] aviso: {e}")
            pre_all = "\n".join(
                x for x in (_auto_pre_commands(device), (device.get("pre_commands") or "").strip()) if x
            )
            output_parts += run_pre_commands(ssh, pre_all)
            before = _read_config(ssh, device_type) if capture_diff else ""
            if dry_run:
                # dry-run "real": valida a conexao e mostra a config atual
                output_parts.append(f"[dry-run] leitura da config atual ({_config_cmd(device_type)})")
                output_parts.append((before or "(sem resposta)")[:8000])
                output_parts.append("[dry-run] comandos que seriam aplicados:")
                output_parts.append(rendered)
                return {
                    "status": "success",
                    "output": "\n".join(output_parts),
                    "error": "",
                    "diff": "",
                }
            chunks = _chunks(cfg_actions)
            for idx, (chunk, sleep_after) in enumerate(chunks):
                if not chunk:
                    continue
                out = ssh.send_config_set(
                    chunk,
                    enter_config_mode=(idx == 0),
                    exit_config_mode=(idx == len(chunks) - 1),
                    read_timeout=settings.conn_timeout * 2,
                )
                output_parts.append(out)
                if sleep_after:
                    output_parts.append(f"[aguardando {sleep_after}s]")
                    time.sleep(sleep_after)
            # comandos de salvar (modo exec)
            for sc in saves:
                try:
                    out = ssh.send_command_timing(sc, read_timeout=settings.conn_timeout * 2)
                    output_parts.append(f"$ {sc}\n{out}")
                except Exception as e:  # noqa: BLE001
                    output_parts.append(f"$ {sc}\n[erro ao salvar: {e}]")
            diff = ""
            if capture_diff:
                after = _read_config(ssh, device_type)
                diff = _unified_diff(before, after)
                if diff:
                    output_parts.append("[diff] alteracoes detectadas (ver campo diff)")
                else:
                    output_parts.append("[diff] nenhuma alteracao detectada")
        return {
            "status": "success",
            "output": "\n".join(output_parts),
            "error": "",
            "diff": diff,
        }
    except NetmikoTimeoutException as e:
        return {
            "status": "failed",
            "output": "\n".join(output_parts),
            "error": f"timeout: {e}",
            "diff": "",
        }
    except NetmikoAuthenticationException as e:
        return {
            "status": "failed",
            "output": "\n".join(output_parts),
            "error": f"autenticacao: {e}",
            "diff": "",
        }
    except Exception as e:  # noqa: BLE001
        log.exception("falha ao aplicar config em %s", device.get("ip"))
        return {
            "status": "failed",
            "output": "\n".join(output_parts),
            "error": str(e)[:500],
            "diff": "",
        }
    finally:
        _GLOBAL_SEM.release()


def run_batch(
    devices: list[dict],
    body: str,
    dry_run: bool,
    on_result=None,
    capture_diff: bool = False,
) -> list[dict]:
    """Executa em lote com concorrencia limitada.

    on_result(device, result) e chamado a cada conclusao (para log/historico).
    """
    results: list[dict] = []
    workers = max(1, min(settings.max_workers, len(devices) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                apply_to_device, d, d.get("commands") or body, dry_run, capture_diff
            ): d
            for d in devices
        }
        for fut in as_completed(futures):
            dev = futures[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                res = {"status": "failed", "output": "", "error": str(e), "diff": ""}
            results.append({"device": dev, "result": res})
            if on_result:
                on_result(dev, res)
    return results
