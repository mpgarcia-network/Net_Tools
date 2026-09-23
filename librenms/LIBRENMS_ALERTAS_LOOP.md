# LibreNMS — Alertas de suspeita de loop (e evolução p/ detecção real)

> Objetivo: detectar **loop de rede** por **sintomas** no LibreNMS, usando o que
> ele já coleta. Não é um detector de loop "puro" (isso é a Fase 3), mas pega a
> maioria dos casos (broadcast storm / saturação) sem sensor extra.
>
> Ambiente: `100.120.0.41` (vmssuproxy), LibreNMS `:8001`, token em Settings → API.

---

## 1. Alert rules criadas (Fase 1 — via API)

Criadas via `POST /api/v0/rules` (globais, device `-1`), já habilitadas:

| ID | Nome | Severidade | Regra (resumo) |
|---|---|---|---|
| 13 | Loop suspect: interface errors high (in/out) | critical | `ifInErrors_rate >= 100` OR `ifOutErrors_rate >= 100` (porta up) |
| 14 | Loop suspect: interface errors rising (delta) | warning | `ifInErrors_delta >= 50` OR `ifOutErrors_delta >= 50` (porta up) |
| 15 | Loop suspect: uplink saturated (usage >= 98%) | warning | uso da porta ≥ 98% (porta up) |

> Já existiam (padrão do LibreNMS): `Port status up/down`, `Port utilisation over
> threshold` (80%). A #15 é um reforço pra saturação próxima de 100% (storm).
> Se achar redundante, dá pra desabilitar/remover a #15.

### Como criar mais (exemplo via API)

```bash
curl -s -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name":"Loop suspect: interface errors high (in/out)",
    "severity":"critical",
    "disabled":0,
    "devices":[-1],
    "builder":"{\"condition\":\"AND\",\"rules\":[{\"id\":\"ports.ifInErrors_rate\",\"field\":\"ports.ifInErrors_rate\",\"type\":\"string\",\"input\":\"text\",\"operator\":\"greater_or_equal\",\"value\":\"100\"}],\"valid\":true}",
    "notes":"Suspeita de loop/broadcast storm."
  }' \
  "$BASE/api/v0/rules"
```

> O `builder` é o JSON do editor visual. O campo `query` (SQL) é gerado pelo
> LibreNMS a partir do builder. As métricas de porta ficam em `ports.*`
> (`ifInErrors_rate`, `ifOutErrors_rate`, `ifInOctets_rate`, `ifSpeed`, ...).

> [!IMPORTANT]
> **Atenção ao `builder`:** envie um **OBJETO JSON** (`{"condition":...}`), **não**
> uma string JSON. Se enviar string, a API salva *double-encoded* (`"\"{...}\""`)
> e a tela **/alert-rules quebra (HTTP 500 / "Whoops")** ao renderizar
> (`QueryBuilderParser: Argument #1 must be of type array, string given`).
> Correção: normalizar o `builder` para JSON puro (foi o que fizemos em
> 2026-09-23 para as regras 13/14/15).

---

## 2. Limitações (o que NÃO pega)

- **Broadcast/multicast por porta NÃO é coletado** por padrão (precisa habilitar
  OIDs `ifInBroadcastPkts`/`ifInMulticastPkts`, por vendor — Fase 2).
- **STP (topology change) e MAC flapping** não são nativos (Fase 3).
- As regras acima são **proxy** (erros/saturação), não diagnóstico.

---

## 3. Fase 2 — Broadcast/storm (opcional)

Habilitar coleta de contadores de broadcast nas interfaces (OIDs do `ifXTable`):

- `ifInBroadcastPkts`, `ifOutBroadcastPkts`, `ifInMulticastPkts`, `ifOutMulticastPkts`
- `ifInDiscards`, `ifOutDiscards`
- `ifInUnknownProtos`

Feito isso, criar uma regra com `ports.ifInBroadcastPkts_rate` alto (pico)
combinado com `port_up`. Exige validar por vendor (Comware/ProCurve/Dell/Aruba).

---

## 4. Fase 3 — Detector real: MAC flapping (esboço)

O sinal clássico de loop: **o mesmo MAC aprendido em portas diferentes** do mesmo
switch em poucos segundos. O LibreNMS não coleta isso — precisa consultar o switch.

### Fluxo proposto (script standalone, NÃO no Config Push)

```
[1] Ler a lista de switches (LibreNMS API /api/v0/devices?type=network)
        |
[2] Para cada switch, via SNMP:
        - BRIDGE-MIB:
            dot1dTpFdbAddress  (MAC)
            dot1dTpFdbPort     (bridge port index)
            dot1dBasePortIfIndex (port index -> ifIndex)
        - (opcional) Q-BRIDGE: dot1qTpFdbPort p/ VLANs
        |
[3] Montar mapa MAC -> ifIndex
[4] Coletar 2x (intervalo ~10s) e comparar:
        - mesmo MAC em ifIndex DIFERENTE entre as coletas => FLAPPING
        - (alternativa) mesmo MAC em 2 ifIndex no mesmo snapshot (anomalia)
        |
[5] Se detectado:
        - gerar alerta no LibreNMS:  POST /api/v0/alerts  (ou criar um "service")
        - (opcional) escrita de log + notificação (e-mail/webhook)
```

### Por que SNMP (e não Netmiko)

- Não precisa credencial SSH nem login interativo.
- Rápido e replicável em muitos switches.
- Compatível com Comware/ProCurve/Dell/Aruba (BRIDGE-MIB é padrão).

Para vendors que expõem melhor via CLI (`show mac address-table`), um fallback
via **Netmiko** pode ler o mesmo dado.

### Esboço do script (pseudo-Python)

```python
import threading, time
from pysnmp.hlapi import *

POLL_SECONDS = 10
FLAP_WINDOW  = 3   # quantas coletas com o MAC em portas diferentes = alerta

def read_bridge_macs(ip, community="monitoramentoti"):
    """Retorna {mac: ifindex} via BRIDGE-MIB."""
    macs = {}
    # dot1dTpFdbAddress (.1.3.6.1.2.1.17.4.3.1.1)
    # dot1dTpFdbPort    (.1.3.6.1.2.1.17.4.3.1.2)
    # dot1dBasePortIfIndex (.1.3.6.1.2.1.17.1.4.1.2)
    # ... snmpwalk + correlação ...
    return macs

def watch(switch_ip):
    history = {}   # mac -> [portas ao longo do tempo]
    while True:
        now = read_bridge_macs(switch_ip)
        for mac, port in now.items():
            h = history.setdefault(mac, [])
            h.append(port)
            h[:] = h[-FLAP_WINDOW:]
            if len(set(h)) > 1 and len(h) == FLAP_WINDOW:
                alert(switch_ip, mac, h)
        time.sleep(POLL_SECONDS)

def alert(switch_ip, mac, ports):
    # POST /api/v0/alerts (LibreNMS) ou webhook/e-mail
    print(f"[LOOP?] {switch_ip}: MAC {mac} oscilando entre portas {ports}")
```

### Onde hospedar

- **Não** no Config Push. Sugestão: um **container/stack próprio** (ex.:
  `ssu-loopwatch`) ou um script no `setup-ativos`/host, rodando por systemd/cron.
- Comunidade SNMP: as mesmas do LibreNMS (`monitoramentoti`, `unimedsc`, `public`).

### Alertas no LibreNMS a partir do script

- A API tem rotas de alerta (`/api/v0/alerts`), mas o fluxo mais simples é:
  **criar um "Service"** no LibreNMS (check de serviço) ou usar **webhook** do
  LibreNMS. Alternativa: mandar evento pro **Zabbix** (que já tem transporte).

---

## 5. Roadmap resumido

- [x] **Fase 1** — alert rules de sintoma (erros/saturação) — FEITO.
- [ ] **Fase 2** — coleta de broadcast/storm por porta (por vendor).
- [ ] **Fase 3** — MAC-flapping (BRIDGE-MIB + alerta) — esboço acima.
