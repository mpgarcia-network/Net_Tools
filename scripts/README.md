# scripts/ — operação do LibreNMS (Net Tools)

Scripts de apoio à **descoberta** de ativos no LibreNMS. Rodam no **host** (não
dentro do container) e falam com o container via `docker exec`.

Pré-requisitos: `docker` e `python3` (para manipular os arrays JSON).

| Script | Para que serve |
|---|---|
| `setup-ativos.sh` | Assistente: communities SNMP, redes (`nets`), scan (`snmp-scan.py`) e descoberta de topologia (LLDP). |
| `lnms-scan.sh` | Scan diário das redes cadastradas (`lnms scan`), com lock. Para agendar no cron. |

## Uso rápido

```bash
# assistente interativo (communities / redes / scan / topologia)
scripts/setup-ativos.sh

# scan de uma rede específica
scripts/setup-ativos.sh scan "10.0.120.0/24"

# scan de todas as redes registradas (o mesmo que o cron roda)
scripts/lnms-scan.sh
```

## Cron sugerido (host, root) — 03:30

```cron
30 3 * * * cd /caminho/do/Net_Tools && scripts/lnms-scan.sh
```

## Como funciona a descoberta

1. Cadastre as **communities SNMP** e as **redes** no LibreNMS (`setup-ativos.sh`).
2. O scan varre as redes e adiciona os switches descobertos.
3. A comunidade precisa bater com a do equipamento (ex.: `public`,
   `monitoramentoti`, `unimedsc` — ajuste às suas).

## Detecção de container

Os scripts detectam o container do LibreNMS automaticamente (nome `librenms` do
`docker compose`, ou o label `com.docker.compose.service=librenms`). Dá para
sobrescrever com `LNMS_CONTAINER=<container>`. O log do scan fica em
`/var/log/net-tools-lnms-scan.log` (`LNMS_SCAN_LOG`).

> Docs relacionados: `librenms/LIBRENMS_SCAN_AGENDADO.md`,
> `librenms/LIBRENMS_TOPOLOGIA_GRUPOS_MAPS.md`, `librenms/LIBRENMS_ALERTAS_LOOP.md`.
