# LibreNMS — Scan agendado (descoberta de switches novos)

> O LibreNMS **não** descobre device novo sozinho se não houver redes
> (`nets`) configuradas nem um scan recorrente. Este doc cobre o **scan diário**
> automatizado no host `.41` (vmssuproxy).

## Como funciona

- Script: **`/opt/ssu/.ssu-scripts/lnms-scan.sh`** (versionado em `.ssu-scripts/`).
- Cron (host, root): **`30 3 * * *`** → roda todo dia às **03:30**.
- Log: **`/opt/ssu/scripts/lnms-scan.log`** (mantém as últimas 2000 linhas).

O script:
1. Usa um **lock** (`flock`) para nunca rodar dois scans ao mesmo tempo.
2. Lê a lista de **`nets` do próprio LibreNMS** (`lnms config:get nets`).
3. Roda `lnms scan` **sem argumentos** — varre as redes cadastradas.
4. Roda o scan **como usuário `librenms`** (nunca root).

> **Regra de ouro:** cadastrar uma net nova no LibreNMS já a inclui no scan do
> dia seguinte — **não precisa editar o script**.

## Scan "now" (manual)

**Todas as redes registradas:**
```bash
/opt/ssu/.ssu-scripts/lnms-scan.sh
```

**Uma rede específica:**
```bash
cid=$(docker ps -q -f name=ssu-librenms_librenms | head -n1)
docker exec -u librenms "$cid" php /opt/librenms/lnms scan 10.172.92.0/24 --no-interaction
```

**Forçar descoberta de topologia (LLDP) agora** (o `setup-ativos.sh` já tem):
```bash
/opt/ssu/.ssu-scripts/setup-ativos.sh topology
```

Ou, pelo assistente completo (communities, redes, scan, topologia):
```bash
/opt/ssu/.ssu-scripts/setup-ativos.sh          # menu
/opt/ssu/.ssu-scripts/setup-ativos.sh scan "10.172.92.0/24"
```

## Cadastrar / editar as redes (`nets`)

Pelo assistente (`setup-ativos.sh` → menu de **Redes**) ou via comando oficial:

```bash
# a forma CORRETA (o comando oficial cuida do formato):
cid=$(docker ps -q -f name=ssu-librenms_librenms | head -n1)
docker exec -u librenms "$cid" php /opt/librenms/lnms config:set nets.0 "10.172.19.0/24"
docker exec -u librenms "$cid" php /opt/librenms/lnms config:set nets.1 "10.174.102.0/24"
# ...
docker exec -u librenms "$cid" php /opt/librenms/lnms config:get nets   # confere
```

> [!WARNING]
> **NÃO** edite a tabela `config` (SQL) na mão. Se gravar o `nets` direto no
> banco, o `config:get` / `lnms scan` **não leem** e o scan reclama de
> "Network is required". Use sempre `lnms config:set`.

## Observações

- Community SNMP: as mesmas do LibreNMS no `config:get snmp`
  (`public`, `monitoramentoti`, `unimedsc`). Switch com community diferente não
  é adicionado — cadastre manualmente.
- O scan completo de ~11 redes `/24` leva ~15–20 min (rodando de madrugada).
- Alternativa de ferramenta: `snmp-scan.py` (usado pelo `setup-ativos.sh`).
