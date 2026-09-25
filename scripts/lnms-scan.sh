#!/usr/bin/env bash
# Scan diario das redes de gerencia no LibreNMS (descobre switches novos).
# Roda DENTRO do container como usuario "librenms" (nunca root).
#
# Usa a lista de redes do proprio LibreNMS (config 'nets'): o comando
# 'lnms scan' sem argumentos varre as redes ali cadastradas. Assim, basta
# cadastrar uma net nova no LibreNMS (ou via scripts/setup-ativos.sh) que o
# scan do dia seguinte ja a inclui.
#
# Uso:
#   scripts/lnms-scan.sh
# Cron sugerido (host, root) - todo dia as 03:30:
#   30 3 * * * cd /caminho/Net_Tools && scripts/lnms-scan.sh
#
# Variaveis opcionais:
#   LNMS_CONTAINER  nome/id do container do LibreNMS (default: detecta)
#   LNMS_SCAN_LOG   caminho do log (default: /var/log/net-tools-lnms-scan.log)
set -uo pipefail

LOG="${LNMS_SCAN_LOG:-/var/log/net-tools-lnms-scan.log}"
LOCK="${LNMS_SCAN_LOCK:-/tmp/net-tools-lnms-scan.lock}"
TS=$(date '+%F %T')

# lock: evita dois scans simultaneos (cron + execucao manual)
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "$TS [SKIP] outro scan ja esta em execucao" >> "$LOG"
  exit 0
fi

# localiza o container do LibreNMS (docker compose do repo)
CID="${LNMS_CONTAINER:-}"
if [ -z "$CID" ]; then
  CID=$(docker ps -q -f name='^librenms$' | head -n1)
fi
if [ -z "$CID" ]; then
  CID=$(docker ps -q -f 'label=com.docker.compose.service=librenms' | head -n1)
fi
if [ -z "$CID" ]; then
  echo "$TS [ERRO] container do LibreNMS nao encontrado (suba a stack em librenms/)" >> "$LOG"
  exit 1
fi

# registra quais redes serao varridas neste ciclo
NETS=$(docker exec -u librenms "$CID" php /opt/librenms/lnms config:get nets 2>/dev/null | tr -d '\n ')

{
  echo "===== $TS scan iniciado (cid=$CID) ====="
  echo "nets: $NETS"
  docker exec -u librenms "$CID" php /opt/librenms/lnms scan --no-interaction
  echo "===== $(date '+%F %T') scan concluido (rc=$?) ====="
} >> "$LOG" 2>&1

tail -n 2000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
