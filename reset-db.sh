#!/bin/bash

# =============================================================================
# SSU Config Push - Zera o banco da aplicacao (reset total)
# =============================================================================
# Remove: devices, snippets, execucoes, run_targets, agendamentos, usuarios,
# auditoria, settings e os logos enviados (media/). O admin e recriado a partir
# do .env (ADMIN_USER/ADMIN_PASSWORD) no proximo start.
#
# Uso (no host, como root, no diretorio da stack):
#   ./reset-db.sh          # dry-run (so mostra o que sera apagado)
#   ./reset-db.sh --yes    # executa
#   CONFIRM=yes ./reset-db.sh
# =============================================================================

set -euo pipefail

STACK="ssu-configpush"
SERVICE="configpush"
VOLUME="${STACK}_${SERVICE}_data"

RUN=1
if [ "${1:-}" != "--yes" ] && [ "${CONFIRM:-}" != "yes" ]; then
    RUN=0
fi

cd "$(dirname "$0")"

CID=$(docker ps -q -f name="${STACK}_${SERVICE}" | head -n 1)

if [ "$RUN" = "0" ]; then
    echo "[DRY-RUN] Isto apaga TODO o /data da aplicacao (banco + logos)."
    if [ -n "$CID" ]; then
        echo "Container: $CID"
        docker exec "$CID" sh -c 'echo "--- /data ---"; ls -la /data 2>/dev/null; echo "--- banco ---"; ls -l /data/configpush.db 2>/dev/null' || true
    fi
    echo "Re rode com --yes para executar."
    exit 0
fi

if [ -z "$CID" ]; then
    echo "[ERRO] Container do app (${STACK}_${SERVICE}) nao encontrado."
    exit 1
fi

B="/root/ssu-configpush-db-backup-$(date +%Y%m%d%H%M%S)"
mkdir -p "$B"
echo "[INFO] Backup do volume em $B ..."
docker run --rm -v "${VOLUME}":/data -v "$B":/b alpine \
    sh -c 'tar czf /b/data.tgz -C /data . 2>/dev/null || true'
ls -lh "$B"

echo "[INFO] Parando o app..."
docker service scale "${STACK}_${SERVICE}"=0 >/dev/null
for i in $(seq 1 30); do
    [ -z "$(docker ps -q -f name=${STACK}_${SERVICE})" ] && break
    sleep 2
done

echo "[INFO] Zerando /data (banco + logos)..."
docker run --rm -v "${VOLUME}":/data alpine sh -c \
    'rm -rf /data/* /data/.[!.]* 2>/dev/null; mkdir -p /data/media; true'

echo "[INFO] Subindo o app (recria schema + admin do .env)..."
docker service scale "${STACK}_${SERVICE}"=1 >/dev/null

echo "[INFO] Aguardando..."
for i in $(seq 1 30); do
    [ "$(docker service ls --filter name=${STACK}_${SERVICE} --format '{{.Replicas}}')" = "1/1" ] && break
    sleep 3
done

echo "[INFO] Reset concluido. Backup em $B"
