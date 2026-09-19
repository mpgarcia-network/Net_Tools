#!/bin/bash

# =============================================================================
# rConfig - Purge de configs antigas (retencao)
# =============================================================================
# Mantem N meses de historico (padrao 3) e apaga o que for mais antigo,
# preservando SEMPRE a versao mais recente (latest_version=1) de cada
# device/comando.
#
# O Core nao tem retencao nativa (recurso do rConfig V8 Pro); por isso este
# script roda fora da UI. Ele apaga via Eloquent dentro do container do app:
# o evento `deleted` do model Config remove o arquivo fisico e ajusta a
# `config_summaries`. Ao final roda rconfig:config-summaries-sync para
# recomputar as contagens.
#
# Uso (no host, como root):
#   ./purge-old-configs.sh                 # 3 meses
#   RETENTION_MONTHS=6 ./purge-old-configs.sh
#
# Cron mensal (dia 1 as 04:00):
#   0 4 1 * * cd /opt/rconfig && ./purge-old-configs.sh >> /var/log/rconfig-purge.log 2>&1
# =============================================================================

set -euo pipefail

STACK_NAME="rconfig"
SERVICE_NAME="app"
RETENTION_MONTHS="${RETENTION_MONTHS:-3}"

CID=$(docker ps -q -f name="${STACK_NAME}_${SERVICE_NAME}" | head -n 1)
if [ -z "$CID" ]; then
    echo "[ERRO] Container do app (${STACK_NAME}_${SERVICE_NAME}) nao encontrado neste no."
    exit 1
fi

echo "[INFO] Purge iniciado $(date '+%Y-%m-%d %H:%M:%S') | retencao: ${RETENTION_MONTHS} mes(es) | container: ${CID}"

docker exec -e "RETENTION_MONTHS=${RETENTION_MONTHS}" -i "$CID" php artisan tinker <<'PHP'
$months = (int) (getenv('RETENTION_MONTHS') ?: 3);
$cutoff = now()->subMonths($months);

$ids = \App\Models\Config::query()
    ->where('latest_version', '!=', 1)
    ->where('created_at', '<', $cutoff)
    ->pluck('id')
    ->all();

if (empty($ids)) {
    echo "nothing_to_purge cutoff={$cutoff}\n";
} else {
    $changes = \App\Models\ConfigChange::query()
        ->whereIn('current_config_id', $ids)
        ->orWhereIn('previous_config_id', $ids)
        ->delete();

    $deleted = 0;
    foreach (array_chunk($ids, 500) as $chunk) {
        foreach (\App\Models\Config::whereIn('id', $chunk)->get() as $config) {
            $config->delete();
            $deleted++;
        }
    }

    echo "purged_configs={$deleted} purged_changes={$changes} cutoff={$cutoff}\n";
}
PHP

echo "[INFO] Recomputando config_summaries..."
docker exec "$CID" php artisan rconfig:config-summaries-sync

echo "[INFO] Purge concluido $(date '+%Y-%m-%d %H:%M:%S')."
