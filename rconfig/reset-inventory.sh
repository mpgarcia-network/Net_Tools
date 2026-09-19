#!/bin/bash

# =============================================================================
# rConfig - Reset de inventario (configs + devices)
# =============================================================================
# APAGA:
#   - configs, config_changes, config_summaries (+ arquivos no storage)
#   - todos os devices e seus vinculos (categoria/tag/task/template/vendor)
#   - device_comments e tracked_jobs
#   - zera AUTO_INCREMENT (IDs comecam de 1)
#
# MANTEM: usuarios, settings, credenciais (device_credentials), templates,
#         vendors, categorias, tags, tasks e device_models.
#
# Ordem: os configs sao apagados via Eloquent (remove arquivo fisico + ajusta
# config_summaries); o resto por truncate. NAO e reversivel - faca backup antes.
#
# Uso (no host, como root, a partir de /opt/rconfig):
#   ./reset-inventory.sh            # dry-run (apenas mostra o que sera apagado)
#   ./reset-inventory.sh --yes      # executa
#   CONFIRM=yes ./reset-inventory.sh
# =============================================================================

set -euo pipefail

STACK_NAME="rconfig"
SERVICE_NAME="app"

DRY_RUN=1
if [ "${1:-}" = "--yes" ] || [ "${CONFIRM:-}" = "yes" ]; then
    DRY_RUN=0
fi

CID=$(docker ps -q -f name="${STACK_NAME}_${SERVICE_NAME}" | head -n 1)
if [ -z "$CID" ]; then
    echo "[ERRO] Container do app (${STACK_NAME}_${SERVICE_NAME}) nao encontrado neste no."
    exit 1
fi

if [ "$DRY_RUN" = "1" ]; then
    echo "[DRY-RUN] Nada sera apagado. Re rode com --yes para executar."
else
    echo "[ATENCAO] Reset IRREVERSIVEL de configs + devices. Backup ja feito?"
    echo "[INFO] Iniciando em $(date '+%Y-%m-%d %H:%M:%S') | container: ${CID}"
fi

docker exec -e "DRY_RUN=${DRY_RUN}" -i "$CID" php artisan tinker <<'PHP'
$dry = (getenv('DRY_RUN') === '1');

$tables = [
    'configs',
    'config_changes',
    'config_summaries',
    'device_comments',
    'category_device',
    'device_tag',
    'device_task',
    'device_template',
    'device_vendor',
    'tracked_jobs',
    'devices',
];

echo "=== antes ===\n";
foreach ($tables as $t) {
    printf("  %-20s %d\n", $t, \DB::table($t)->count());
}

if ($dry) {
    echo "modo dry-run: nada alterado.\n";
} else {
    // 1) Configs via Eloquent (dispara deleted -> remove arquivo + ajusta summaries)
    $deleted = 0;
    \App\Models\Config::pluck('id')
        ->chunk(500)
        ->each(function ($chunk) use (&$deleted) {
            foreach (\App\Models\Config::whereIn('id', $chunk)->get() as $config) {
                $config->delete();
                $deleted++;
            }
        });
    echo "configs_apagados={$deleted}\n";

    // 2) Truncate das demais (zera AUTO_INCREMENT)
    foreach ($tables as $t) {
        try {
            \DB::table($t)->truncate();
        } catch (\Throwable $e) {
            \DB::table($t)->delete();
            try { \DB::statement("ALTER TABLE `{$t}` AUTO_INCREMENT = 1"); } catch (\Throwable $e2) {}
        }
    }

    echo "=== depois ===\n";
    foreach ($tables as $t) {
        printf("  %-20s %d\n", $t, \DB::table($t)->count());
    }
}
PHP

if [ "$DRY_RUN" = "1" ]; then
    exit 0
fi

echo "[INFO] Removendo arquivos residuais do storage..."
docker exec "$CID" sh -c \
    'find /var/www/html/rconfig/storage/app/rconfig/data -mindepth 1 -delete 2>/dev/null; find /var/www/html/rconfig/storage/app/rconfig/tempdir -mindepth 1 -delete 2>/dev/null; true'

echo "[INFO] Recomputando config_summaries..."
docker exec "$CID" php artisan rconfig:config-summaries-sync || true

echo "[INFO] Reset concluido em $(date '+%Y-%m-%d %H:%M:%S')."
