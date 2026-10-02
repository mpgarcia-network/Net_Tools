#!/bin/bash
# Aplica os templates custom SSU ao rConfig em execucao:
#   1) copia os YAML de ./templates para o storage do container app;
#   2) registra/atualiza a tabela `templates` do DB (idempotente).
#
# Uso:  ./seed-templates.sh
set -e
cd "$(dirname "$0")"

APP=$(docker ps -qf name=ssu-rconfig_app)
if [ -z "$APP" ]; then
  echo "ERRO: container rconfig app nao encontrado" >&2
  exit 1
fi

for f in templates/*.yml; do
  docker cp "$f" "$APP:/var/www/html/rconfig/storage/app/rconfig/templates/$(basename "$f")"
  echo "copiado $(basename "$f")"
done

docker cp seed-templates.php "$APP:/tmp/seed-templates.php"
docker exec "$APP" php /tmp/seed-templates.php
