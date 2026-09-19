# rConfig — Backup/versionamento de configuração de equipamentos 

Web app (Laravel/PHP) que coleta e **versiona as configurações** dos ativos de rede
(SSH/Telnet), com histórico, diff e agendamento — complementar ao Oxidized.
Roda como stack **Docker Swarm** no padrão Docker Swarm (`manager-docker.sh`): imagem
`rconfig/rconfig` (Core, multi-arquitetura) + MariaDB + Redis + **Nginx** (terminação TLS).

> **Versão rConfig:** este é o template rConfig (`stacks/rconfig`), **sem vínculo** com o
> repositório upstream `rconfig/rconfig8coredocker`. O `.git` do upstream foi removido.

---

## 📦 O que esta stack entrega (estado atual)

- **Swarm** com 4 serviços: `nginx`, `app`, `db` (MariaDB 10.11), `redis`.
- **HTTPS** terminando no Nginx (`8443`) e HTTP (`8088`) redirecionando para HTTPS.
  O app **não publica porta** — só o Nginx.
- **Keep Unchanged Config** (tipo Oxidized): não grava arquivo/registro quando a config
  não muda (patch em `patch/SaveConfigsToDiskAndDb.php`, ligado por `RCONFIG_KEEP_UNCHANGED`).
- **Retenção** de 3 meses via `purge-old-configs.sh` (cron mensal).
- **Reset de inventário** via `reset-inventory.sh` (configs + devices, zerando IDs).
- **Templates do GitHub** funcionando pela UI (import do catálogo `rconfig/rConfig-templates`).
- **Log Viewer** (`/log-viewer`) funcionando (hosts de acesso em `SANCTUM_STATEFUL_DOMAINS`).
- **MariaDB em bind path** no host (`data/mariadb`) → backup/restore direto.
- Rotina pós-upgrade: `php artisan rconfig:set-config-permissions` (>= 8.2.14).

> Recursos **Pro** (não existem no Core): retenção nativa na UI, `HARD_LINK`, "Keep Unchanged"
> nativo. Esta stack implementa equivalentes próprios (acima).

---

## 🚀 Deploy do zero — cliente novo

> Para uso em campo, há uma folha de checagem curta: [`CHECKLIST-DEPLOY.md`](CHECKLIST-DEPLOY.md).

### TL;DR

```bash
cd /opt/rconfig
./manager-docker.sh init-env          # gera .env com senhas de banco aleatórias
$EDITOR .env                          # APP_URL + hosts stateful + TIMEZONE (ver Passo 2)
./manager-docker.sh start
./manager-docker.sh status            # 4 serviços 1/1
curl -k -s -o /dev/null -w '%{http_code}\n' https://localhost:8443/   # 302
./manager-docker.sh console
php artisan v8core:install            # 1ª instalação (banco vazio)
```

### Pré-requisitos
- Docker Swarm ativo no host (`docker swarm init`).
- Repo rConfig clonado em `/opt/rconfig` (ou esta pasta copiada).
- Portas livres: HTTPS `8443` e HTTP `8088` (configuráveis via `.env`).
- (Opcional, p/ templates) saída de internet do container para `github.com`.

### Passo 1 — Gerar o `.env`
```bash
cd /opt/rconfig
./manager-docker.sh init-env     # cria .env do .env.example + senhas aleatórias
```
> `init-env` é para **instalação nova**. Não rode em banco existente (troca as senhas).

### Passo 2 — Ajustar o `.env` do cliente (obrigatório)
Edite estas chaves (o resto fica no padrão):

| Chave | O que pôr |
|-------|-----------|
| `APP_URL` | URL de acesso: `https://<IP-do-host>:8443` |
| `SANCTUM_STATEFUL_DOMAINS` | hosts:porta de acesso, ex.: `192.168.100.241:8443,100.120.0.41:8443,localhost:8443` |
| `LOG_VIEWER_API_STATEFUL_DOMAINS` | idem acima (necessário p/ o `/log-viewer`) |
| `SWARM_NODE_CONSTRAINT` | hostname do nó (deixe `` p/ resolver automático) |
| `TIMEZONE` | fuso do cliente (ex.: `America/Sao_Paulo`) |
| `RCONFIG_HTTPS_PORT` / `RCONFIG_HTTP_PORT` | portas publicadas, se quiser mudar (padrão `8443`/`8088`) |

### Passo 3 — Subir a stack
```bash
./manager-docker.sh start
```
O `start` faz: gera `.env` (se faltar) → resolve `SWARM_NODE_CONSTRAINT` para o hostname
→ garante o datadir do MariaDB e os diretórios do Nginx (**gera TLS self-signed** se
`nginx/ssl` estiver vazio) → valida o patch → cria a rede overlay `rconfig-net`
(`10.192.200.0/24`) → `docker stack deploy rconfig`.

### Passo 4 — Validar
```bash
./manager-docker.sh status       # nginx, app, db, redis = 1/1
curl -k -s -o /dev/null -w '%{http_code}\n' https://localhost:8443/   # 302 (login)
```
Web UI: `https://<IP-do-host>:8443` (o `:8088` redireciona para HTTPS).

### Passo 5 — Primeiro acesso (instalação do app)
Na 1ª instalação (banco vazio):
```bash
./manager-docker.sh console
php artisan v8core:install
```
O entrypoint já gera `APP_KEY` e roda as migrações no start; com banco instalado, só aplica migrações novas.

### Passo 6 — TLS com os IPs corretos
O `start` gera self-signed sem SAN. Para o navegador aceitar LAN **e** Tailscale:
```bash
cd /opt/rconfig/nginx/ssl
rm -f rconfig.crt rconfig.key
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout rconfig.key -out rconfig.crt \
  -subj "/C=BR/O=rConfig/CN=rconfig" \
  -addext "subjectAltName=IP:<IP-LAN>,IP:<IP-TAILSCALE>,DNS:localhost"
chmod 600 rconfig.key; chmod 644 rconfig.crt
docker service update --force rconfig_nginx
```
> Certificado de CA (Let's Encrypt/interna): substitua os arquivos mantendo os nomes.

### Passo 7 — Pós-deploy (opcional)
- **Retenção** (cron mensal, dia 1 às 04:00):
  ```bash
  0 4 1 * * cd /opt/rconfig && ./purge-old-configs.sh >> /var/log/rconfig-purge.log 2>&1
  ```
- **Templates do GitHub**: UI → **Templates → Import from GitHub** (baixa o catálogo) →
  reabra o diálogo e escolha **Vendor** → template. (Após o import, dê um Ctrl+F5 se o
  dropdown não atualizar.)
- **Keep Unchanged** já vem ativo; nada a fazer.

---

## 🛠️ Operação (manager)

| Comando | O que faz |
|---------|-----------|
| `./manager-docker.sh start` | Garante `.env`/rede/nginx/patch e sobe a stack |
| `./manager-docker.sh stop` | Remove a stack (volumes e rede preservados) |
| `./manager-docker.sh restart` | Remove, aguarda 10s e sobe de novo |
| `./manager-docker.sh status` | Status dos serviços |
| `./manager-docker.sh logs` | Logs do app (follow) |
| `./manager-docker.sh console` | Terminal dentro do container do app |
| `./manager-docker.sh init-env` | (Re)cria `.env` com senhas novas (confirmar) |
| `./manager-docker.sh update` | Atualiza o app para a imagem de `RCONFIG_VERSION` |

### Atualização de versão
1. **Backup antes** (ver seção Backups): dump do MariaDB + cópia do `.env`.
2. Em `.env`, mude `RCONFIG_VERSION` para a nova tag (ex.: `8.2.17`).
3. `./manager-docker.sh update` — recria o task do app; o entrypoint aplica as migrações.
4. **Upgrades que passam pela 8.2.14** (ex.: `8.2.7 → 8.2.17`): rode uma vez, no container:
   ```bash
   ./manager-docker.sh console
   php artisan rconfig:set-config-permissions   # aceita --dry-run
   ```
5. **Revalide o patch** `patch/SaveConfigsToDiskAndDb.php` contra o arquivo da nova
   versão (ou desligue com `RCONFIG_KEEP_UNCHANGED=false`).
6. Valide: `./manager-docker.sh status` (4/4) e `curl -k ... https://localhost:8443/` → `302`.

---

## 🧬 Keep Unchanged Config (gravar só quando mudar)

O Core não tem isso nativo (é Pro). A stack aplica um patch que dá o comportamento do
Oxidized: se a config baixada — já **descontando as exclusões de diff** (`Diff exclusions`)
e normalização — for idêntica à última, **não cria arquivo nem registro** em `configs`.

- `patch/SaveConfigsToDiskAndDb.php` sobrescreve a classe do Core via **bind mount**
  (`docker-compose.yml`, sem imagem própria).
- Ligado por padrão: `RCONFIG_KEEP_UNCHANGED=true` (use `false` para o original).
- Compara `sha1` do conteúdo limpo — o mesmo critério do `Config Compare` nativo.
- No Application Log aparece `Config unchanged - skipped saving (Keep Unchanged Config)`.

```bash
# aplica/atualiza o patch
./manager-docker.sh restart      # ou: docker service update --force rconfig_app
docker exec $(docker ps -q -f name=rconfig_app | head -n1) \
  php -l /var/www/html/rconfig/app/CustomClasses/SaveConfigsToDiskAndDb.php
```

> ⚠️ O patch é baseado na **8.2.17**. Em update da imagem, compare o arquivo do novo
> release e revalide (ou desligue o patch).

---

## 🧹 Retenção de configs (purge mensal)

Mantém **3 meses** de histórico e apaga o mais antigo, **preservando sempre a última
versão** (`latest_version=1`) de cada device/comando. Apaga via Eloquent dentro do
container: remove os **arquivos** e recalcula as contagens (`config_summaries`).

```bash
./purge-old-configs.sh                 # 3 meses
RETENTION_MONTHS=6 ./purge-old-configs.sh
```

Cron mensal no host (dia 1, 04:00):
```bash
0 4 1 * * cd /opt/rconfig && ./purge-old-configs.sh >> /var/log/rconfig-purge.log 2>&1
```

> Referência de volume: ~24 KB/coleta × 2/dia × 100 switches ≈ **144 MB/mês**. Com o
> Keep Unchanged, só coletas que mudam consomem espaço.

---

## ♻️ Reset de inventário

Zera **configs + devices** (com vínculos e IDs) mantendo usuários, settings, credenciais,
templates, vendors, categorias, tags e tasks.

```bash
./reset-inventory.sh          # dry-run (só mostra o que será apagado)
./reset-inventory.sh --yes    # executa
```
Recria as contagens ao final (`rconfig:config-summaries-sync`).

---

## 📥 Templates do GitHub

O botão **Templates → Import from GitHub** roda `rconfig:clone-templates`, que faz
`git clone https://github.com/rconfig/rConfig-templates.git` **de dentro do container**
para `storage/app/rconfig/templates/rConfig-templates`. Depois, escolha **Vendor** e o
`.yml` no diálogo para importar de fato (o botão sozinho só baixa o catálogo).

Diagnóstico (precisa de saída p/ GitHub):
```bash
CID=$(docker ps -q -f name=rconfig_app | head -n1)
docker exec "$CID" git ls-remote https://github.com/rconfig/rConfig-templates.git
```

Sem egress — clonar no host e copiar pro volume:
```bash
git clone --depth 1 https://github.com/rconfig/rConfig-templates.git /tmp/rConfig-templates
docker run --rm -v rconfig_storage_data:/s -v /tmp/rConfig-templates:/src alpine \
  sh -c 'mkdir -p /s/app/rconfig/templates/rConfig-templates && cp -a /src/. /s/app/rconfig/templates/rConfig-templates/'
docker exec $(docker ps -q -f name=rconfig_app | head -n1) \
  chown -R www-data:www-data /var/www/html/rconfig/storage/app/rconfig/templates
```
> Não clique em "Import from GitHub" depois disso (ele apaga a pasta e tenta clonar).

---

## 📜 Log Viewer (`/log-viewer`)

O viewer usa `Auth::check()` e só recebe a sessão de hosts **stateful**. Se você acessa por
um IP que não está em `SANCTUM_STATEFUL_DOMAINS` / `LOG_VIEWER_API_STATEFUL_DOMAINS`, a API
retorna `403` e "No log files were found". Inclua LAN **e** Tailscale, **com a porta**
(ex.: `100.120.0.41:8443`), e recrie o app:
```bash
docker service update --force rconfig_app
```
O aviso "Front-end assets are outdated" é cosmético (assets vêm do `vendor/`).

---

## 💾 Backups

- **MariaDB**: bind path em `stacks/rconfig/data/mariadb` (dono `999:999`) — backup/restore
  direto (rsync/tar da pasta).
- **Redis e storage do app**: volumes nomeados `rconfig_redis_data` e
  `rconfig_storage_data` (configs coletadas, chaves, logs, clone de templates).
- **`.env`**: guarda `APP_KEY` e senhas do banco — sem ele a app não sobe e os dados
  encriptados não descriptografam. **Fazer backup junto.**
- **Nginx/TLS**: config em `nginx/conf.d/default.conf` (versionada); certificados
  `nginx/ssl/rconfig.crt|.key` (não versionados).
- Dump do banco:
  ```bash
  docker exec $(docker ps -q -f name=rconfig_db) sh -c \
    "mysqldump -uroot -p\$MYSQL_ROOT_PASSWORD rconfig" > backup_$(date +%Y%m%d).sql
  ```

---

## 🔐 Segurança / o que NÃO se versiona

- `.env` (gitignored) contém senhas do MariaDB e `APP_KEY` — nunca commit.
- `nginx/ssl/` (gitignored) contém certificado e **chave privada TLS** — nunca commit.
- `data/` (gitignored) contém o datadir do MariaDB e configs coletadas.
- O app **não publica porta**; o único acesso é pelo Nginx (rede overlay).
- O MariaDB **não é publicado** no host. Para expor temporariamente:
  `docker service update --publish-add published=3307,target=3306 rconfig_db`.
- Diferença vs. upstream: sem `container_name`, sem `depends_on` (o entrypoint aguarda o DB),
  sem `restart:` (usado `deploy.restart_policy`), logs limitados a `10m×3`.

---

## 🧯 Troubleshooting / gotchas

| Sintoma | Causa / solução |
|---------|-----------------|
| **Quick Peek / ver config dá erro** | Arquivo criado por `docker exec` (root) fica ilegível p/ o Apache. Coletas normais (worker=`www-data`) não têm isso. Manual: `docker exec -u www-data ...`; ou `docker exec <app> chown -R www-data:www-data storage/app/rconfig/data` |
| **`/log-viewer` → 403** | Host de acesso fora de `SANCTUM_STATEFUL_DOMAINS`/`LOG_VIEWER_API_STATEFUL_DOMAINS` (com porta). Ver seção Log Viewer |
| **Templates "não vem nenhum"** | Catálogo não clonado (sem egress) **ou** UI não atualizada. Ctrl+F5 e escolha o Vendor; ver seção Templates |
| **`HARD_LINK=true` no `.env`** | Não faz nada no Core — ignore/remova |
| **Configs crescendo todo dia** | Keep Unchanged desligado? `RCONFIG_KEEP_UNCHANGED=true` + restart. Ver seção |
| **Porta ocupada** | Ajuste `RCONFIG_HTTPS_PORT`/`RCONFIG_HTTP_PORT` no `.env` e `start` |
| **Update travado em "No such image"** | Evite `docker system prune` durante convergência |

---

## ⚙️ Variáveis principais (`.env`)

| Variável | Uso | Padrão |
|----------|-----|--------|
| `RCONFIG_VERSION` | Tag da imagem do app | `8.2.17` |
| `RCONFIG_HTTPS_PORT` / `RCONFIG_HTTP_PORT` | Portas publicadas pelo Nginx (HTTPS/HTTP) | `8443` / `8088` |
| `APP_URL` | URL de acesso (edit por cliente) | `https://localhost:8443` |
| `APP_FORCE_HTTPS` / `TRUSTED_PROXIES` | Operação atrás de reverse proxy | `true` / `*` |
| `SANCTUM_STATEFUL_DOMAINS` / `LOG_VIEWER_API_STATEFUL_DOMAINS` | Hosts:porta de acesso (Log Viewer/Sanctum) | `localhost:8443` |
| `RCONFIG_NGINX_CONF_PATH` / `RCONFIG_NGINX_SSL_PATH` | Config/TLS do Nginx (relativo → absoluto no manager) | `./nginx/conf.d` / `./nginx/ssl` |
| `RCONFIG_KEEP_UNCHANGED` | Só grava config quando mudar (patch tipo Oxidized) | `true` |
| `RCONFIG_PATCH_PATH` | Caminho do patch montado sobre a classe do Core | `./patch/SaveConfigsToDiskAndDb.php` |
| `SWARM_NODE_CONSTRAINT` | Hostname do nó Swarm | `` |
| `DB_DATABASE` / `DB_USERNAME` / `DB_PASSWORD` | Banco do rConfig | `rconfig` / `rconfig_user` / gerado |
| `MYSQL_ROOT_PASSWORD` | Senha root do MariaDB | gerado |
| `TIMEZONE` | Fuso do cliente | `America/Sao_Paulo` |
| `MAIL_*` | SMTP p/ notificações (padrão log) | — |
| `RCONFIG_API_TOKEN` | Token da API do rConfig | `V8Core` |
