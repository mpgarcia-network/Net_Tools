# LibreNMS (deploy)

Stack de deploy do **LibreNMS** baseada no compose oficial
(https://github.com/librenms/docker), adaptada ao padrão Net Tools:
`docker compose`, variáveis em `.env`, sem segredos fixos.

Serviços: `db` (MariaDB), `redis`, `msmtpd` (relay de e-mail), `librenms` e
`dispatcher`.

## Quickstart

```bash
cd librenms
./manager-docker.sh init-env   # cria .env (gera MYSQL_PASSWORD), librenms.env, msmtpd.env
./manager-docker.sh start
./manager-docker.sh status
```

Acesse `http://<host>:${APP_PORT:-8001}`. No primeiro acesso o LibreNMS pede
para criar o usuário admin.

> Dados persistem em `./data/` (banco e `/data` do app). O manager ajusta o
> dono das pastas (`data/db` -> 999; `data/librenms` -> PUID:PGID).

## Comandos do manager

| Comando | Ação |
|---|---|
| `start` / `stop` / `restart` | sobe/derruba a stack |
| `status` | status dos containers |
| `logs` | logs (follow) |
| `pull` | puxa imagem nova e sobe (upgrade) |
| `console` | shell no container do LibreNMS |
| `init-env` | (re)cria os arquivos de ambiente |

## Variáveis

- `.env`: `TZ`, `PUID`, `PGID`, `APP_PORT`, `MYSQL_DATABASE/USER/PASSWORD`.
- `librenms.env`: opções do app (cache/sessão em Redis, etc.).
- `msmtpd.env`: SMTP para alertas por e-mail.

## Integração com o Config Push

O Config Push consome o inventário via API (conector opcional):

- `LIBRENMS_URL` (ex.: `http://<host>:8001`)
- `LIBRENMS_TOKEN` (X-Auth-Token, gerado em *Settings → API*)

## Opcional

O compose oficial traz também sidecars de **syslog-ng** (514) e **snmptrapd**
(162). Se precisar, adicione os serviços ao `compose.yml` (ver o exemplo
oficial).

## Licença

Imagem oficial: MIT (repo `librenms/docker`). Projeto LibreNMS: GPLv3. Este
diretório contém apenas arquivos de deploy (nenhum código do LibreNMS).
