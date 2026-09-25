# Changelog — Net Tools

## v0.6.0 — 2026-09-25

**Templating de comandos com variáveis (Jinja)**
- Modelos aceitam `{{ ... }}` resolvido **por device** na execução (`name`/`hostname`,
  `ip`, `vendor`, `model`, `driver`, `protocol`, `port`, `site`, `site_role`, `tags`,
  `now`/`today`, `var.*`).
- **Variáveis globais e por site** (`var.*`) em Configurações (JSON
  `{"globals": {...}, "sites": {...}}`); site sobrescreve global.
- **StrictUndefined** (variável inexistente falha o device) e ambiente **sandbox**.
- **Prévia** do modelo na tela do snippet.

## v0.5.0 — 2026-09-25

**Backup oficial pelo rConfig**
- **Conector rConfig reescrito** com os endpoints reais (rConfig v8): inventário e
  resumo pela **v2** (`/api/v2/devices`, `/api/v2/devices/summary`), **versões** pela
  **v1** (`/api/v1/configs/all-by-deviceid/{id}`) e **disparo de coleta** pela **v1**
  (`/api/v1/download-now/{id}`); diff por `/api/v2/config-changes/by-config/{id}`.
- O app **não coleta** config: **exibe e dispara** no rConfig (quem executa é o rConfig);
  `last_config_id`/`last_config_at` sincronizados a partir do rConfig.
- **Correlação por IP**: o `external_id` guarda o id do inventário (LibreNMS), não o do
  rConfig — a correlação com o rConfig é pelo **IP** (fallback nome). Corrige o core
  (`external_id=2`) exibindo as versões do AGG.
- **Telas**: `Backups` (status por device + resumo do rConfig) e detalhe do device
  (versões + diff HTML), com **Backup agora** / **Backup de todos**.
- **API v1** de backups: `GET /api/v1/backups`, `GET /api/v1/backups/{id}`,
  `POST /api/v1/backups/{id}` (202) e `GET /api/v1/backups/{id}/config` (texto).
- **Ver/baixar a config completa**: a API v1 `all-by-deviceid` devolve o texto
  (campo `config`); a tela do device exibe a versão selecionada e
  `/backups/{id}/config.txt?version=` baixa o arquivo.
- **Segurança**: filtro dos campos sensíveis devolvidos pela API do rConfig
  (`device_password`, `device_enable_password`, `device_username`, `ssh_key_id`).

## v0.4.0 — 2026-09-21

**Papéis de equipamento + níveis de operador (alçada)**
- Campo **papel no site** no device: Acesso, TOR, Distribuição, Core, Firewall
  (vazio = não classificado). Filtro/ordenação/edição em massa por papel.
- Novos papéis de usuário: **Operador Básico / Médio / Avançado** (substituem o
  genérico `operator`; migração automática dos usuários existentes).
- **Alçada por hierarquia** (Core > Distribuição/TOR > Acesso; Firewall = avançado):
  - Básico → só Acesso · Médio → Acesso/TOR/Distribuição · Avançado → tudo.
  - **Fail-closed**: device sem papel só é alvo de Avançado/Admin.
- Enforcement no servidor em criação de execução, agendamentos, retry/rerun e no
  scheduler (revalida pelo papel atual de quem criou). Gestão de devices/modelos
  restrita a Avançado/Admin.
- **Devices**: engrenagem com **seletor de colunas** (Nome, IP, Vendor, Modelo,
  Driver, Protocolo, Porta, Usuário, Tags, Camada, Ativo), persistido no navegador.

## v0.3.0 — 2026-09-21

**Conformidade / Drift (Golden config)**
- Políticas de regras `require` / `forbid` / `regex`, com severidade (erro/aviso),
  alvo por vendor/driver/tag e/ou lista de devices.
- Execução assíncrona lendo a config ao vivo (Netmiko); resultados por device com
  **evidências** (linhas) e **drift** (mudança desde a última coleta) via snapshot
  Git interno. Telas de políticas, execuções e histórico por device.

**Integrações**
- **Conexões de API** (LibreNMS/rConfig) editáveis em **Configurações**: URL, token
  (cifrado em repouso) e validação de TLS, com **Testar** e fallback para `.env`.

## v0.2.0 — 2026-09-19

**Núcleo NCM**
- **Backups**: coleta de config por device, versionamento Git (`dulwich`), histórico,
  **diff** entre versões e relatório de cobertura (ok/falhou/atrasado/nunca).
- **Integração**: conectores **LibreNMS** (descoberta) e **rConfig** (inventário +
  status de backup + diff); sincronização de inventário com `source`/`external_id`;
  derivação de vendor/modelo a partir do `os` do LibreNMS.

**Experiência (Devices)**
- **Filtros por coluna** (busca, vendor, driver, protocolo, ativo).
- **Ordenação por coluna** (clique no cabeçalho, asc/desc).
- **Edição em massa** usando o escopo dos filtros (porta, protocolo, driver, tags,
  usuário, senha, enable, ativo).

## v0.1.0 — 2026-09-19

Primeira base do produto (derivada do motor interno de push + governança).

**Push / governança**
- Inventário (manual + import xlsx/CSV), busca, paginação, edição em massa (incl. usuário/senha).
- Modelos de comando, execução em lote, simulação (dry-run) e aplicação real com diff.
- Aprovação, agendamento, auditoria, RBAC, credencial padrão (TACACS/AAA).
- Multi-vendor: catalog `vendor/modelo -> driver`, autodetect (SSHDetect), suporte FortiOS.

**Backup / versionamento**
- Motor próprio de backup com Netmiko + versionamento Git (`dulwich`) por device.
- Histórico e diff entre versões.

**Plataforma**
- Tema escuro/claro/automático; i18n PT/EN/ES; webhook; `/healthz`.
- Conectores (opcionais) LibreNMS / Oxidized / rConfig (esqueleto).

**Pendências (roadmap)**
- Compliance/golden config e drift.
- API REST + tokens; SSO/2FA; trilha imutável.
- UI de Backup/Compliance; instalador Windows.
