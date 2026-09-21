# Changelog — Net Tools

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
