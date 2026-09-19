# Net Tools

Coleção de ferramentas de rede (NCM, backup/versionamento e monitoramento),
cada uma em sua pasta, com deploy Docker Swarm padronizado.

| Ferramenta | Pasta | O que é |
|---|---|---|
| **Config Push** | [`config_push/`](config_push/) | Gestão de configuração (push, dry-run/diff, aprovação, agendamento, auditoria, RBAC, backup/versionamento próprio) |
| **rConfig** | [`rconfig/`](rconfig/) | Coleta e versionamento de configuração (deploy Swarm + patch "keep unchanged" + retenção) |
| **LibreNMS** | [`librenms/`](librenms/) | Monitoramento/descoberta (SNMP) e inventário |

Cada pasta é **autônoma** (tem seu `docker-compose.yml`, `manager-docker.sh`,
`.env.example` e `README.md`). Sobe-se só o que o cliente precisa.

## Uso geral

```bash
cd <ferramenta>
./manager-docker.sh init-env
./manager-docker.sh start
./manager-docker.sh status
```

## Licença / dependências de terceiros

- O código deste repositório é proprietário — ver [`LICENSE`](LICENSE).
- Pastas `rconfig/` e `librenms/` referenciam projetos de terceiros (imagens
  oficiais). Revise as licenças desses projetos antes de distribuir/comercializar
  (ver `rconfig/NOTICE.md`).
