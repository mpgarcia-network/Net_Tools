# LibreNMS (integração)

Não mantemos um stack do LibreNMS neste repositório — usamos o **projeto
oficial**: https://github.com/librenms/librenms (imagem `librenms/librenms`).

O **Config Push** se integra ao LibreNMS via **API**, como conector opcional
(descoberta/inventário):

- Variáveis de ambiente (no `.env` do `config_push`):
  - `LIBRENMS_URL` — ex.: `http://librenms:8000`
  - `LIBRENMS_TOKEN` — token de API (X-Auth-Token)
- Código: `config_push/app/connectors/librenms.py`
- Uso: importar devices (nome/IP/vendor/modelo/OS) e alimentar o inventário.

> Licença: LibreNMS é um projeto de terceiros (**GPLv3**). Não embutimos nem
> derivamos o código dele no produto; apenas consumimos a API.
