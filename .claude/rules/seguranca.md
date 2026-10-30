<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Segurança (invariantes do produto)

O Psychoscope é uma ferramenta de segurança: estas regras não se negociam por conveniência.

- **Menor privilégio.** O Core roda sem capabilities; só o sensor recebe `CAP_NET_RAW`/`CAP_NET_ADMIN` (como `AmbientCapabilities` da unit própria do sensor, com usuário dedicado; nunca `setcap`, que o systemd 252 anula, nem `NoNewPrivileges=no` na unit do Core). Não amplie.
- **Identidade vem do kernel.** Módulos são autenticados por `SO_PEERCRED` (UID e PID); nunca confie em campo autodeclarado. Na dúvida, recuse (fail closed).
- **Entrada externa é hostil** (pacotes, mensagens IPC, arquivos de configuração): valide limites *antes* de alocar (framing de no máximo 1 MiB), sem `panic`, sem `unsafe` nos decoders; todo parser tem teste de propriedade e alvo de fuzz.
- **Permissões:** sockets `0660` ou `0600`, banco de alertas `0600`, diretórios `0750`. Endpoint sem autenticação só em loopback.
- **Configuração estrita:** campo desconhecido é erro, com a lista dos válidos. Falhar na partida com mensagem acionável é melhor que degradar em silêncio.
- **Erros para clientes não vazam detalhes internos** (caminhos, SQL, stack); o detalhe vai para o log.
- **Dependência nova exige justificativa:** prefira a biblioteca padrão, fixe a versão (`go.sum`, `Cargo.lock`) e prefira Go e Rust puros a CGO.
- **Sem segredos nem dados pessoais** em código, testes, logs ou fixtures.
