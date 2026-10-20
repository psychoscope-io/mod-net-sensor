<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Git e publicação

- **Nunca** faça push, tag, merge, release, criação de repositório, mudança de configuração da organização ou de escopo de token sem pedido explícito. Prepare tudo e entregue os comandos.
- **Commits:** identidade do dono (configuração local do repositório, e-mail noreply do GitHub), **sem trailers de IA**. Uma unidade lógica por commit, e cada commit compila e passa nos testes.
- **Mensagens seguem o [Conventional Commits](https://www.conventionalcommits.org/pt-br/v1.0.0/):** `tipo(escopo): descrição`, com tipo em `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`; `!` marca mudança incompatível. Cabeçalho em português, no imperativo, em minúscula, sem ponto final, com até 72 caracteres (o validador aceita até 100); o corpo, separado por uma linha em branco, explica o porquê. `scripts/check-commit-msg.sh` valida (hook `commit-msg`, `pre-push` e CI).
- **`git add` com caminhos explícitos** quando houver trabalho de outras pessoas ou sessões na árvore; nunca `git add -A` às cegas.
- **Histórico publicado é imutável:** não reescreva e não mova tags. Antes de publicar a reescrita é aceitável, mas refaça os pins: a tag do `psychoscope-proto`, o `go.sum` do core e o `Cargo.lock` do sensor.
- **Tag local só por necessidade técnica** (por exemplo, calcular o `go.sum`), e sempre avisando o dono.
- **Antes de publicar,** confira: `git grep` por e-mail pessoal, caminhos absolutos do usuário (diretório pessoal) e segredos; autor e committer de todos os commits; árvore limpa.
- **Ordem de publicação:** `psychoscope-proto` (branch e tag) → `psychoscope-core` → `mod-net-sensor` → `.github`.
