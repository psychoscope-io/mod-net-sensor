---
name: publicar-versao
description: Preparar a publicação de uma versão (tags e releases) dos repositórios do Psychoscope, sem publicar. Use quando o usuário pedir para publicar, lançar, taguear ou preparar um release.
---
<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Preparar uma publicação

Você prepara e verifica; **o dono executa os pushes e as tags** (veja `git-e-publicacao.md`).

1. **Pré-voo em cada repositório:** árvore limpa; testes e linters verdes (inclusive com a toolchain mais nova); `git grep` por e-mail pessoal, caminhos absolutos do usuário e segredos; autor e committer de todos os commits conferidos.
2. **Contrato mudou?** Ordem: proto (`make check`, `buf breaking` contra a última tag) → tag anotada → core (`go get ...@vX.Y.Z`, `go.sum`) → sensor (tag e `Cargo.lock`). Teste os consumidores sem `go.work`/`[patch]` e com o `local-deps.sh`.
3. **Integração:** `scripts/e2e.sh` e `scripts/live_smoke.sh` do `mod-net-sensor`, com `GOWORK=off`.
4. **Versões:** a tag do sensor deve coincidir com `version` do `Cargo.toml`; o core recebe a versão por `-ldflags` a partir da tag. Tag `vX.Y.Z` dispara `release.yml` (tarballs amd64/arm64, `SHA256SUMS`, atestado de proveniência).
5. **Entregue** a lista de comandos na ordem (`git push origin main vX.Y.Z` por repositório, proto primeiro), dizendo o que *não* foi verificado (Actions, arm64, systemd, `setcap`).
6. **Depois do push do dono:** `gh run list/view` (somente leitura) para conferir os workflows; se o release falhar, leia o log e corrija com uma versão de patch. **Nunca mova nem recrie a tag publicada.**
