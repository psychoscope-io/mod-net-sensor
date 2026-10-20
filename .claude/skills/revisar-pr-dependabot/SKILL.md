---
name: revisar-pr-dependabot
description: Revisar e preparar a aprovação das PRs abertas do Dependabot nos repositórios do Psychoscope. Use quando o usuário pedir para aprovar, aceitar ou mergear PRs do Dependabot.
---
<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Revisar PRs do Dependabot

1. **Listar** (somente leitura), com o estado do CI:
   `gh pr list -R psychoscope-io/<repo> --json number,title,reviewDecision,statusCheckRollup`
2. **Para cada PR:**
   - CI verde? Se falhar, leia o log (`gh run view <id> --log-failed`) e separe: falha *causada* pela mudança (não aprove) de falha que já existia (corrija no `main` primeiro e peça `@dependabot rebase`).
   - Leia as notas de versão no corpo da PR: mudança incompatível, runtime exigido, comportamento padrão alterado.
   - **Qual workflow muda?** Se só `release.yml`, o CI da PR não o exercita; diga isso e acompanhe o primeiro release.
   - Atualização de dependência que quebra o build (ex.: `charmbracelet/x/ansi` com o Bubble Tea v1): não aprove e adicione `ignore` no `dependabot.yml`, com o motivo em comentário.
3. **Aprovar** só o que passou: `gh pr review <n> -R <repo> --approve`. Aprovar não mergeia.
4. **Mergear** é do dono; entregue o comando (`gh pr merge <n> -R <repo> --squash --delete-branch`). Se aparecer "refusing ... without `workflow` scope", ele precisa rodar `gh auth refresh -h github.com -s workflow`.
5. Depois dos merges: confira o CI do `main` e rode `git pull --ff-only origin main` nos clones locais.
