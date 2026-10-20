---
name: refatorar-sem-quebrar
description: Reorganizar código existente (dividir função, mover responsabilidade, simplificar) sem mudar comportamento. Use quando o usuário pedir refatoração ou limpeza, ou quando uma mudança exigir reorganizar antes.
---
<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Refatorar sem quebrar

1. **Um objetivo por refatoração** (por exemplo: tirar a leitura de configuração de dentro do motor). Outro problema descoberto no caminho vira anotação para o dono, não parte desta mudança.
2. **Rede de segurança primeiro.** Rode os testes e confirme que estão verdes. Se a área não tem teste, escreva antes testes de caracterização do comportamento *atual*.
3. **Passos pequenos,** testando a cada passo. Commit próprio (`refactor: ...`), separado de qualquer mudança de comportamento.
4. **Não mude ao mesmo tempo** API pública, contrato, formato de saída, mensagens de erro ou configuração. Se isso for necessário, é outra mudança, com seu próprio pedido.
5. **Cheque se melhorou de verdade:** menos imports cruzados, funções e arquivos menores, nomes mais claros, menos estado compartilhado. "Mais abstrato" não é melhoria.
6. **Feche o ciclo:** atualize a seção "Estrutura" do `AGENTS.md` se o mapa mudou e rode a skill `verificar-*` do repositório.
