<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Organização do código

Meta: quem chega agora sabe por onde começar.

- **`AGENTS.md` é o mapa.** Ao criar, mover ou remover pacote ou módulo, atualize a seção "Estrutura" no mesmo commit.
- **Cada diretório tem um propósito de uma frase,** escrito no comentário do pacote (Go) ou no `//!` do módulo (Rust).
- **Um conceito por arquivo,** nomeado pelo conceito (`net_scan.go`, `reassembly.rs`), nunca pelo tipo (`models`, `types`, `utils`).
- **Tamanho como sinal de alerta, não como lei:** função com mais de ~50 linhas, arquivo com mais de ~400 ou pacote com mais de um motivo para mudar pedem divisão. Divida num commit próprio logo após a funcionalidade, antes de crescer mais.
- **Grafo de dependências raso e sem ciclos.** Se um pacote precisa importar "para cima", falta uma interface.
- **Pontos de extensão têm um modelo a copiar e uma skill** (nova regra, novo decoder, evolução do contrato). Criou um tipo novo de extensão? Escreva a skill.
- **Comentário de contrato em todo símbolo público:** o que faz, o que assume, o que devolve em erro; invariantes não óbvios (concorrência, ordem, limites) escritos onde vivem.
- **Sem código morto,** código comentado nem TODO sem dono: apague, o git lembra.
