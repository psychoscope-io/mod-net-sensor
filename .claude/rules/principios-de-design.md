<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Princípios de design

Código que qualquer pessoa consiga ler, mudar e testar sem conhecer o resto. Em caso de conflito, vence o mais simples.

- **KISS.** A solução mais simples que atende o requisito de hoje e os testes. Sem generalidade "para o futuro" (YAGNI): nenhum parâmetro, interface, flag, camada ou opção de configuração que ninguém usa agora.
- **Uma responsabilidade por unidade** (pacote, tipo, função). Se a descrição precisa de "e", divida. Aqui: decoders só transformam bytes em valores, o motor só roteia eventos, as regras só decidem, o armazenamento só persiste, `app` só monta.
- **Separe decisão de I/O.** Lógica de decisão não abre socket, arquivo nem lê o relógio: recebe isso por parâmetro (tempo do evento, `io.Reader`, interface pequena). É o que permite testar sem mocks pesados.
- **Dependências apontam para dentro.** Domínio (regras, parsers) não importa infraestrutura (IPC, SQLite, TUI). Camadas externas dependem de interfaces pequenas, definidas por quem as consome (`ctl.Backend`, `ipc.Handler`, `Controller`).
- **Um ponto de composição.** Quem conecta as peças é `internal/app` (Go) e `main.rs` (Rust); o resto recebe o que precisa. Sem estado global mutável e sem singletons.
- **DRY com bom senso.** Abstraia na terceira repetição, e só se as cópias mudam pelo mesmo motivo. Duplicação pequena e óbvia custa menos que a abstração errada.
- **Explícito acima de implícito.** Sem reflexão, macros ou `init()` com efeito colateral quando código direto resolve. Exceção justificada: `overlayStruct`, que concentra a validação estrita da configuração em um só lugar.
- **Falhe cedo e alto.** Valide na fronteira e devolva erros com contexto; nunca ignore um erro nem engula um pânico.
- **Otimize com medição.** Primeiro clareza; desempenho só onde um benchmark ou métrica mostrar o gargalo, com o número na mensagem do commit.
- **Nomes dizem o que é.** Sem `util`, `helper`, `manager`, `common`, `data`; sem abreviação obscura.
