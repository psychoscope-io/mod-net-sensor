<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Testes e verificação

- **Não diga "pronto" sem executar.** Rode build, lint/vet, testes (com `-race` em Go) e, ao mexer em IPC, protocolo, regras ou sensor, os testes de integração do repositório do sensor (`scripts/e2e.sh`, `scripts/live_smoke.sh`).
- **Todo teste novo cobre** o caminho feliz, o erro e a entrada hostil ou malformada. Regra de detecção traz casos de falso positivo.
- **Limiar e heurística:** prove que o teste "morde" alterando o limiar e vendo o teste falhar.
- **Bug corrigido nasce de um teste que o reproduz.**
- **Reproduza o CI.** Ele usa as ferramentas mais novas (clippy, Go). Instale a toolchain estável mais recente isolada (diretórios temporários), sem alterar a do usuário.
- **Testes herméticos:** caminhos explícitos em diretório temporário, sem depender de HOME, rede, root ou do que existe na máquina. Esperas por condição (`eventually`), não por `sleep` fixo.
- **Declare o que não foi verificado:** GitHub Actions, systemd real, capabilities ambientes, runners arm64, qualquer coisa que exija root.
- **Nunca enfraqueça uma verificação** (teste, lint, limite) para fazer algo passar; corrija a causa.
