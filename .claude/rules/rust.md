---
paths:
  - "**/*.rs"
---
# Regras de Rust

- Prefira tipos e funções livres a hierarquias; `trait` só com mais de uma implementação real ou fronteira de teste (como `Controller`). Módulos pequenos, com `pub` mínimo e `//!` dizendo o propósito; as peças são conectadas em `main.rs`.
- Sem `unsafe`, salvo FFI mínima (`libc::poll`, `sysconf`) com comentário `SAFETY:` justificando o invariante.
- Nada de `unwrap`/`expect`/indexação que possa entrar em pânico em caminho alimentado por dados externos; use `Option`/`Result` e o `Reader` com limites.
- Erros de biblioteca com `thiserror`; mensagens em português e acionáveis.
- Leituras assíncronas que não são cancel-safe (framer) rodam em task própria, nunca dentro de `select!`.
- A thread de captura nunca bloqueia nem acumula memória sem limite: canal limitado, descarte contado e exposto no `StatusModulo`.
- `cargo fmt` e `clippy -D warnings` limpos na toolchain do projeto **e** na estável mais nova.
- Dependência nova com justificativa; `Cargo.lock` sempre commitado e `--locked` no CI.
