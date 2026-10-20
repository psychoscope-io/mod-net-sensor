---
name: verificar-sensor
description: Rodar a verificação completa do mod-net-sensor antes de entregar uma mudança, incluindo o clippy da toolchain estável mais nova. Use ao terminar qualquer alteração no sensor.
---
# Verificar o sensor

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

**Toolchain mais nova (o que o CI usa).** Instale uma estável isolada, sem tocar no `rustup` do usuário:

```bash
export RUSTUP_HOME=$(mktemp -d) CARGO_HOME=$(mktemp -d) CARGO_TARGET_DIR=$(mktemp -d)
curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal -c clippy -c rustfmt
PATH=$CARGO_HOME/bin:$PATH cargo clippy --locked --all-targets -- -D warnings
```

Integração (exige `../psychoscope-core`; antes de a tag do proto existir no GitHub, o script já usa `local-deps.sh`):

```bash
scripts/e2e.sh && scripts/live_smoke.sh
scripts/fuzz.sh 30          # se tocou em parsers ou na remontagem
```

No relatório final, diga o que rodou e o que **não** pôde rodar (GitHub Actions, arm64, fuzz longo).
