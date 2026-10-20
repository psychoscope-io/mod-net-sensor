# AGENTS.md — mod-net-sensor

Sensor de rede do Psychoscope em Rust: **Source → Decode → Sink**. Captura pacotes (libpcap ou arquivo pcap), decodifica e envia eventos ao Core por socket Unix.

## Estrutura

- `src/capture/`: libpcap em thread dedicada (modo não bloqueante + `poll`) e leitura de pcap; canal limitado, descarte contado.
- `src/protocols/`: parsers **puros** (ethernet, ip, tcp, udp, icmp, dns, tls) sobre `reader::Reader`; `decode_frame` percorre L2→L4.
- `src/reassembly.rs`: remontagem estrita de ClientHello TLS em vários segmentos. `src/event.rs`: pacote → `EventoFluxoRede` (política `interesting`: DNS, ClientHello, TCP SYN/RST, ICMP; `all` emite tudo).
- `src/pipeline.rs`: `decode_loop` e `SensorController`. `src/ipc/`: framer e cliente (Hello, reconexão com backoff, status, comandos).
- `fuzz/` (cargo-fuzz), `scripts/` (`e2e.sh`, `live_smoke.sh`, `fuzz.sh`, `gen_pcap.py`).

## Comandos

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
scripts/e2e.sh          # daemon Go real + pcap sintético; exige ../psychoscope-core
scripts/live_smoke.sh   # captura ao vivo em `lo` dentro de `unshare -Urn`
scripts/fuzz.sh 30      # exige nightly e cargo-fuzz
```

Requer `libpcap-dev`. O proto vem por `git` + `tag` (`Cargo.lock` fixa o commit); antes de a tag existir no GitHub: `source ../psychoscope-proto/scripts/local-deps.sh`.

## Regras e skills

Regras (`.claude/rules/`): as oito compartilhadas (`fluxo-de-trabalho`, `principios-de-design`, `organizacao-do-codigo`, `testes-e-verificacao`, `git-e-publicacao`, `seguranca`, `contrato-proto`, `estilo-e-idioma`) e `rust`, `protocolos` (deste repositório).
Skills (`.claude/skills/`): `adicionar-decoder-de-protocolo`, `verificar-sensor`, `refatorar-sem-quebrar`, `revisar-pr-dependabot`, `publicar-versao`.

## Armadilhas conhecidas

- O CI usa o clippy **mais novo**; um lint novo já quebrou a build. Reproduza com uma toolchain estável isolada.
- `immediate_mode` do libpcap pode ignorar o timeout de leitura: a thread de captura usa modo não bloqueante + `poll` para enxergar o `stop`.
- O processo sai com `std::process::exit` após o encerramento ordenado, para uma tarefa presa não impedir o shutdown.
- A tag `vX.Y.Z` tem de coincidir com `version` do `Cargo.toml` (o `release.yml` confere).
