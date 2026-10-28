# AGENTS.md — mod-net-sensor

Sensor de rede do Psychoscope em Rust: **Source → Decode → Sink**. Captura pacotes (libpcap ou arquivo pcap), decodifica e envia eventos ao Core por socket Unix.

## Estrutura

- `src/capture/`: libpcap em thread dedicada (modo não bloqueante + `poll`) e leitura de pcap; canal limitado, descarte contado.
- `src/protocols/`: parsers **puros** (ethernet, ip, tcp, udp, icmp, dns, tls) sobre `reader::Reader`; `decode_frame` percorre L2→L4.
- `src/reassembly.rs`: remontagem estrita de ClientHello TLS em vários segmentos. `src/event.rs`: pacote → `EventoFluxoRede` (política `interesting`: DNS, ClientHello, TCP SYN/RST, ICMP; `all` emite tudo).
- `src/pipeline.rs`: `decode_loop` (estado em `Decoder`, expiração ociosa da remontagem ao vivo) e `SensorController` (contadores no `StatsSnapshot`). `src/ipc/`: `framer.rs` e `client.rs` (Hello, reconexão com backoff, status, comandos), com o contrato `Controller`/`StatsSnapshot` em `client/controller.rs`. `src/main.rs` só liga as etapas (captura, decode, destino Core ou `--print`, sinais, resumo, encerramento).
- Diagnóstico e uso: `src/interfaces.rs` (`--list-interfaces`), `src/check.rs` (`--check`), `src/explain.rs` (erros → instruções, funções puras), `src/output.rs` (`--print`, texto e JSON), `src/summary.rs` (resumo final e de `-v`). `benches/hot_path.rs` + `make bench` medem o caminho quente (`docs/DESEMPENHO.md`).
- Testes dos módulos grandes ficam ao lado, em `<modulo>/tests.rs` (`ipc/client`, `reassembly`, `capture/sniffer`).
- `fuzz/` (cargo-fuzz), `scripts/` (`demo.sh`, `e2e.sh`, `live_smoke.sh`, `fuzz.sh`, `gen_pcap.py`, `gen_fp_pcap.py`, `analyze_fp.sh`; `lib/build.sh` é o prólogo comum de demo, e2e e live_smoke: PATH do Go, local-deps, busca e build do Core; `tag.sh` é cópia compartilhada). `testdata/falsos-positivos/` é o catálogo de falsos positivos: pcaps SINTÉTICOS (só endereços de documentação) com `<nome>.esperado` (regras que ainda disparam com os limiares padrão) e `<nome>.ajuste` (argumentos do `psychoscope-cli analyze` que devem silenciá-los); `analyze_fp.sh` confere tudo e o `e2e.sh` o chama. Pcap de captura real nunca entra no repositório.

## Comandos

```bash
make hooks              # uma vez por clone: ativa commit-msg, pre-commit e pre-push
make check              # o que o CI roda: fmt, clippy -D warnings, shellcheck, actionlint, cargo deny, cargo test
make build              # dist/mod-net-sensor (release, --locked)
make tag                # scripts/tag.sh: sobe a versão do Cargo.toml/Cargo.lock, commit de versão e tag anotada (local; o push é seu)
scripts/demo.sh         # demo interativa para quem vai testar (clona o core se faltar); não faz parte do CI
scripts/e2e.sh          # daemon Go real + pcap sintético (inclui `psychoscope-cli analyze` e o catálogo de falsos positivos); exige ../psychoscope-core
scripts/live_smoke.sh   # captura ao vivo em `lo` dentro de `unshare -Urn`
scripts/fuzz.sh 30      # exige nightly e cargo-fuzz
```

Requer `libpcap-dev`. Ferramentas fora do `Cargo.toml`: `cargo-deny` (`cargo install cargo-deny --locked`), `shellcheck` e `actionlint`; `deny.toml` define licenças e origens permitidas. O proto vem por `git` + `tag` (`Cargo.lock` fixa o commit); antes de a tag existir no GitHub: `source ../psychoscope-proto/scripts/local-deps.sh`.

## Regras e skills

Regras (`.claude/rules/`): as oito compartilhadas (`fluxo-de-trabalho`, `principios-de-design`, `organizacao-do-codigo`, `testes-e-verificacao`, `git-e-publicacao`, `seguranca`, `contrato-proto`, `estilo-e-idioma`) e `rust`, `protocolos` (deste repositório).
Skills (`.claude/skills/`): `adicionar-decoder-de-protocolo`, `verificar-sensor`, `refatorar-sem-quebrar`, `revisar-pr-dependabot`, `publicar-versao`.

## Armadilhas conhecidas

- O CI usa o clippy **mais novo**; um lint novo já quebrou a build. Reproduza com uma toolchain estável isolada.
- `immediate_mode` do libpcap pode ignorar o timeout de leitura: a thread de captura usa modo não bloqueante + `poll` para enxergar o `stop`.
- O processo sai com `std::process::exit` após o encerramento ordenado, para uma tarefa presa não impedir o shutdown.
- A tag `vX.Y.Z` tem de coincidir com `version` do `Cargo.toml` (o `release.yml` confere).
