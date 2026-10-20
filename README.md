# mod-net-sensor

Sensor de rede do Psychoscope em Rust: **Source → Decode → Sink**.

```
pcap (thread dedicada, nao bloqueante) ──mpsc──▶ decode (parsers puros) ──mpsc──▶ cliente IPC ──▶ core.sock
```

- **Source** (`src/capture/`): libpcap em thread própria; canal limitado — se o consumidor atrasa, o pacote é descartado e **contado** (nunca bloqueia nem cresce sem limite). Também lê `--pcap-file` (replay/testes, sem perdas).
- **Decode** (`src/protocols/`): Ethernet (+VLAN), Linux SLL, IP puro, IPv4/IPv6 (extensões, fragmentos), TCP, UDP, ICMP/ICMPv6, DNS (compressão segura, A/AAAA, rcode) e TLS ClientHello (SNI, versão). Sem `unsafe`, toda leitura checada; entrada arbitrária nunca causa panic (testes proptest).
- **Sink** (`src/ipc/`): `Hello` com PID real (o Core confere via `SO_PEERCRED`), telemetria `EventoFluxoRede`, `StatusModulo` periódico (heartbeat; inclui memória, CPU e descartes), comandos PAUSAR/RETOMAR/RECONFIGURAR (`bpf=`)/ENCERRAR com ACK/NACK e reconexão com backoff exponencial.

## Uso

```
mod-net-sensor -i eth0 [--bpf "udp port 53 or tcp port 443"] [--emit interesting|all]
mod-net-sensor --pcap-file captura.pcap [--exit-on-eof]
```

Sob o supervisor do Core, `PSYCHOSCOPE_SOCKET` e `PSYCHOSCOPE_MODULE_ID` são definidos automaticamente.

`--emit interesting` (padrão) gera evento para DNS, TLS ClientHello, TCP com SYN/RST e ICMP — o suficiente para as regras de DNS e de varredura; `all` emite todo pacote IP.

Limitações conhecidas: DNS sobre TCP só considera a primeira mensagem do segmento; ClientHello só é remontado quando cabe num único registro TLS; sem QUIC/DoH.

### Remontagem de ClientHello TLS

Clientes com chave pós-quântica passam de 1,4 KB e o SNI pode cair no segundo segmento TCP. `src/reassembly.rs` remonta o ClientHello antes de `build_event` (o formato do evento e o contrato IPC não mudam: continua um evento TLS por handshake, emitido quando o registro completa):

- só inicia buffer quando o primeiro segmento com payload de um fluxo abre um registro de handshake (`0x16 0x03 … 0x01`) que declara mais bytes do que o segmento traz — tráfego sem handshake não aloca nada;
- aceita apenas segmentos estritamente em ordem; lacuna, retransmissão, sobreposição, RST ou pacote truncado pelo snaplen descartam o fluxo (sem evento TLS para ele);
- limites: 18 KiB por fluxo, 4096 fluxos (despeja o mais antigo) e TTL de 5 s medido no relógio dos pacotes (também vale ao ler `--pcap-file`).

## Privilégios

Captura ao vivo exige `CAP_NET_RAW` + `CAP_NET_ADMIN` (ou root). Preferível a rodar como root:

```
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/mod-net-sensor
```

O Core (e o supervisor) seguem sem privilégios. Requer `libpcap-dev` para compilar e `libpcap` para executar.

## Testes

```
cargo test                    # unitários + proptest + mock do Core
scripts/e2e.sh                # daemon Go real + sensor (pcap sintético): 60 eventos, 3 alertas, TUI em pty, comandos, shutdown
scripts/live_smoke.sh         # captura AO VIVO em `lo` dentro de `unshare -Urn` (sem sudo)
scripts/fuzz.sh [segundos]    # cargo-fuzz: roda cada alvo por N segundos (padrão 60); exige nightly
```

### Fuzzing

O crate `fuzz/` (fora do workspace principal) tem cinco alvos do cargo-fuzz, todos com o contrato "nenhuma entrada causa panic": `decode_frame` (todos os `LinkType` + geração do evento), `parse_dns`, `parse_client_hello`, `read_frame` (framer async e decodificação protobuf, em runtime tokio `current_thread`) e `reassembler` (sequências de segmentos; confere os limites de memória).

```
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked
scripts/fuzz.sh                     # 60 s por alvo
scripts/fuzz.sh 300 reassembler     # um alvo, 5 min
cargo +nightly fuzz run parse_dns   # interativo; crashes em fuzz/artifacts/<alvo>/
```

Precisa de `libpcap-dev` (ou `LIBPCAP_LIBDIR`, como acima). No CI, `.github/workflows/fuzz.yml` roda semanalmente (cron) e sob demanda (`workflow_dispatch`), 5 min por alvo, e publica os artefatos de crash.

Depende de `psychoscope-proto` via `git` + `tag = "v0.1.0"` (`Cargo.lock` fixa o commit). Antes da publicação (ou offline): `source ../psychoscope-proto/scripts/local-deps.sh` faz o Cargo buscar a tag no checkout local; os scripts `e2e.sh`/`live_smoke.sh` já fazem isso quando o repositório irmão existe. Para iterar no contrato sem criar tags, use `[patch]` em `.cargo/config.toml` (ignorado pelo git).
Se `libpcap-dev` não estiver instalado, mas a lib de runtime sim, crie um symlink `libpcap.so` num diretório qualquer e exporte `LIBPCAP_LIBDIR=<dir>` para linkar.

## Licença

Apache License 2.0 — veja [LICENSE](LICENSE).

## Releases e instalação

Cada tag `vX.Y.Z` (igual à versão do `Cargo.toml`) publica tarballs `linux/amd64` e `linux/arm64`, `SHA256SUMS` e atestado de
proveniência (`gh attestation verify <tarball> --repo psychoscope-io/mod-net-sensor`). O binário é compilado em Ubuntu 22.04
(glibc 2.35) e precisa de `libpcap0.8` em tempo de execução. A instalação como serviço (usuário dedicado, `setcap` e unit do
systemd) é feita pelo `install.sh` do `psychoscope-core`: veja `docs/INSTALL.md` naquele repositório.

