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

Limitações conhecidas: ClientHello fragmentado em vários segmentos TCP não é reconstruído; DNS sobre TCP só considera a primeira mensagem do segmento; sem QUIC/DoH.

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
```

`Cargo.toml` usa `path` para `../psychoscope-proto/rust` durante o desenvolvimento; trocar por `git` + `tag` antes de publicar.
Se `libpcap-dev` não estiver instalado, mas a lib de runtime sim, crie um symlink `libpcap.so` num diretório qualquer e exporte `LIBPCAP_LIBDIR=<dir>` para linkar.
