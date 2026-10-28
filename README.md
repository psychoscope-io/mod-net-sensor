# mod-net-sensor

Sensor de rede do Psychoscope em Rust: **Source → Decode → Sink**.

```
pcap (thread dedicada, nao bloqueante) ──mpsc──▶ decode (parsers puros) ──mpsc──▶ cliente IPC ──▶ core.sock
```

- **Source** (`src/capture/`): libpcap em thread própria; canal limitado — se o consumidor atrasa, o pacote é descartado e **contado** (nunca bloqueia nem cresce sem limite). Também lê `--pcap-file` (replay/testes, sem perdas).
- **Decode** (`src/protocols/`): Ethernet (+VLAN/QinQ), Linux cooked v1 e v2 (SLL, SLL2), loopback BSD (DLT_NULL/DLT_LOOP), IP puro, IPv4/IPv6 (extensões; fragmentos não iniciais são contados, não remontados), TCP, UDP, ICMP/ICMPv6, DNS (compressão segura, A/AAAA, rcode; nomes de até 253 caracteres) e TLS ClientHello (SNI, versão). Sem `unsafe`, toda leitura checada; entrada arbitrária nunca causa panic (testes proptest).
- **Sink** (`src/ipc/`): `Hello` com PID real (o Core confere via `SO_PEERCRED`), telemetria `EventoFluxoRede`, `StatusModulo` periódico (heartbeat; inclui memória, CPU e o detalhe das perdas, veja "Perdas e contadores"), comandos PAUSAR/RETOMAR/RECONFIGURAR (`bpf=`)/ENCERRAR com ACK/NACK e reconexão com backoff exponencial.

## Uso

```
mod-net-sensor -i eth0 [--bpf "udp port 53 or tcp port 443"] [--emit interesting|all]
mod-net-sensor --pcap-file captura.pcap [--exit-on-eof]
mod-net-sensor --list-interfaces                 # interfaces que dá para capturar
mod-net-sensor --check -i eth0                   # confere o ambiente e diz o que corrigir
mod-net-sensor --pcap-file captura.pcap --print  # eventos no terminal, sem o Core
```

Sob o supervisor do Core, `PSYCHOSCOPE_SOCKET` e `PSYCHOSCOPE_MODULE_ID` são definidos automaticamente.

| Opção | Padrão | O que faz |
|---|---|---|
| `-i`, `--interface <nome>` | | Captura ao vivo (exige `CAP_NET_RAW` e `CAP_NET_ADMIN`, veja "Privilégios"). |
| `--pcap-file <arquivo>` | | Lê um arquivo pcap/pcapng em vez de capturar (replay, testes), sem perdas. Exatamente uma fonte entre `-i` e `--pcap-file`. |
| `--bpf <filtro>` | nenhum | Filtro BPF (por exemplo `"udp port 53 or tcp port 443"`); pode ser trocado ao vivo pelo Core (`RECONFIGURAR`). |
| `--emit interesting\|all` | `interesting` | Quais pacotes viram evento (veja abaixo). |
| `--snaplen <bytes>` | 2048 | Bytes capturados por pacote (128 a 65535). |
| `--no-promisc` | desligado | Não usa o modo promíscuo. |
| `--queue-size <n>` | 8192 | Tamanho dos canais internos (16 a 1 000 000); excedentes são descartados e contados. `queue-size × snaplen` não pode passar de 256 MiB. |
| `--socket <caminho>` | `/var/run/psychoscope/core.sock` | Socket do Core (também `PSYCHOSCOPE_SOCKET`). |
| `--module-id <nome>` | `mod-net-sensor` | Identificador deste módulo (também `PSYCHOSCOPE_MODULE_ID`). |
| `--exit-on-eof` | desligado | Com `--pcap-file`: encerra depois de enviar tudo, em vez de ficar ocioso. |
| `--list-interfaces` | | Lista as interfaces (estado, tipo e endereços; as ativas com IPv4 primeiro) e sai. Só pode ser usado sozinho. |
| `--check` | | Confere fonte, filtro BPF (no tipo de enlace real da fonte, quando ela abre), permissão de captura, fila e destino dos eventos, mostra **como corrigir** cada problema e sai com 1 se algo falhar (avisos não contam). Não captura, não envia nada e não conecta no Core: só confere se o socket existe e se você pode escrever nele, para não deixar um "handshake falhou" no log. |
| `--print[=text\|json]` | | Imprime cada evento no stdout em vez de enviá-lo ao Core, que não precisa estar no ar. `text`: uma linha por evento; `json`: um objeto por linha, com os nomes de campo do contrato. Com `--pcap-file`, implica `--exit-on-eof`. |
| `-v`, `--verbose` | desligado | Uma linha de resumo a cada 10 s no stderr (pacotes/s, eventos/s, perdas). |

`--emit interesting` (padrão) gera evento para DNS, TLS ClientHello, TCP com SYN/RST e ICMP — o suficiente para as regras de DNS e de varredura; `all` emite todo pacote IP, inclusive os de protocolo de camada 4 desconhecido (`PROTO_DESCONHECIDO`).

### Diagnóstico e erros

`--check` roda as mesmas aberturas que a partida (interface, permissão, arquivo, filtro BPF) e explica cada falha:

```
[ok]      fonte: interface wlp2s0 (192.168.0.8, ...)
[falha]   captura: pcap: libpcap error: socket: Operation not permitted
         como corrigir: a captura exige CAP_NET_RAW e CAP_NET_ADMIN: uma vez, como administrador, rode `sudo setcap ...`
[aviso]   destino: sem socket do Core em /var/run/psychoscope/core.sock: ...
```

Os mesmos textos aparecem quando a partida falha: interface inexistente (com a lista das que existem), interface desativada, arquivo ausente ou que não é pcap, filtro BPF inválido, permissão e Core fora do ar.

### Ver os eventos sem o Core

```
mod-net-sensor --pcap-file captura.pcap --print
2023-11-14T22:13:20.000Z UDP 10.0.0.1:51000 -> 10.0.0.2:53 71B DNS consulta example.com tipo 1
2023-11-14T22:13:20.500Z TCP 10.0.0.1:52000 -> 10.0.0.2:443 571B [PSH,ACK] TLS ClientHello SNI secure.example.com versao TLS1.3
mod-net-sensor --pcap-file captura.pcap --print=json | jq .dns
```

Domínios e SNI vêm da rede e podem ser hostis: no modo texto, caracteres de controle viram `?`; no JSON, o escape é o do `serde_json`.

### Resumo ao encerrar, perdas e contadores

Ao sair, o sensor imprime no stderr um resumo (duração, pacotes e bytes, eventos entregues ou impressos, **perdas** e o que foi visto e ignorado). Perdas são dados que deviam ter sido processados e não foram; "ignorados" é tráfego que o sensor viu e decidiu não transformar em evento (política de emissão, ARP e afins). Um replay que termina sem nenhuma sessão com o Core avisa que os eventos não chegaram a lugar nenhum e sugere `--print`.

O `StatusModulo` leva os mesmos números no mapa `contadores` (chaves documentadas em `ipc.proto`; o Core aceita até 64 chaves de até 64 caracteres em `[a-z0-9._-]` e descarta o resto; o Core mostra as perdas na TUI e exporta `psychoscope_module_counter_total{module,counter}`):

| Chave | O que conta |
|---|---|
| `perda.kernel`, `perda.interface` | Pacotes que o kernel e a interface descartaram (`ps_drop`, `ps_ifdrop` do libpcap). |
| `perda.fila_captura` | Pacotes descartados porque a fila entre a captura e o decodificador encheu. |
| `perda.fila_eventos` | Eventos descartados porque a fila para o cliente IPC encheu. |
| `perda.ipc` | Eventos perdidos na reconexão com o Core ou numa falha de escrita no socket. |
| `decode.malformado`, `decode.nao_suportado` | Quadros truncados/malformados; quadros de protocolo não suportado (ARP e afins, ruído normal). |
| `ip.fragmento` | Fragmentos IP que não são o primeiro (não remontados). |
| `politica.filtrados` | Pacotes decodificados que a política de emissão não transformou em evento. |
| `remontagem.descartados` | ClientHellos fragmentados que a remontagem descartou sem completar. |

Limitações conhecidas: DNS sobre TCP só considera a primeira mensagem do segmento; DNS só é reconhecido na porta 53 (sem mDNS nem DoT); ClientHello só é remontado quando cabe num único registro TLS; sem QUIC/DoH, HTTP ou túneis (GRE, VXLAN); fragmentos IP não são remontados.

### Remontagem de ClientHello TLS

Clientes com chave pós-quântica passam de 1,4 KB e o SNI pode cair no segundo segmento TCP. `src/reassembly.rs` remonta o ClientHello antes de `build_event` (o formato do evento e o contrato IPC não mudam: continua um evento TLS por handshake, emitido quando o registro completa):

- só inicia buffer quando o primeiro segmento com payload de um fluxo abre um registro de handshake (`0x16 0x03 … 0x01`) que declara mais bytes do que o segmento traz — tráfego sem handshake não aloca nada;
- aceita apenas segmentos estritamente em ordem; lacuna, retransmissão, sobreposição, RST ou pacote truncado pelo snaplen descartam o fluxo (sem evento TLS para ele);
- limites: 18 KiB por fluxo, 4096 fluxos no total (despeja o mais antigo), **64 por IP de origem** (um host não esvazia a tabela dos demais; o excedente não é remontado e conta em `remontagem.descartados`) e TTL de 5 s medido no relógio dos pacotes (também vale ao ler `--pcap-file`). Ao vivo, a cada segundo o TTL também é conferido pelo relógio do sistema, para liberar a memória quando o tráfego para.

## Privilégios

Captura ao vivo exige `CAP_NET_RAW` + `CAP_NET_ADMIN` (ou root). Preferível a rodar como root:

```
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/mod-net-sensor
```

O Core (e o supervisor) seguem sem privilégios. Requer `libpcap-dev` para compilar e `libpcap` para executar.

Compilar: `make build` gera `dist/mod-net-sensor` (`cargo build --release --locked`). Para montar o ambiente inteiro (clonar os três repositórios, atualizar e compilar tudo em `dist/`), use `scripts/dev.sh` do repositório [.github](https://github.com/psychoscope-io/.github).

## Testar em minutos (demo)

`scripts/demo.sh` compila o Core e o sensor, sobe o daemon com um pcap sintético malicioso (sem privilégios e sem tocar na sua rede) e abre a TUI com 10 alertas para você explorar. Requer `go`, `cargo`, `python3` e `libpcap-dev`; se `../psychoscope-core` não existir, o Core é clonado em `~/.cache/psychoscope-demo` (ou aponte um checkout com `PSYCHOSCOPE_CORE`).

```
git clone https://github.com/psychoscope-io/mod-net-sensor && cd mod-net-sensor
scripts/demo.sh
```

Na TUI: `tab` alterna os painéis, `j`/`k` navegam, `p` pausa, `r` retoma e `x` encerra o módulo, `q` sai. O script imprime os comandos da CLI (`list`, `alerts --history`, `metrics`, `cmd`) para usar em outro terminal. O pcap é reproduzido uma vez; ao sair, o estado temporário é apagado.

## Testes

```
cargo test                    # unitários + proptest + mock do Core
scripts/demo.sh               # demo interativa: daemon + pcap sintético + TUI
scripts/e2e.sh                # daemon Go real + sensor (pcap sintético): 330 eventos, 10 alertas exatos, contadores, TUI em pty, comandos, SQLite, shutdown,
                              # `psychoscope-cli analyze` sobre o mesmo pcap e o catálogo de falsos positivos
scripts/analyze_fp.sh <cli> <sensor>  # só o catálogo: roda `analyze` em testdata/falsos-positivos/*.pcap e confere .esperado e .ajuste
make bench                    # benchmark do caminho quente (veja docs/DESEMPENHO.md)
scripts/live_smoke.sh         # captura AO VIVO em `lo` dentro de `unshare -Urn` (sem sudo)
scripts/bench_live.sh         # serviço inteiro sob carga crescente em `lo` (sem sudo): perdas, CPU e memória (veja docs/DESEMPENHO.md)
scripts/fuzz.sh [segundos]    # cargo-fuzz: roda cada alvo por N segundos (padrão 60); exige nightly
```

### Catálogo de casos (falsos e verdadeiros positivos)

Dois diretórios de pcaps **sintéticos** (só endereços de documentação, gerados por `scripts/gen_fp_pcap.py`; captura real nunca entra aqui):

- `testdata/falsos-positivos/`: o alerta é indevido. Hoje: `beacon-keepalive` (aplicativo que reabre a conexão a cada ~30 s), `nxdomain-srv-apt` (consultas SRV `_https._tcp.*`
  que dão NXDOMAIN, como o apt), `scan-web-navegador` (40 conexões na 443 com handshake completo) e `tls-sni-azure-blob` (rótulo de 20 letras sob um armazenamento de nuvem).
- `testdata/verdadeiros-positivos/`: o alerta **tem** de disparar, para que nenhum ajuste de limiar o perca: `scan-nmap-vertical`, `scan-horizontal-443` (150 hosts
  sem resposta) e `nxdomain-dga-com-srv` (DGA misturado a consultas SRV).

Ao lado de cada pcap: `<nome>.esperado` (regras que disparam com os limiares padrão, uma por linha; `#` abre comentário. Nos falsos positivos, uma regra listada é um caso
conhecido, mantido de propósito quando o sinal da regra não o separa do ataque; quando a regra passar a distingui-lo, o teste falha e o arquivo deve ser esvaziado) e,
opcionalmente, `<nome>.ajuste` (argumentos do `psychoscope-cli analyze`, um por linha, que silenciam o alerta). A receita para criar um caso novo está em
`psychoscope-core/docs/FALSOS-POSITIVOS.md`. O `analyze` precisa do `psychoscope-cli` da versão que tem o subcomando (e, para estes casos, da que tem os ajustes das regras).

### Fuzzing

O crate `fuzz/` (fora do workspace principal) tem cinco alvos do cargo-fuzz, todos com o contrato "nenhuma entrada causa panic": `decode_frame` (sequências de quadros de todos os `LinkType`, com a remontagem compartilhada, + geração do evento), `parse_dns`, `parse_client_hello`, `read_frame` (framer async e decodificação protobuf, em runtime tokio `current_thread`) e `reassembler` (sequências de segmentos; confere os limites de memória).

```
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked
scripts/fuzz.sh                     # 60 s por alvo
scripts/fuzz.sh 300 reassembler     # um alvo, 5 min
cargo +nightly fuzz run parse_dns   # interativo; crashes em fuzz/artifacts/<alvo>/
```

Precisa de `libpcap-dev` (ou `LIBPCAP_LIBDIR`, como acima). No CI, `.github/workflows/fuzz.yml` roda semanalmente (cron) e sob demanda (`workflow_dispatch`), 5 min por alvo, e publica os artefatos de crash.

Depende de `psychoscope-proto` via `git` + `tag = "v0.4.0"` (`Cargo.lock` fixa o commit). Antes da publicação (ou offline): `source ../psychoscope-proto/scripts/local-deps.sh` faz o Cargo buscar a tag no checkout local; os scripts `e2e.sh`/`live_smoke.sh` já fazem isso quando o repositório irmão existe. Para iterar no contrato sem criar tags, use `[patch]` em `.cargo/config.toml` (ignorado pelo git).
Se `libpcap-dev` não estiver instalado, mas a lib de runtime sim, crie um symlink `libpcap.so` num diretório qualquer e exporte `LIBPCAP_LIBDIR=<dir>` para linkar.

## Licença

Apache License 2.0 — veja [LICENSE](LICENSE).

## Releases e instalação

Cada tag `vX.Y.Z` (igual à versão do `Cargo.toml`) publica tarballs `linux/amd64` e `linux/arm64`, `SHA256SUMS` e atestado de
proveniência (`gh attestation verify <tarball> --repo psychoscope-io/mod-net-sensor`). O binário é compilado em Ubuntu 22.04
(glibc 2.35) e precisa de `libpcap0.8` em tempo de execução. A instalação como serviço (usuário dedicado, `setcap` e unit do
systemd) é feita pelo `get.sh` (baixa, confere e instala Core e sensor; depois, `psychoscope-update`) ou pelo `install.sh` do `psychoscope-core`: veja `docs/INSTALL.md` naquele repositório. Para criar a tag da próxima versão: `make tag` (`scripts/tag.sh`, só local; ajusta `Cargo.toml`/`Cargo.lock` e o push é seu).

