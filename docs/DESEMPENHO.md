# Desempenho do caminho quente

Como medir e a linha de base de cada mudança de desempenho. Regra do projeto: otimização só com número.

## Como medir

```bash
make bench
```

Gera `target/bench.pcap` (`scripts/gen_pcap.py --repeat 30 --filler 2000`: ~70 mil pacotes, dos quais ~9,9 mil viram evento na política `interesting`) e roda `benches/hot_path.rs`:

- `decode_event`: `decode_frame` + `build_event_reassembling` sobre todos os quadros (sem canal).
- `decode_loop`: o laço real com canal de entrada, canal de eventos e consumidor (inclui a cópia do quadro, como a captura faz).
- `ipc_write`: 4096 eventos de telemetria escritos num socket Unix real (um leitor descarta o que chega): `um_frame_por_escrita` (`write_message`) e `lote_de_16`/`lote_de_64` (`append_frame` + uma escrita por lote, como o cliente IPC envia).
- Antes da medição de tempo, o benchmark imprime as alocações por pacote (alocador global de contagem, só no benchmark).

Outro pcap: `BENCH_PCAP=/caminho/arquivo.pcap cargo bench --bench hot_path`. Os tempos variam entre execuções (±10%); compare sempre na mesma máquina e com ela ociosa.

## Linha de base (v0.2.1, 2026-10-23)

Máquina de desenvolvimento (laptop), `cargo bench` com `lto = "thin"`.

| Cenário | Política | Tempo (70 020 pacotes) | Vazão | Alocações/pacote |
|---|---|---|---|---|
| `decode_event` | `interesting` | 33,8 ms | 2,07 Mpacotes/s | 3,20 (35 bytes) |
| `decode_event` | `all` | 31,1 ms | 2,25 Mpacotes/s | 3,20 (35 bytes) |
| `decode_loop` | `interesting` | 66,6 ms | 1,05 Mpacotes/s | n/d |
| `decode_loop` | `all` | 91,4 ms | 0,77 Mpacotes/s | n/d |

Leitura: a política `interesting` aloca o mesmo que `all`, porque o evento (com as duas `String` de IP) é montado antes de decidir se é descartado; ~86% dos pacotes do pcap são descartados. A escrita IPC não existia no benchmark: a medição antes da otimização foi de 7,2 ms para 4096 eventos (570 mil eventos/s, um frame por escrita).

## Depois das otimizações (v0.3.0, 2026-10-23)

Mesma máquina e mesmo pcap.

| Cenário | Política | Tempo | Vazão | Alocações/pacote | Mudança |
|---|---|---|---|---|---|
| `decode_event` | `interesting` | 8,4 ms (70 020 pacotes) | 8,4 Mpacotes/s | 0,65 | 33,8 → 8,4 ms: os endereços só são montados para quem vira evento |
| `decode_event` | `all` | 33,3 ms | 2,1 Mpacotes/s | 3,20 | sem mudança (todo pacote vira evento) |
| `decode_loop` | `interesting` | 51,8 ms | 1,35 Mpacotes/s | n/d | 66,6 → 51,8 ms |
| `decode_loop` | `all` | 85,5 ms | 0,82 Mpacotes/s | n/d | dentro do ruído |
| `ipc_write` | um frame por escrita | 6,5 ms (4096 eventos) | 0,63 Mev/s | n/d | 7,2 → 6,5 ms (serialização direta no buffer; ruído de ~15%) |
| `ipc_write` | lote de 64 | 1,2 ms | 3,4 Mev/s | n/d | 7,2 → 1,2 ms: o cliente IPC agora envia assim |

Tentado e descartado (não passou da margem de ruído): montar o texto do IP com uma única alocação reduziu as alocações de 3,20 para 2,22 por pacote em `all`, mas o tempo não mudou de forma significativa (p = 0,15); a regra é otimizar o que o número mostra, então não entrou.

O que sobra no `decode_loop` (≈0,5 µs por pacote, ~1,4 Mpacotes/s por thread de captura) é a cópia do quadro (`to_vec`) e o salto de canal entre a captura e o decodificador. Para tráfego de um host (dezenas de milhares de pacotes/s) não é gargalo, e por isso ficou como está. Se um dia for, os caminhos são: decodificar na própria thread de captura e enviar só eventos (elimina a cópia e um salto, mas muda o modelo de perdas: o kernel passa a descartar no lugar da fila interna), ou reciclar os buffers dos quadros.

## Carga ao vivo: o serviço inteiro sob tráfego alto (2026-10-29)

O `make bench` mede o caminho quente isolado. Para o serviço inteiro (captura, decodificação, IPC, motor com as oito regras, banco de alertas) há três scripts, todos sem privilégios:

- `scripts/bench_live.sh`: sobe o daemon e o sensor em release dentro de `unshare -Urn`, captura em `lo` (ou num par `veth`, com `BENCH_IFACE=veth`) e injeta UDP em taxa crescente, 15 s por degrau. Cenário **ruído** (UDP de dados, descartado pela política `interesting`: mede só captura e decodificação) e **dns** (cada pacote vira evento: mede IPC, motor e regras no pior caso). `BENCH_SOAK=<s>` troca a rampa por uma execução longa com amostras a cada 30 s.
- `scripts/bench_replay.sh` + `scripts/gen_traffic_pcap.py`: reproduz no daemon real pcaps grandes e sintéticos (sensor sem perdas, com contrapressão pelo IPC) e mede o tempo até o Core processar tudo. Cenários **variado** (DNS, handshakes TCP e ClientHellos de 5000 origens), **tempestade-scan** e **tempestade-nxdomain** (um alerta por origem ou cliente, 20 000 alertas).
- `go test -bench` no Core (`internal/ipc`, `internal/detection/rules`): isola a leitura IPC e o motor, para atribuir o gargalo.

Máquina: laptop Intel Core i7-8565U (4 núcleos, 8 threads), 19 GiB, kernel 7.0.0-38; sensor v0.3.0 e Core v0.11.0 mais a correção da poda de cooldowns (`a7340a7`). O gerador (3 a 4 processos Python) roda na mesma máquina e disputa CPU com o sensor, então as taxas máximas abaixo são **piso**, não teto. Percentuais de CPU são de um núcleo (100 % = um núcleo inteiro).

### Rampa em `lo`

| Cenário | Enviado (pkt/s) | Capturado (pkt/s) | Perdas: fila de eventos / fila de captura / kernel (15 s) | Eventos/s no motor | CPU sensor | CPU Core | Memória sensor / Core (MiB) |
|---|---|---|---|---|---|---|---|
| ruído | 20 000 | 19 961 | 0 / 0 / 0 | 0 | 11 % | 0 % | 21 / 17 |
| ruído | 50 000 | 49 844 | 0 / 0 / 0 | 0 | 35 % | 0 % | 21 / 17 |
| ruído | 100 000 | 99 826 | 0 / 0 / 0 | 0 | 59 % | 0 % | 21 / 17 |
| ruído | 200 000 | 199 493 | 0 / 0 / 0 | 0 | 106 % | 0 % | 22 / 19 |
| ruído | 382 758 | 374 562 | 0 / 0 / 201 313 (≈3,5 %) | 0 | 113 % | 0 % | 23 / 19 |
| dns | 20 000 | 19 967 | 0 / 0 / 0 | 19 967 | 10 % | 17 % | 23 / 197 |
| dns | 49 999 | 49 894 | 0 / 0 / 0 | 49 894 | 47 % | 56 % | 23 / 215 |
| dns | 99 997 | 99 708 | 0 / 0 / 473 | 99 708 | 69 % | 130 % | 24 / 216 |
| dns | 199 995 | 199 017 | 1 312 010 / 2 449 / 14 405 | 111 619 | 120 % | 162 % | 27 / 218 |
| dns | 335 290 | 331 043 | 3 732 576 / 187 273 / 106 523 | 70 290 | 116 % | 111 % | 27 / 218 |

### Rampa num par `veth` (driver e pilha de recepção virtuais, não `lo`)

O sensor captura na ponta de um par `veth` cujo outro lado está num namespace filho; o gerador roda lá.

| Cenário | Enviado (pkt/s) | Capturado (pkt/s) | Perdas: fila de eventos / fila de captura / kernel (15 s) | Eventos/s no motor | CPU sensor | CPU Core | Memória sensor / Core (MiB) |
|---|---|---|---|---|---|---|---|
| ruído | 20 000 | 19 964 | 0 / 0 / 0 | 0 | 8 % | 0 % | 21 / 17 |
| ruído | 50 000 | 49 899 | 0 / 0 / 0 | 0 | 25 % | 0 % | 21 / 17 |
| ruído | 100 000 | 99 794 | 0 / 0 / 0 | 0 | 64 % | 0 % | 21 / 18 |
| ruído | 200 000 | 199 506 | 0 / 0 / 0 | 0 | 91 % | 0 % | 21 / 19 |
| ruído | 398 094 | 396 549 | 0 / 5 407 / 8 987 | 0 | 118 % | 0 % | 23 / 19 |
| dns | 20 000 | 19 935 | 0 / 0 / 0 | 19 935 | 17 % | 21 % | 23 / 191 |
| dns | 50 000 | 49 909 | 0 / 0 / 0 | 49 909 | 24 % | 47 % | 23 / 217 |
| dns | 100 000 | 99 750 | 0 / 0 / 0 | 99 749 | 119 % | 154 % | 23 / 223 |
| dns | 199 996 | 199 438 | 1 188 536 / 0 / 0 | 120 425 | 122 % | 171 % | 26 / 225 |
| dns | 366 411 | 365 321 | 4 160 038 / 150 137 / 2 122 | 78 727 | 124 % | 123 % | 27 / 230 |

O comportamento é o mesmo de `lo`: sem perdas até 200 000 pkt/s de ruído e até 100 000 pkt/s de DNS; acima disso a primeira fila a encher é a de eventos do sensor. Os degraus perto do limite variam entre execuções (por exemplo, dns a 100 000 pkt/s teve de 0 a 473 perdas, e a 200 000 de 1,1 a 1,4 milhão), porque gerador e sensor disputam os mesmos núcleos.

### Onde está o limite de ~100 000 a 125 000 eventos/s

O gargalo do cenário `dns` é a **leitura IPC no Core**, e não as regras nem a escrita do sensor:

- Cada sessão IPC é lida por uma única goroutine (`readLoop`). Num perfil do Core em execução (build temporário com pprof, nunca commitado) a 200 000 pkt/s, ela consome ~94 % de um núcleo: desserialização do protobuf ~49 %, leituras sem buffer no socket ~33 %, tratador e prazo de leitura ~12 %.
- O motor sozinho tem folga: ~38 % de um núcleo a ~123 000 eventos/s ao vivo, e 820 000 eventos/s no benchmark (`BenchmarkEngine`, 100 000 eventos, fila pré-cheia).
- A escrita em lote do sensor passa de 3 milhões de eventos/s (`make bench`), então o sensor não limita; ele só descarta (`perda.fila_eventos`, contada e visível em `psychoscope-cli metrics`) quando o Core não acompanha.
- Medido, não aplicado: embrulhar a conexão da sessão num `bufio.Reader` reduz a leitura de 3,03 para 1,92 µs por evento (`BenchmarkReadMessageSocket`). A decisão de aplicar é do dono.

### Tráfego variado e tempestade de alertas (reprodução de pcap)

O sensor lê o pcap sem perdas e o Core processa tudo; a vazão é eventos ÷ tempo até o motor esvaziar. Duas execuções por cenário (faixa); 500 000 eventos no variado e 20 000 origens ou clientes nas tempestades.

| Cenário | Eventos/s | Perdas no motor | Alertas gerados / esperados | CPU Core | Memória Core (MiB) |
|---|---|---|---|---|---|
| variado | 159 000 a 170 000 | 25 a 26 % | 0 / 0 | 228 a 236 % | 226 |
| tempestade-scan | 204 000 a 206 000 | 53 a 54 % | 9 200 a 9 500 / 20 000 | 267 a 269 % | 167 a 176 |
| tempestade-nxdomain | 151 000 a 171 000 | 0 % | 20 000 / 20 000 (todos gravados, banco de 12 MiB) | 242 a 245 % | 173 a 179 |

- **Bug encontrado e corrigido** (`a7340a7`, Core): a poda dos cooldowns do motor rodava a cada evento quando o mapa passava de 10 000 chaves (custo quadrático). Antes da correção a tempestade de NXDOMAIN rodava a 81 000 a 89 000 eventos/s, descartava ~114 600 eventos no motor e gerava só ~10 300 dos 20 000 alertas; depois, nenhuma perda. O teste `TestEnginePurgeCooldownsIsAmortized` reproduz o problema (20 000 podas antes, no máximo 6 depois).
- **Achado em aberto:** com tráfego variado ou varredura em massa a ~200 000 eventos/s sem limite de taxa, a fila de entrada do motor (4096, `Submit` não bloqueante) enche e o motor descarta 25 a 54 % dos eventos (`psychoscope_engine_events_dropped_total`), perdendo cerca de metade dos alertas da tempestade de varredura. Contribuinte medido: o despejo do `net.beacon` (`Beacon.evict`) consome ~20 % de CPU quando há muita rotatividade de chaves. Nada disso é alcançável num laptop real (~5 eventos/s), mas é o comportamento sob ataque em massa.

### Execução longa

`BENCH_SOAK=600 BENCH_SOAK_RATE=50000`, cenário dns a 50 000 pkt/s por 600 s (20 amostras): sensor estável em 22 MiB, Core entre 197 e 219 MiB sem tendência de alta, CPU 57 a 59 % (sensor) e 60 a 66 % (Core), **0 perdas** do início ao fim.

### O que não foi medido

- **Interface física** (Wi-Fi, Ethernet): driver real, NAPI, offloads e interrupções têm outro caminho no kernel; o `veth` só cobre a pilha virtual. Exige uma segunda máquina e privilégios.
- **Outras máquinas e arm64:** um único laptop (i7-8565U). Os números absolutos não se transportam.
- **Teto real do sensor:** o gerador Python disputa CPU com ele, então os pontos de perda são pisos.
- **Tráfego fora do catálogo sintético:** handshakes TLS completos, IPv6, VLAN, fragmentação.
- **Variações de configuração:** tamanho da fila do motor, `MaxEvents`, janela maior.
- **Disco lento** na gravação dos alertas, execuções acima de 10 minutos, vários módulos ou sensores ao mesmo tempo.

Para repetir:

```bash
scripts/bench_live.sh                                                        # rampa em lo
BENCH_IFACE=veth scripts/bench_live.sh                                       # rampa num par veth
BENCH_SOAK=600 BENCH_SOAK_RATE=50000 BENCH_MODES=dns scripts/bench_live.sh   # execução longa
scripts/bench_replay.sh                                                      # tráfego variado e tempestades
```
