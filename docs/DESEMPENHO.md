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
- Aplicado depois (Core, `readLoop` com `bufio.Reader` de 64 KiB; a leitura caiu de 3,03 para 1,92 µs por evento em `BenchmarkReadMessageSocket`). Medido de novo, duas execuções cada, dns ao vivo em `lo`: a 100 000 pkt/s o CPU do Core caiu de 130 a 154 % para 105 a 109 %; a 200 000 pkt/s o motor foi de 112 000 a 126 000 para 184 000 eventos/s e as perdas na fila de eventos do sensor de 1,2 a 1,4 milhão para 200 000 a 236 000. Na reprodução de pcap o Core lê 250 000 a 308 000 eventos/s no variado (antes 159 000 a 170 000). O gargalo passa a ser o motor: a fila de 4096 enche mais e o motor descarta 46 a 51 % do variado e perde ainda mais alertas da tempestade de varredura (4 000 de 20 000, antes ~9 300), porque o leitor ficou mais rápido que as regras. As tabelas desta página são da versão anterior ao `bufio`.

### Tráfego variado e tempestade de alertas (reprodução de pcap)

O sensor lê o pcap sem perdas e o Core processa tudo; a vazão é eventos ÷ tempo até o motor esvaziar. Duas execuções por cenário (faixa); 500 000 eventos no variado e 20 000 origens ou clientes nas tempestades.

| Cenário | Eventos/s | Perdas no motor | Alertas gerados / esperados | CPU Core | Memória Core (MiB) |
|---|---|---|---|---|---|
| variado | 159 000 a 170 000 | 25 a 26 % | 0 / 0 | 228 a 236 % | 226 |
| tempestade-scan | 204 000 a 206 000 | 53 a 54 % | 9 200 a 9 500 / 20 000 | 267 a 269 % | 167 a 176 |
| tempestade-nxdomain | 151 000 a 171 000 | 0 % | 20 000 / 20 000 (todos gravados, banco de 12 MiB) | 242 a 245 % | 173 a 179 |

- **Bug encontrado e corrigido** (`a7340a7`, Core): a poda dos cooldowns do motor rodava a cada evento quando o mapa passava de 10 000 chaves (custo quadrático). Antes da correção a tempestade de NXDOMAIN rodava a 81 000 a 89 000 eventos/s, descartava ~114 600 eventos no motor e gerava só ~10 300 dos 20 000 alertas; depois, nenhuma perda. O teste `TestEnginePurgeCooldownsIsAmortized` reproduz o problema (20 000 podas antes, no máximo 6 depois).
- **Achado em aberto:** com tráfego variado ou varredura em massa a ~200 000 eventos/s sem limite de taxa, a fila de entrada do motor (4096, `Submit` não bloqueante) enche e o motor descarta 25 a 54 % dos eventos (`psychoscope_engine_events_dropped_total`), perdendo cerca de metade dos alertas da tempestade de varredura. Contribuinte medido: o despejo do `net.beacon` (`Beacon.evict`) consome ~20 % de CPU quando há muita rotatividade de chaves. Nada disso é alcançável num laptop real (~5 eventos/s), mas é o comportamento sob ataque em massa.

### O motor sob churn de chaves e o tamanho da fila

Com o leitor mais rápido, o motor virou o limite sob tráfego em massa. Duas medições (Core após `v0.11.1`):

- **`Beacon.evict`** (`BenchmarkBeaconChurn`, 200 000 origens distintas contra o teto de 50 000 séries): era 75 % do tempo do beacon, e quase metade disso era `sort.Slice` sobre structs. Ordenar só os instantes (`[]int64`, `slices.Sort`) levou de 160 000 a 220 000 para 260 000 a 380 000 ev/s do beacon sozinho, com a mesma política de despejo (as 10 % mais antigas; empates no corte não despejam mais que isso). Despejar 25 % de uma vez daria 375 000 a 539 000, mas muda a política e ficou dentro do ruído; não foi adotado. No replay (duas execuções, máquina com carga; dentro do ruído, só o benchmark isolado é firme): tempestade de varredura com 4 800 a 4 900 alertas (antes 4 000 a 4 400) e o variado com 37 % de eventos descartados no motor (antes 46 a 51 %). No cenário `dns` ao vivo não há churn de chaves, então ali o efeito é nulo; com a máquina em carga (média de 7 no `uptime`) o motor ficou em 153 000 a 169 000 ev/s a 200 000 pkt/s, dentro da variação das execuções anteriores.
- **Fila do motor** (`detection.queue_size`, replay de 500 000 eventos em ~2 s): descartes no variado 185 000 (4096), 157 000 a 165 000 (16 384) e 106 000 a 116 000 (65 536, +40 MiB de memória no Core); alertas da varredura 4 800, 5 600 a 6 000 e 8 800 a 9 000 de 20 000. A fila só absorve rajada: com entrada sustentada acima da vazão do motor ela não evita o descarte (22 % ainda no maior tamanho). O padrão continua 4096; quem espera rajadas pode subir o valor.
- **Achado novo:** na tempestade de NXDOMAIN, com o motor mais rápido, o gravador de alertas (fila de 1 024) chegou a descartar 64 a 654 dos 20 000 alertas (`psychoscope_store_alerts_dropped_total`). Não tratado aqui.

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
