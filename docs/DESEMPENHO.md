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

## Carga ao vivo: o serviço inteiro sob tráfego alto (2026-10-28)

O `make bench` mede o caminho quente isolado. Para o serviço inteiro (captura, decodificação, IPC, motor com as oito regras, banco de alertas) o `scripts/bench_live.sh` sobe o daemon e o sensor em release dentro de `unshare -Urn` (sem privilégios), captura em `lo` e injeta tráfego UDP sintético em taxa crescente, 15 s por degrau. Dois cenários:

- **ruído:** UDP de dados na porta 9999. A política `interesting` descarta tudo, então mede só captura e decodificação.
- **dns:** consultas DNS (64 nomes que se repetem). Cada pacote vira evento: mede IPC, motor e regras no pior caso.

Máquina: laptop Intel Core i7-8565U (4 núcleos, 8 threads), 19 GiB, kernel 7.0.0-38; sensor v0.3.0 e Core v0.11.0 (árvore de trabalho). O gerador (4 processos Python) roda na mesma máquina e disputa CPU com o sensor, então os limites abaixo são **piso**, não teto. Percentuais de CPU são de um núcleo (100 % = um núcleo inteiro).

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

Os degraus de 100 000 e 200 000 pkt/s do cenário `dns` foram repetidos em outras execuções: em 100 000, de 0 a 350 pacotes perdidos no sensor; em 200 000, de 1,1 a 1,4 milhão perdidos na fila de eventos, com o motor entre 106 000 e 126 000 eventos/s. Perto do limite (ruído a ~380 000 e dns acima de 200 000) o resultado varia bastante entre execuções, porque o gerador e o sensor disputam os mesmos núcleos. O motor (`events_dropped`) não descartou evento algum em nenhuma execução.

Leitura:

- **Captura e decodificação (ruído):** sem perdas até 200 000 pkt/s, com o sensor em cerca de um núcleo. Perto de 380 000 pkt/s o kernel começa a descartar (perda de 3,5 % no buffer da captura). A memória do sensor fica em ~21 a 23 MiB e não cresce com a taxa.
- **IPC e motor (dns):** o caminho do evento (escrita IPC no sensor, leitura no Core e as oito regras numa única goroutine do motor) entrega cerca de 100 000 a 125 000 eventos/s. Até 100 000 pkt/s quase não há perdas. A 200 000 o caminho não acompanha e a fila de eventos do sensor enche: o sensor descarta (`perda.fila_eventos`, contada e visível em `psychoscope-cli metrics`) em vez de crescer sem limite, e o motor não perde evento algum (`events_dropped` = 0). Esta medição não separa quanto do limite é da escrita IPC, da leitura no Core ou das regras; o `make bench` mostra que a escrita em lote do sensor passa de 3 milhões de eventos/s, então o gargalo provável é o lado do Core.
- **Memória do Core:** sobe de ~17 para ~218 MiB quando há muitos eventos, porque a janela deslizante guarda até 200 000 eventos (`MaxEvents`); estabiliza aí.
- **Contexto:** o serviço real de um laptop (medido em 28 min de uso normal) vê ~41 pacotes/s e ~5 eventos/s, três ordens de grandeza abaixo do ponto em que as perdas começam. O limite de ~100 000 eventos/s só importa num host com tráfego de servidor ou sob ataque (varredura, inundação de DNS).
- **Limites da medição:** um só host e um só gerador (loopback, pacotes de ~45 a ~150 bytes, uma origem); sem TLS, fluxos variados nem muitos alertas no banco; e uma interface real (`wlp2s0`, `eth0`) tem outro caminho no kernel (driver, NAPI), que não foi medido. Um erro do script na primeira passagem (o contador de perdas do kernel saía sempre 0) foi corrigido antes desta tabela.

Para repetir:

```bash
scripts/bench_live.sh                                              # degraus padrão
BENCH_SECS=15 BENCH_PROCS=4 BENCH_RATES="100000 200000" BENCH_MODES=dns scripts/bench_live.sh
```
