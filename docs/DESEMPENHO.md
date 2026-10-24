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
