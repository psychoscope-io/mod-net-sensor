# Desempenho do caminho quente

Como medir e a linha de base de cada mudança de desempenho. Regra do projeto: otimização só com número.

## Como medir

```bash
make bench
```

Gera `target/bench.pcap` (`scripts/gen_pcap.py --repeat 30 --filler 2000`: ~70 mil pacotes, dos quais ~9,9 mil viram evento na política `interesting`) e roda `benches/hot_path.rs`:

- `decode_event`: `decode_frame` + `build_event_reassembling` sobre todos os quadros (sem canal).
- `decode_loop`: o laço real com canal de entrada, canal de eventos e consumidor (inclui a cópia do quadro, como a captura faz).
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

Leitura: a política `interesting` aloca o mesmo que `all`, porque o evento (com as duas `String` de IP) é montado antes de decidir se é descartado; ~86% dos pacotes do pcap são descartados.
