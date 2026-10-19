# mod-net-sensor

Sensor de rede do Psychoscope em Rust (pipeline Source -> Decode -> Sink).

Estado: Fase 2 — framer IPC (`src/ipc/framer.rs`) com golden vectors e proptest;
captura/decoders/cliente IPC chegam na Fase 4. `Cargo.toml` usa `path` para
`../psychoscope-proto/rust` durante o desenvolvimento; trocar por `git` + `tag` antes de publicar.

Interop real com o Core em Go: `scripts/interop.sh` (requer `../psychoscope-core`).
`testdata/framing_vectors.json` é cópia de `psychoscope-proto/testdata/`.
