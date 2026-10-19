//! SOURCE: captura de pacotes (Fase 4). `sniffer.rs` abrira a interface via pcap
//! em thread dedicada e enviara os frames brutos por `mpsc` ao runtime Tokio.
pub mod sniffer;
