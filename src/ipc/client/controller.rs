//! Contrato entre o cliente IPC e o resto do sensor: o que o Core pode pedir
//! (pausar, retomar, reconfigurar) e os numeros que o sensor reporta no status.
use std::collections::HashMap;
use std::future::Future;

/// Numeros do pipeline reportados no `StatusModulo`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StatsSnapshot {
    pub packets_captured: u64,
    pub bytes: u64,
    /// Pacotes perdidos em qualquer etapa (kernel, canal do sniffer).
    pub packets_dropped: u64,
}

/// Interface entre os comandos do Core e o resto do sensor.
pub trait Controller: Send + Sync + 'static {
    fn pause(&self);
    fn resume(&self);
    fn reconfigure(
        &self,
        params: HashMap<String, String>,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn stats(&self) -> StatsSnapshot;
}
