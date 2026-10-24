//! Contrato entre o cliente IPC e o resto do sensor: o que o Core pode pedir
//! (pausar, retomar, reconfigurar) e os numeros que o sensor reporta no status.
use std::collections::HashMap;
use std::future::Future;

/// Numeros do pipeline reportados no `StatusModulo`.
#[derive(Debug, Default, Clone)]
pub struct StatsSnapshot {
    pub packets_captured: u64,
    pub bytes: u64,
    /// Perdas das etapas do pipeline (kernel, interface, filas); o cliente soma as do IPC.
    pub packets_dropped: u64,
    /// Contadores detalhados, cumulativos; as chaves estao documentadas em `ipc.proto`.
    pub counters: Vec<(&'static str, u64)>,
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
