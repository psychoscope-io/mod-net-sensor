//! Parsing de flags CLI.
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "mod-net-sensor",
    version,
    about = "Sensor de rede do Psychoscope"
)]
pub struct Config {
    /// Caminho do socket do core.
    #[arg(
        long,
        env = "PSYCHOSCOPE_SOCKET",
        default_value = "/var/run/psychoscope/core.sock"
    )]
    pub socket: PathBuf,

    /// Identificador deste modulo no Hello.
    #[arg(long, default_value = "mod-net-sensor")]
    pub module_id: String,
}
