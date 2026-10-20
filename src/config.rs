//! Parsing de flags CLI (e variaveis de ambiente injetadas pelo supervisor do Core).
use std::path::PathBuf;

use clap::{ArgGroup, Parser};

use crate::event::EmitPolicy;

#[derive(Debug, Parser)]
#[command(
    name = "mod-net-sensor",
    version,
    about = "Sensor de rede do Psychoscope (captura -> decode -> IPC)"
)]
#[command(group(ArgGroup::new("source").required(true).args(["interface", "pcap_file"])))]
pub struct Config {
    /// Socket do core (o supervisor define PSYCHOSCOPE_SOCKET).
    #[arg(
        long,
        env = "PSYCHOSCOPE_SOCKET",
        default_value = "/var/run/psychoscope/core.sock"
    )]
    pub socket: PathBuf,

    /// Identificador deste modulo (o supervisor define PSYCHOSCOPE_MODULE_ID).
    #[arg(long, env = "PSYCHOSCOPE_MODULE_ID", default_value = "mod-net-sensor")]
    pub module_id: String,

    /// Interface para captura ao vivo (requer CAP_NET_RAW e CAP_NET_ADMIN, ou root).
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Le pacotes de um arquivo pcap em vez de capturar ao vivo (testes, replay).
    #[arg(long)]
    pub pcap_file: Option<PathBuf>,

    /// Filtro BPF opcional (ex.: "udp port 53 or tcp port 443").
    #[arg(long)]
    pub bpf: Option<String>,

    /// Bytes capturados por pacote.
    #[arg(long, default_value_t = crate::capture::sniffer::DEFAULT_SNAPLEN, value_parser = clap::builder::RangedI64ValueParser::<i32>::new().range(128..=65535))]
    pub snaplen: i32,

    /// Desliga o modo promiscuo.
    #[arg(long)]
    pub no_promisc: bool,

    /// Quais pacotes viram evento.
    #[arg(long, value_enum, default_value = "interesting")]
    pub emit: EmitPolicy,

    /// Tamanho dos canais internos (pacotes e eventos); excedentes sao descartados e contados.
    #[arg(long, default_value_t = 8192, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(16..=1_000_000))]
    pub queue_size: usize,

    /// Com --pcap-file: encerra apos enviar todos os eventos (em vez de ficar ocioso).
    #[arg(long)]
    pub exit_on_eof: bool,
}

impl Config {
    /// Analisa os argumentos e aplica as regras entre flags que o clap nao expressa.
    pub fn try_parse_checked<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cfg = Self::try_parse_from(args)?;
        if cfg.exit_on_eof && cfg.pcap_file.is_none() {
            return Err(<Self as clap::CommandFactory>::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--exit-on-eof so pode ser usado com --pcap-file",
            ));
        }
        Ok(cfg)
    }

    /// Como `try_parse_checked` sobre `std::env::args`, encerrando o processo em caso de erro.
    pub fn parse_checked() -> Self {
        Self::try_parse_checked(std::env::args_os()).unwrap_or_else(|e| e.exit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_checked(std::iter::once("mod-net-sensor").chain(args.iter().copied()))
    }

    #[test]
    fn requires_exactly_one_source() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["-i", "eth0", "--pcap-file", "x.pcap"]).is_err());
        let c = parse(&["-i", "eth0"]).unwrap();
        assert_eq!(c.interface.as_deref(), Some("eth0"));
        assert_eq!(
            (c.emit, c.snaplen, c.queue_size),
            (EmitPolicy::Interesting, 2048, 8192)
        );
    }

    #[test]
    fn exit_on_eof_only_with_file_and_bounds() {
        assert!(parse(&["-i", "eth0", "--exit-on-eof"]).is_err());
        let r = parse(&["--pcap-file", "x", "--exit-on-eof", "--emit", "all"]);
        assert!(r.is_ok(), "{:?}", r.err());
        assert!(parse(&["-i", "lo", "--snaplen", "10"]).is_err());
        assert!(parse(&["-i", "lo", "--queue-size", "1"]).is_err());
        assert!(parse(&["-i", "lo", "--emit", "nada"]).is_err());
    }
}
