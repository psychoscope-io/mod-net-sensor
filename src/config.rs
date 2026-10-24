//! Parsing de flags CLI (e variaveis de ambiente injetadas pelo supervisor do Core).
use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::event::EmitPolicy;

/// Teto da memoria que a fila de pacotes pode reter no pior caso (`queue_size * snaplen`).
pub const MAX_QUEUE_BYTES: u64 = 256 << 20;

/// Formato de `--print`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrintFormat {
    /// Uma linha de texto por evento.
    Text,
    /// Um objeto JSON por linha.
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mod-net-sensor",
    version,
    about = "Sensor de rede do Psychoscope (captura -> decode -> IPC)"
)]
#[command(group(ArgGroup::new("source").args(["interface", "pcap_file"])))]
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

    /// Lista as interfaces de rede capturaveis e sai.
    #[arg(long)]
    pub list_interfaces: bool,

    /// Confere o ambiente (fonte, permissao de captura, filtro BPF, socket do Core), diz o que
    /// corrigir e sai com 1 se algo falhar. Nao envia eventos.
    #[arg(long)]
    pub check: bool,

    /// Imprime os eventos no terminal em vez de envia-los ao Core (nao precisa do Core).
    /// Formato: text (padrao) ou json.
    #[arg(long, value_enum, num_args = 0..=1, default_missing_value = "text", value_name = "FORMATO")]
    pub print: Option<PrintFormat>,

    /// Mostra um resumo periodico (pacotes/s, perdas, eventos) no stderr.
    #[arg(short, long)]
    pub verbose: bool,
}

impl Config {
    /// Analisa os argumentos e aplica as regras entre flags que o clap nao expressa.
    pub fn try_parse_checked<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cfg = Self::try_parse_from(args)?;
        if cfg.list_interfaces {
            let others = cfg.interface.is_some()
                || cfg.pcap_file.is_some()
                || cfg.check
                || cfg.print.is_some();
            return if others {
                Err(Self::usage_error(
                    "--list-interfaces so pode ser usado sozinho",
                ))
            } else {
                Ok(cfg)
            };
        }
        if cfg.interface.is_none() && cfg.pcap_file.is_none() {
            return Err(Self::usage_error(
                "informe a fonte: -i <interface> ou --pcap-file <arquivo> (as interfaces disponiveis aparecem com --list-interfaces)",
            ));
        }
        if cfg.exit_on_eof && cfg.pcap_file.is_none() {
            return Err(<Self as clap::CommandFactory>::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--exit-on-eof so pode ser usado com --pcap-file",
            ));
        }
        let worst = cfg.queue_size as u64 * cfg.snaplen as u64;
        if worst > MAX_QUEUE_BYTES {
            let fit = MAX_QUEUE_BYTES / cfg.snaplen as u64;
            return Err(<Self as clap::CommandFactory>::command().error(
                clap::error::ErrorKind::ValueValidation,
                format!(
                    "--queue-size {} com --snaplen {} pode reter {} MiB na fila de pacotes (maximo {} MiB): \
                     use --queue-size {fit} ou menos, ou reduza --snaplen",
                    cfg.queue_size,
                    cfg.snaplen,
                    worst >> 20,
                    MAX_QUEUE_BYTES >> 20,
                ),
            ));
        }
        Ok(cfg)
    }

    fn usage_error(msg: &str) -> clap::Error {
        <Self as clap::CommandFactory>::command()
            .error(clap::error::ErrorKind::MissingRequiredArgument, msg)
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

    #[test]
    fn queue_memory_is_bounded() {
        let at_limit = parse(&["-i", "lo", "--snaplen", "65535", "--queue-size", "4096"]);
        assert!(at_limit.is_ok(), "{:?}", at_limit.err());
        let e = parse(&["-i", "lo", "--snaplen", "65535", "--queue-size", "8192"]).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("--queue-size 4096 ou menos"), "{msg}");
        assert!(parse(&["--pcap-file", "x", "--queue-size", "1000000"]).is_err());
        // o padrao cabe com folga
        assert!(parse(&["-i", "lo"]).is_ok());
    }

    #[test]
    fn list_interfaces_stands_alone_and_other_modes_still_need_a_source() {
        let c = parse(&["--list-interfaces"]).unwrap();
        assert!(c.list_interfaces && c.interface.is_none());
        assert!(parse(&["--list-interfaces", "-i", "eth0"]).is_err());
        assert!(parse(&["--list-interfaces", "--check"]).is_err());
        // sem fonte, o erro diz o que fazer e onde ver as interfaces
        let msg = parse(&[]).unwrap_err().to_string();
        assert!(
            msg.contains("informe a fonte") && msg.contains("--list-interfaces"),
            "{msg}"
        );
        assert!(
            parse(&["--check"]).is_err(),
            "--check precisa da fonte a conferir"
        );
        assert!(parse(&["--check", "-i", "eth0"]).is_ok());
    }

    #[test]
    fn print_takes_an_optional_format() {
        assert_eq!(parse(&["-i", "lo"]).unwrap().print, None);
        assert_eq!(
            parse(&["-i", "lo", "--print"]).unwrap().print,
            Some(PrintFormat::Text)
        );
        assert_eq!(
            parse(&["-i", "lo", "--print=json"]).unwrap().print,
            Some(PrintFormat::Json)
        );
        assert_eq!(
            parse(&["-i", "lo", "--print", "text"]).unwrap().print,
            Some(PrintFormat::Text)
        );
        assert!(parse(&["-i", "lo", "--print=xml"]).is_err());
        assert!(parse(&["-i", "lo", "-v"]).unwrap().verbose);
    }
}
