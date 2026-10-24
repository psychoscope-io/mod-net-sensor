//! `--check`: confere o ambiente do sensor (fonte, filtro BPF, permissao de captura, fila e
//! destino dos eventos) e diz o que corrigir, sem capturar nem enviar nada.
use std::os::unix::net::UnixStream;

use crate::capture::sniffer::{self, CaptureConfig, Source};
use crate::config::{Config, MAX_QUEUE_BYTES};
use crate::explain::{CaptureContext, capture_hint, socket_hint};
use crate::interfaces;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// Nao impede o sensor de rodar (ele reconecta sozinho), mas nenhum evento chegara antes.
    Warn,
    Fail,
}

#[derive(Debug)]
pub struct Item {
    pub status: Status,
    pub what: &'static str,
    pub detail: String,
    pub fix: Option<String>,
}

impl Item {
    fn ok(what: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Ok,
            what,
            detail: detail.into(),
            fix: None,
        }
    }

    fn warn(what: &'static str, detail: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            status: Status::Warn,
            what,
            detail: detail.into(),
            fix,
        }
    }

    fn fail(what: &'static str, detail: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            status: Status::Fail,
            what,
            detail: detail.into(),
            fix,
        }
    }
}

#[derive(Debug)]
pub struct Report(pub Vec<Item>);

impl Report {
    /// Sem nenhuma falha (avisos nao contam).
    pub fn passed(&self) -> bool {
        self.0.iter().all(|i| i.status != Status::Fail)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for i in &self.0 {
            let tag = match i.status {
                Status::Ok => "[ok]    ",
                Status::Warn => "[aviso] ",
                Status::Fail => "[falha] ",
            };
            out += &format!("{tag} {}: {}\n", i.what, i.detail);
            if let Some(fix) = &i.fix {
                out += &format!("         como corrigir: {fix}\n");
            }
        }
        let count = |s| self.0.iter().filter(|i| i.status == s).count();
        out += &format!(
            "\nresultado: {} falha(s), {} aviso(s)\n",
            count(Status::Fail),
            count(Status::Warn)
        );
        out
    }
}

fn capture_cfg(cfg: &Config) -> Option<CaptureConfig> {
    let source = match (&cfg.interface, &cfg.pcap_file) {
        (Some(i), _) => Source::Interface(i.clone()),
        (None, Some(f)) => Source::File(f.clone()),
        (None, None) => return None,
    };
    Some(CaptureConfig {
        source,
        bpf: cfg.bpf.clone(),
        snaplen: cfg.snaplen,
        promisc: !cfg.no_promisc,
    })
}

/// Roda todas as conferencias, na ordem em que o sensor depende delas.
pub fn run(cfg: &Config) -> Report {
    let source = source(cfg);
    let source_ok = source.status == Status::Ok;
    let mut items = vec![source];
    if let Some(expr) = &cfg.bpf {
        items.push(filter(expr));
    }
    items.push(if source_ok {
        capture(cfg)
    } else {
        Item::warn(
            "captura",
            "nao verificada: a fonte tem problema (veja acima)",
            None,
        )
    });
    items.push(queue(cfg));
    items.push(destination(cfg));
    Report(items)
}

fn exe_path() -> String {
    std::env::current_exe().map_or_else(|_| "<binario>".to_string(), |p| p.display().to_string())
}

fn source(cfg: &Config) -> Item {
    if let Some(path) = &cfg.pcap_file {
        return match std::fs::metadata(path) {
            Ok(m) if m.is_file() => Item::ok(
                "fonte",
                format!("arquivo {} ({} bytes)", path.display(), m.len()),
            ),
            Ok(_) => Item::fail(
                "fonte",
                format!("{} nao e um arquivo", path.display()),
                Some("aponte --pcap-file para um arquivo pcap".into()),
            ),
            Err(e) => {
                let ctx = CaptureContext {
                    interface: None,
                    pcap_file: Some(path),
                    available: "",
                    exe: "",
                };
                Item::fail(
                    "fonte",
                    format!("{}: {e}", path.display()),
                    capture_hint(&e.to_string(), &ctx),
                )
            }
        };
    }
    let name = cfg.interface.as_deref().unwrap_or_default();
    let all = match interfaces::list() {
        Ok(l) => l,
        Err(e) => {
            return Item::warn(
                "fonte",
                format!(
                    "nao foi possivel listar as interfaces ({e}); a existencia de '{name}' sera confirmada ao abrir a captura"
                ),
                None,
            );
        }
    };
    let ctx = CaptureContext {
        interface: Some(name),
        pcap_file: None,
        available: &interfaces::names(&all),
        exe: "",
    };
    match all.iter().find(|i| i.name == name) {
        None => Item::fail(
            "fonte",
            format!("interface '{name}' nao encontrada"),
            capture_hint("No such device exists", &ctx),
        ),
        Some(i) if !i.up => Item::fail(
            "fonte",
            format!("interface '{name}' esta desativada"),
            capture_hint("That device is not up", &ctx),
        ),
        Some(i) => {
            let addrs = if i.addresses.is_empty() {
                "sem endereco".to_string()
            } else {
                i.addresses.join(", ")
            };
            Item::ok("fonte", format!("interface {name} ({addrs})"))
        }
    }
}

fn filter(expr: &str) -> Item {
    match sniffer::check_bpf(expr) {
        Ok(()) => Item::ok("filtro BPF", format!("\"{expr}\" e valido")),
        Err(e) => {
            let ctx = CaptureContext {
                interface: None,
                pcap_file: None,
                available: "",
                exe: "",
            };
            Item::fail(
                "filtro BPF",
                e.to_string(),
                capture_hint(&e.to_string(), &ctx),
            )
        }
    }
}

fn capture(cfg: &Config) -> Item {
    let Some(cc) = capture_cfg(cfg) else {
        return Item::fail("captura", "nenhuma fonte informada", None);
    };
    match sniffer::probe(&cc) {
        Ok(link) => Item::ok(
            "captura",
            format!("fonte aberta com sucesso (enlace {link:?})"),
        ),
        Err(e) => {
            let text = e.to_string();
            let available = interfaces::list()
                .map(|l| interfaces::names(&l))
                .unwrap_or_default();
            let exe = exe_path();
            let ctx = CaptureContext {
                interface: cfg.interface.as_deref(),
                pcap_file: cfg.pcap_file.as_deref(),
                available: &available,
                exe: &exe,
            };
            Item::fail("captura", text.clone(), capture_hint(&text, &ctx))
        }
    }
}

fn queue(cfg: &Config) -> Item {
    let worst = cfg.queue_size as u64 * cfg.snaplen as u64;
    Item::ok(
        "fila de pacotes",
        format!(
            "ate {} MiB no pior caso (limite {} MiB)",
            worst >> 20,
            MAX_QUEUE_BYTES >> 20
        ),
    )
}

fn destination(cfg: &Config) -> Item {
    if cfg.print.is_some() {
        return Item::ok(
            "destino",
            "os eventos serao impressos no terminal (--print); o Core nao e usado",
        );
    }
    match UnixStream::connect(&cfg.socket) {
        Ok(_) => Item::ok(
            "destino",
            format!("Core escutando em {}", cfg.socket.display()),
        ),
        Err(e) => Item::warn(
            "destino",
            format!("sem conexao com o Core em {}: {e}", cfg.socket.display()),
            socket_hint(e.kind(), &cfg.socket).map(|h| {
                format!("{h}; o sensor tenta reconectar sozinho, mas nenhum evento chega ate la")
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::pcapfile::{LINKTYPE_ETHERNET, PcapPacket, write_pcap};
    use crate::protocols::testutil::*;

    fn parse(args: &[&str]) -> Config {
        Config::try_parse_checked(std::iter::once("mod-net-sensor").chain(args.iter().copied()))
            .unwrap()
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("check-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pcap_in(d: &std::path::Path) -> std::path::PathBuf {
        let ip = eth_v4(17, &udp(5000, 53, &dns_query("a.com", 1)));
        let path = d.join("t.pcap");
        let mut f = std::fs::File::create(&path).unwrap();
        write_pcap(
            &mut f,
            LINKTYPE_ETHERNET,
            65535,
            &[PcapPacket {
                ts_sec: 1,
                ts_usec: 0,
                data: &ip,
                wire_len: None,
            }],
        )
        .unwrap();
        path
    }

    fn status_of(r: &Report, what: &str) -> Status {
        r.0.iter()
            .find(|i| i.what == what)
            .unwrap_or_else(|| panic!("sem item {what}"))
            .status
    }

    #[test]
    fn a_healthy_replay_passes_and_a_missing_core_is_only_a_warning() {
        let d = dir("ok");
        let pcap = pcap_in(&d);
        let sock = d.join("nao-existe.sock");
        let cfg = parse(&[
            "--pcap-file",
            pcap.to_str().unwrap(),
            "--bpf",
            "udp port 53",
            "--socket",
            sock.to_str().unwrap(),
        ]);
        let r = run(&cfg);
        assert!(r.passed(), "{}", r.render());
        for ok in ["fonte", "filtro BPF", "captura", "fila de pacotes"] {
            assert_eq!(status_of(&r, ok), Status::Ok, "{}", r.render());
        }
        assert_eq!(status_of(&r, "destino"), Status::Warn);
        let text = r.render();
        assert!(
            text.contains("--print")
                && text.contains("como corrigir")
                && text.contains("resultado: 0 falha(s), 1 aviso(s)"),
            "{text}"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn problems_are_failures_with_a_fix_and_do_not_hide_each_other() {
        let d = dir("bad");
        let cfg = parse(&[
            "--pcap-file",
            d.join("falta.pcap").to_str().unwrap(),
            "--bpf",
            "udp port",
            "--print",
        ]);
        let r = run(&cfg);
        assert!(!r.passed());
        assert_eq!(status_of(&r, "fonte"), Status::Fail);
        assert_eq!(status_of(&r, "filtro BPF"), Status::Fail);
        assert_eq!(
            status_of(&r, "captura"),
            Status::Warn,
            "nao testada quando a fonte falha"
        );
        assert_eq!(
            status_of(&r, "destino"),
            Status::Ok,
            "--print dispensa o Core"
        );
        let text = r.render();
        assert!(
            text.contains("nao existe") && text.contains("pcap-filter"),
            "{text}"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_listening_core_is_ok_and_an_unknown_interface_is_never_ok() {
        let d = dir("core");
        let sock = d.join("core.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let cfg = parse(&["-i", "nao-existe-xyz0", "--socket", sock.to_str().unwrap()]);
        let r = run(&cfg);
        assert_eq!(status_of(&r, "destino"), Status::Ok, "{}", r.render());
        assert_ne!(status_of(&r, "fonte"), Status::Ok, "{}", r.render());
        std::fs::remove_dir_all(d).unwrap();
    }
}
