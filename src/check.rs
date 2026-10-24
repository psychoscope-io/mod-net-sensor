//! `--check`: confere o ambiente do sensor (fonte, filtro BPF, permissao de captura, fila e
//! destino dos eventos) e diz o que corrigir, sem capturar nem enviar nada.
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use crate::capture::sniffer::{self, CaptureConfig, CaptureError, Source};
use crate::config::{Config, MAX_QUEUE_BYTES};
use crate::explain::{CaptureContext, capture_hint, socket_hint};
use crate::interfaces;
use crate::protocols::LinkType;

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

/// Resultado de abrir a fonte como a captura abriria.
type Probe = Result<LinkType, CaptureError>;

/// Roda todas as conferencias, na ordem em que o sensor depende delas. A abertura real da
/// fonte vem antes do filtro BPF, porque so ela sabe o tipo de enlace em que o filtro vale.
pub fn run(cfg: &Config) -> Report {
    let source = source(cfg);
    let probe: Option<Probe> = (source.status == Status::Ok)
        .then(|| capture_cfg(cfg))
        .flatten()
        .map(|cc| sniffer::probe(&cc));
    let mut items = vec![source];
    if let Some(expr) = &cfg.bpf {
        items.push(filter(expr, probe.as_ref()));
    }
    items.push(capture(cfg, probe.as_ref()));
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

/// Valido no enlace real quando a fonte abriu; sem isso, so a sintaxe (contra Ethernet) pode
/// ser conferida, e um erro que nao seja de sintaxe fica como aviso (o filtro pode valer so em
/// outro tipo de enlace).
fn filter(expr: &str, probe: Option<&Probe>) -> Item {
    match probe {
        Some(Ok(link)) => Item::ok(
            "filtro BPF",
            format!("\"{expr}\" e valido no enlace {link:?}"),
        ),
        Some(Err(CaptureError::Filter(e))) => bpf_failure(e.to_string()),
        _ => match sniffer::check_bpf(expr) {
            Ok(()) => Item::ok(
                "filtro BPF",
                format!(
                    "\"{expr}\" tem sintaxe valida (a confirmacao no enlace real depende de abrir a captura)"
                ),
            ),
            Err(e) if e.to_string().to_lowercase().contains("syntax error") => {
                bpf_failure(e.to_string())
            }
            Err(e) => Item::warn(
                "filtro BPF",
                format!("nao confirmado: {e}; pode ser valido no enlace real da interface"),
                None,
            ),
        },
    }
}

fn bpf_failure(text: String) -> Item {
    let ctx = CaptureContext {
        interface: None,
        pcap_file: None,
        available: "",
        exe: "",
    };
    let fix = capture_hint(&text, &ctx).or_else(|| {
        Some(
            "ajuste --bpf para valer no tipo de enlace da fonte (veja `man pcap-filter`)"
                .to_string(),
        )
    });
    Item::fail("filtro BPF", text, fix)
}

fn capture(cfg: &Config, probe: Option<&Probe>) -> Item {
    match probe {
        None => Item::warn(
            "captura",
            "nao verificada: a fonte tem problema (veja acima)",
            None,
        ),
        Some(Ok(link)) => Item::ok(
            "captura",
            format!("fonte aberta com sucesso (enlace {link:?})"),
        ),
        Some(Err(CaptureError::Filter(_))) => Item::warn(
            "captura",
            "nao concluida por causa do filtro BPF (veja acima)",
            None,
        ),
        Some(Err(e)) => {
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

/// Confere o socket do Core sem conectar: uma conexao sem Hello aparece no log do Core como
/// "handshake falhou", ruido que o `--check` nao deve produzir num Core em producao. Existe,
/// e um socket e o usuario pode escrever nele (a permissao que o connect exigiria).
fn destination(cfg: &Config) -> Item {
    if cfg.print.is_some() {
        return Item::ok(
            "destino",
            "os eventos serao impressos no terminal (--print); o Core nao e usado",
        );
    }
    let path = &cfg.socket;
    let warn = |detail: String, kind: std::io::ErrorKind| {
        Item::warn(
            "destino",
            detail,
            socket_hint(kind, path).map(|h| {
                format!("{h}; o sensor tenta reconectar sozinho, mas nenhum evento chega ate la")
            }),
        )
    };
    match std::fs::metadata(path) {
        Err(e) => warn(
            format!("sem socket do Core em {}: {e}", path.display()),
            e.kind(),
        ),
        Ok(m) if !m.file_type().is_socket() => Item::warn(
            "destino",
            format!("{} existe, mas nao e um socket", path.display()),
            Some(
                "aponte --socket para o socket do Core (o padrao e /var/run/psychoscope/core.sock)"
                    .into(),
            ),
        ),
        Ok(_) if !writable(path) => warn(
            format!("sem permissao de escrita em {}", path.display()),
            std::io::ErrorKind::PermissionDenied,
        ),
        Ok(_) => Item::ok(
            "destino",
            format!(
                "socket do Core em {} com permissao de escrita (nao conectei, para nao gerar um handshake incompleto no log do Core)",
                path.display()
            ),
        ),
    }
}

/// O usuario efetivo pode escrever no caminho (`access(2)`; o mesmo que o connect exige).
fn writable(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` e uma string C valida e termina em NUL durante a chamada; access so le o caminho.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
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
    fn a_present_core_socket_is_ok_and_an_unknown_interface_is_never_ok() {
        let d = dir("core");
        let sock = d.join("core.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let cfg = parse(&["-i", "nao-existe-xyz0", "--socket", sock.to_str().unwrap()]);
        let r = run(&cfg);
        assert_eq!(status_of(&r, "destino"), Status::Ok, "{}", r.render());
        assert_ne!(status_of(&r, "fonte"), Status::Ok, "{}", r.render());
        std::fs::remove_dir_all(d).unwrap();
    }

    /// Escreve um pcap vazio com o enlace `dlt` (113 = Linux cooked v1).
    fn empty_pcap(d: &std::path::Path, dlt: u32) -> std::path::PathBuf {
        let path = d.join(format!("dlt{dlt}.pcap"));
        let mut f = std::fs::File::create(&path).unwrap();
        write_pcap(&mut f, dlt, 65535, &[]).unwrap();
        path
    }

    fn item<'a>(r: &'a Report, what: &str) -> &'a Item {
        r.0.iter()
            .find(|i| i.what == what)
            .unwrap_or_else(|| panic!("sem item {what}"))
    }

    #[test]
    fn the_filter_is_validated_on_the_real_link_not_only_on_ethernet() {
        let d = dir("link");
        let sll = empty_pcap(&d, 113);
        // vale no enlace real (Linux cooked) e e aceito tambem como Ethernet
        let ok = run(&parse(&[
            "--pcap-file",
            sll.to_str().unwrap(),
            "--bpf",
            "inbound",
            "--print",
        ]));
        assert_eq!(item(&ok, "filtro BPF").status, Status::Ok);
        assert!(
            item(&ok, "filtro BPF").detail.contains("LinuxSll"),
            "{}",
            ok.render()
        );
        // `ether host` nao vale em Linux cooked: a falha vem do enlace real, com a causa do libpcap
        let bad = run(&parse(&[
            "--pcap-file",
            sll.to_str().unwrap(),
            "--bpf",
            "ether host 02:00:00:00:00:01",
            "--print",
        ]));
        assert_eq!(
            item(&bad, "filtro BPF").status,
            Status::Fail,
            "{}",
            bad.render()
        );
        assert!(
            item(&bad, "filtro BPF")
                .fix
                .as_deref()
                .unwrap()
                .contains("pcap-filter")
        );
        assert_eq!(
            item(&bad, "captura").status,
            Status::Warn,
            "sem repetir a mesma falha"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn without_the_real_link_only_syntax_errors_are_failures() {
        // fonte inexistente: a captura nao abre, entao so da para conferir contra Ethernet
        let missing = "/tmp/nao-existe-check.pcap";
        let syntax = run(&parse(&[
            "--pcap-file",
            missing,
            "--bpf",
            "udp port",
            "--print",
        ]));
        assert_eq!(item(&syntax, "filtro BPF").status, Status::Fail);
        // valido como Ethernet: aceito, dizendo que falta a confirmacao no enlace real
        let fine = run(&parse(&[
            "--pcap-file",
            missing,
            "--bpf",
            "udp port 53",
            "--print",
        ]));
        assert_eq!(item(&fine, "filtro BPF").status, Status::Ok);
        assert!(item(&fine, "filtro BPF").detail.contains("enlace real"));
        // invalido so como Ethernet (nao e erro de sintaxe): aviso, nao falha
        let link_specific = run(&parse(&[
            "--pcap-file",
            missing,
            "--bpf",
            "ifname eth0",
            "--print",
        ]));
        assert_eq!(
            item(&link_specific, "filtro BPF").status,
            Status::Warn,
            "{}",
            link_specific.render()
        );
    }

    #[test]
    fn the_core_socket_is_checked_without_connecting() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("sock");
        let pcap = pcap_in(&d);
        let dest = |sock: &std::path::Path| {
            let r = run(&parse(&[
                "--pcap-file",
                pcap.to_str().unwrap(),
                "--socket",
                sock.to_str().unwrap(),
            ]));
            let i = item(&r, "destino");
            (i.status, i.detail.clone(), i.fix.clone())
        };
        // um arquivo comum no lugar do socket
        let file = d.join("nao-e-socket");
        std::fs::write(&file, b"x").unwrap();
        let (st, detail, fix) = dest(&file);
        assert_eq!(st, Status::Warn);
        assert!(
            detail.contains("nao e um socket") && fix.unwrap().contains("--socket"),
            "{detail}"
        );
        // um socket que ninguem escuta: presente e gravavel, e a conferencia nao conecta (nao ha
        // erro de conexao recusada, nem "handshake falhou" no log de um Core de verdade)
        let sock = d.join("parado.sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        let (st, detail, _) = dest(&sock);
        assert_eq!(st, Status::Ok, "{detail}");
        assert!(detail.contains("nao conectei"), "{detail}");
        // sem permissao de escrita (nao vale como root, que ignora o modo)
        // SAFETY: geteuid nao tem precondicoes e nao falha.
        if unsafe { libc::geteuid() } != 0 {
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o400)).unwrap();
            let (st, detail, fix) = dest(&sock);
            assert_eq!(st, Status::Warn);
            assert!(
                detail.contains("sem permissao de escrita")
                    && fix.unwrap().contains("modo e grupo"),
                "{detail}"
            );
        }
        std::fs::remove_dir_all(d).unwrap();
    }
}
