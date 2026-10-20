//! Captura via libpcap em uma thread dedicada (a leitura pcap e bloqueante e nao deve
//! ocupar o runtime Tokio). Os pacotes seguem por um canal limitado: quando o consumidor
//! nao acompanha, o pacote e descartado e contado — a captura nunca bloqueia nem acumula
//! memoria sem limite no modo ao vivo.
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use pcap::{Activated, Active, Capture, Error as PcapError};
use tokio::sync::{mpsc, oneshot};

use crate::protocols::LinkType;

/// Bytes capturados por pacote: suficiente para cabecalhos + ClientHello tipico.
pub const DEFAULT_SNAPLEN: i32 = 2048;
const READ_TIMEOUT_MS: i32 = 200;
const KERNEL_BUFFER_BYTES: i32 = 8 << 20;
const STATS_EVERY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub enum Source {
    Interface(String),
    /// Leitura offline de um arquivo pcap (testes, replay forense).
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub source: Source,
    pub bpf: Option<String>,
    pub snaplen: i32,
    pub promisc: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("pcap: {0}")]
    Pcap(#[from] PcapError),
    #[error("tipo de enlace nao suportado (DLT {0})")]
    UnsupportedLink(i32),
    #[error("falha ao iniciar a thread de captura: {0}")]
    Thread(std::io::Error),
}

/// Pacote bruto entregue ao decodificador.
#[derive(Debug)]
pub struct Captured {
    pub ts: SystemTime,
    /// Tamanho original na rede (pode exceder `data.len()` quando o snaplen truncou).
    pub wire_len: u32,
    pub link: LinkType,
    pub data: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct CaptureCounters {
    /// Pacotes lidos do pcap.
    pub captured: AtomicU64,
    /// Bytes (tamanho original na rede) dos pacotes lidos.
    pub bytes: AtomicU64,
    /// Descartes do kernel/interface informados por `pcap_stats`.
    pub kernel_dropped: AtomicU64,
    /// Descartes por canal cheio (consumidor lento).
    pub channel_dropped: AtomicU64,
}

pub struct ReconfigRequest {
    pub bpf: String,
    pub reply: oneshot::Sender<Result<(), String>>,
}

pub struct CaptureHandle {
    pub join: JoinHandle<Result<(), CaptureError>>,
    pub stop: Arc<AtomicBool>,
    pub paused: Arc<AtomicBool>,
    pub counters: Arc<CaptureCounters>,
    pub reconfig: std::sync::mpsc::Sender<ReconfigRequest>,
    pub live: bool,
}

fn timestamp(tv_sec: i64, tv_usec: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        + Duration::new(
            tv_sec.max(0) as u64,
            (tv_usec.clamp(0, 999_999) * 1000) as u32,
        )
}

/// Abre a fonte (erros como falta de permissao aparecem aqui, de forma sincrona) e
/// inicia a thread de captura.
pub fn spawn(
    cfg: &CaptureConfig,
    tx: mpsc::Sender<Captured>,
) -> Result<CaptureHandle, CaptureError> {
    let stop = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(CaptureCounters::default());
    let (rtx, rrx) = std::sync::mpsc::channel::<ReconfigRequest>();

    let ctx = Ctx {
        tx,
        stop: stop.clone(),
        paused: paused.clone(),
        counters: counters.clone(),
        reconfig: rrx,
    };
    let (join, live) = match &cfg.source {
        Source::Interface(name) => {
            let mut cap = Capture::from_device(name.as_str())?
                .promisc(cfg.promisc)
                .snaplen(cfg.snaplen)
                .timeout(READ_TIMEOUT_MS)
                .immediate_mode(true)
                .buffer_size(KERNEL_BUFFER_BYTES)
                .open()?
                .setnonblock()?; // com immediate_mode o timeout do libpcap pode nao valer: espera via poll(2)
            if let Some(f) = &cfg.bpf {
                cap.filter(f, true)?;
            }
            let link = link_of(&cap)?;
            let fd = cap.as_raw_fd();
            let j = std::thread::Builder::new()
                .name("pcap-live".into())
                .spawn(move || {
                    run(
                        cap,
                        link,
                        true,
                        ctx,
                        |c: &mut Capture<Active>| {
                            c.stats()
                                .ok()
                                .map(|s| u64::from(s.dropped) + u64::from(s.if_dropped))
                        },
                        move || wait_readable(fd),
                    )
                })
                .map_err(CaptureError::Thread)?;
            (j, true)
        }
        Source::File(path) => {
            let mut cap = Capture::from_file(path)?;
            if let Some(f) = &cfg.bpf {
                cap.filter(f, true)?;
            }
            let link = link_of(&cap)?;
            let j = std::thread::Builder::new()
                .name("pcap-file".into())
                .spawn(move || run(cap, link, false, ctx, |_| None, || {}))
                .map_err(CaptureError::Thread)?;
            (j, false)
        }
    };
    Ok(CaptureHandle {
        join,
        stop,
        paused,
        counters,
        reconfig: rtx,
        live,
    })
}

/// Espera ate `fd` ficar legivel ou 100 ms passarem (limite para reavaliar `stop`).
fn wait_readable(fd: RawFd) {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `p` e valido durante a chamada e nfds = 1; EINTR/erros apenas antecipam o retorno.
    unsafe { libc::poll(&mut p, 1, 100) };
}

fn link_of<T: Activated + ?Sized>(cap: &Capture<T>) -> Result<LinkType, CaptureError> {
    let dlt = cap.get_datalink().0;
    LinkType::from_dlt(dlt).ok_or(CaptureError::UnsupportedLink(dlt))
}

struct Ctx {
    tx: mpsc::Sender<Captured>,
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    counters: Arc<CaptureCounters>,
    reconfig: std::sync::mpsc::Receiver<ReconfigRequest>,
}

fn run<T: Activated + ?Sized>(
    mut cap: Capture<T>,
    link: LinkType,
    live: bool,
    ctx: Ctx,
    mut stats: impl FnMut(&mut Capture<T>) -> Option<u64>,
    mut idle_wait: impl FnMut(),
) -> Result<(), CaptureError> {
    let mut last_stats = Instant::now();
    while !ctx.stop.load(Relaxed) {
        while let Ok(req) = ctx.reconfig.try_recv() {
            let r = if live {
                cap.filter(&req.bpf, true).map_err(|e| e.to_string())
            } else {
                Err("reconfiguracao nao suportada na leitura de arquivo".to_string())
            };
            let _ = req.reply.send(r);
        }

        match cap.next_packet() {
            Ok(p) => {
                ctx.counters.captured.fetch_add(1, Relaxed);
                ctx.counters
                    .bytes
                    .fetch_add(u64::from(p.header.len), Relaxed);
                if ctx.paused.load(Relaxed) {
                    continue; // continua drenando o pcap para nao encher o buffer do kernel
                }
                let pkt = Captured {
                    ts: timestamp(p.header.ts.tv_sec, p.header.ts.tv_usec),
                    wire_len: p.header.len,
                    link,
                    data: p.data.to_vec(),
                };
                if live {
                    match ctx.tx.try_send(pkt) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            ctx.counters.channel_dropped.fetch_add(1, Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                } else if ctx.tx.blocking_send(pkt).is_err() {
                    break; // arquivo: sem perdas; consumidor encerrado
                }
            }
            Err(PcapError::TimeoutExpired) => idle_wait(),
            Err(PcapError::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }

        if last_stats.elapsed() >= STATS_EVERY {
            last_stats = Instant::now();
            if let Some(d) = stats(&mut cap) {
                ctx.counters.kernel_dropped.store(d, Relaxed);
            }
        }
    }
    if let Some(d) = stats(&mut cap) {
        ctx.counters.kernel_dropped.store(d, Relaxed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::pcapfile::{LINKTYPE_ETHERNET, PcapPacket, write_pcap};
    use crate::protocols::testutil::*;

    fn fixture(dir: &tempfile_dir::Dir, linktype: u32, pkts: &[PcapPacket<'_>]) -> PathBuf {
        let path = dir.path.join("t.pcap");
        let mut f = std::fs::File::create(&path).unwrap();
        write_pcap(&mut f, linktype, 65535, pkts).unwrap();
        path
    }

    /// Diretorio temporario sem dependencia externa.
    mod tempfile_dir {
        use std::path::PathBuf;
        pub struct Dir {
            pub path: PathBuf,
        }
        impl Dir {
            pub fn new(tag: &str) -> Self {
                let path =
                    std::env::temp_dir().join(format!("sniffer-{tag}-{}", std::process::id()));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    fn cfg(path: PathBuf, bpf: Option<&str>) -> CaptureConfig {
        CaptureConfig {
            source: Source::File(path),
            bpf: bpf.map(String::from),
            snaplen: DEFAULT_SNAPLEN,
            promisc: false,
        }
    }

    fn drain(mut rx: mpsc::Receiver<Captured>) -> Vec<Captured> {
        let mut v = Vec::new();
        while let Ok(p) = rx.try_recv() {
            v.push(p);
        }
        v
    }

    #[test]
    fn replays_file_in_order_with_timestamps_and_wire_len() {
        let dir = tempfile_dir::Dir::new("order");
        let dns = eth_v4(17, &udp(5000, 53, &dns_query("a.com", 1)));
        let syn = eth_v4(6, &tcp(1, 80, 0x02, &[]));
        let path = fixture(
            &dir,
            LINKTYPE_ETHERNET,
            &[
                PcapPacket {
                    ts_sec: 1_700_000_000,
                    ts_usec: 250_000,
                    data: &dns,
                    wire_len: None,
                },
                PcapPacket {
                    ts_sec: 1_700_000_001,
                    ts_usec: 0,
                    data: &syn[..30],
                    wire_len: Some(syn.len() as u32),
                },
            ],
        );
        let (tx, rx) = mpsc::channel(16);
        let h = spawn(&cfg(path, None), tx).unwrap();
        assert!(!h.live);
        h.join.join().unwrap().unwrap();
        let got = drain(rx);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].data, dns);
        assert_eq!(got[0].link, LinkType::Ethernet);
        assert_eq!(
            got[0].ts,
            SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 250_000_000)
        );
        assert_eq!(
            (got[1].data.len(), got[1].wire_len),
            (30, syn.len() as u32),
            "snaplen truncou, wire_len preservado"
        );
        assert_eq!(h.counters.captured.load(Relaxed), 2);
        assert_eq!(
            h.counters.bytes.load(Relaxed),
            (dns.len() + syn.len()) as u64
        );
    }

    #[test]
    fn bpf_filter_applies_to_files() {
        let dir = tempfile_dir::Dir::new("bpf");
        let dns = eth_v4(17, &udp(5000, 53, &dns_query("a.com", 1)));
        let other = eth_v4(17, &udp(5000, 9999, b"x"));
        let path = fixture(
            &dir,
            LINKTYPE_ETHERNET,
            &[
                PcapPacket {
                    ts_sec: 1,
                    ts_usec: 0,
                    data: &other,
                    wire_len: None,
                },
                PcapPacket {
                    ts_sec: 2,
                    ts_usec: 0,
                    data: &dns,
                    wire_len: None,
                },
            ],
        );
        let (tx, rx) = mpsc::channel(16);
        let h = spawn(&cfg(path, Some("udp port 53")), tx).unwrap();
        h.join.join().unwrap().unwrap();
        let got = drain(rx);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, dns);
    }

    #[test]
    fn invalid_bpf_unsupported_link_and_missing_file_fail_synchronously() {
        let dir = tempfile_dir::Dir::new("errs");
        let path = fixture(&dir, LINKTYPE_ETHERNET, &[]);
        let (tx, _rx) = mpsc::channel(1);
        assert!(matches!(
            spawn(&cfg(path.clone(), Some("isto nao e bpf ((")), tx.clone()),
            Err(CaptureError::Pcap(_))
        ));

        let weird = dir.path.join("weird.pcap");
        let mut f = std::fs::File::create(&weird).unwrap();
        write_pcap(&mut f, 147, 65535, &[]).unwrap();
        assert!(matches!(
            spawn(&cfg(weird, None), tx.clone()),
            Err(CaptureError::UnsupportedLink(147))
        ));

        assert!(matches!(
            spawn(&cfg(dir.path.join("nao-existe.pcap"), None), tx),
            Err(CaptureError::Pcap(_))
        ));
    }

    #[test]
    fn reconfigure_is_rejected_for_files_and_stop_ends_thread() {
        let dir = tempfile_dir::Dir::new("reconf");
        let pkt = eth_v4(17, &udp(1, 2, b"x"));
        let many: Vec<PcapPacket<'_>> = (0..1000)
            .map(|i| PcapPacket {
                ts_sec: i,
                ts_usec: 0,
                data: &pkt,
                wire_len: None,
            })
            .collect();
        let path = fixture(&dir, LINKTYPE_ETHERNET, &many);
        let (tx, rx) = mpsc::channel(1); // pequeno: a thread bloqueia no blocking_send
        let h = spawn(&cfg(path, None), tx).unwrap();

        let (otx, orx) = oneshot::channel();
        h.reconfig
            .send(ReconfigRequest {
                bpf: "udp".into(),
                reply: otx,
            })
            .unwrap();
        h.stop.store(true, Relaxed);
        drop(rx); // libera a thread bloqueada no envio
        let _ = h.join.join().unwrap();
        // A resposta pode nao ter sido processada se stop venceu a corrida; se foi, deve ser erro.
        if let Ok(r) = orx.blocking_recv() {
            assert!(r.is_err());
        }
    }

    #[test]
    fn timestamp_helper_clamps_garbage() {
        assert_eq!(timestamp(-5, -1), SystemTime::UNIX_EPOCH);
        assert_eq!(
            timestamp(1, 5_000_000),
            SystemTime::UNIX_EPOCH + Duration::new(1, 999_999_000)
        );
    }
}
