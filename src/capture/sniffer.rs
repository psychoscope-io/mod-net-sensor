//! Captura via libpcap em uma thread dedicada (a leitura pcap e bloqueante e nao deve
//! ocupar o runtime Tokio). Os pacotes seguem por um canal limitado: quando o consumidor
//! nao acompanha, o pacote e descartado e contado — a captura nunca bloqueia nem acumula
//! memoria sem limite no modo ao vivo.
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use pcap::{Activated, Active, Capture, Error as PcapError, Offline};
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
    #[error(
        "tipo de enlace nao suportado (DLT {0}); aceitos: {supported}",
        supported = crate::protocols::SUPPORTED_DLT
    )]
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
    /// Pacotes descartados pelo buffer do kernel (`ps_drop` do `pcap_stats`).
    pub kernel_dropped: AtomicU64,
    /// Pacotes descartados pela interface (`ps_ifdrop` do `pcap_stats`).
    pub interface_dropped: AtomicU64,
    /// Descartes por canal cheio (consumidor lento).
    pub channel_dropped: AtomicU64,
}

/// Descartes acumulados que o libpcap informa para a captura aberta.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct KernelStats {
    dropped: u64,
    if_dropped: u64,
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
        Source::Interface(name) => (spawn_live(cfg, name, ctx)?, true),
        Source::File(path) => (spawn_file(cfg, path, ctx)?, false),
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

type CaptureThread = JoinHandle<Result<(), CaptureError>>;

/// Abre a interface (permissao, buffer do kernel, filtro BPF) sem iniciar a leitura.
fn open_live(cfg: &CaptureConfig, name: &str) -> Result<Capture<Active>, CaptureError> {
    let mut cap = Capture::from_device(name)?
        .promisc(cfg.promisc)
        .snaplen(cfg.snaplen)
        .timeout(READ_TIMEOUT_MS)
        .immediate_mode(true)
        .buffer_size(KERNEL_BUFFER_BYTES)
        .open()?;
    if let Some(f) = &cfg.bpf {
        cap.filter(f, true)?;
    }
    Ok(cap)
}

/// Abre o arquivo pcap (e o filtro BPF) sem iniciar a leitura.
fn open_file(cfg: &CaptureConfig, path: &Path) -> Result<Capture<Offline>, CaptureError> {
    let mut cap = Capture::from_file(path)?;
    if let Some(f) = &cfg.bpf {
        cap.filter(f, true)?;
    }
    Ok(cap)
}

/// Confere se a fonte abre como `spawn` abriria (interface, permissao, arquivo, filtro BPF e
/// tipo de enlace) e a fecha em seguida, sem capturar nada. Para `--check`.
pub fn probe(cfg: &CaptureConfig) -> Result<LinkType, CaptureError> {
    match &cfg.source {
        Source::Interface(name) => link_of(&open_live(cfg, name)?),
        Source::File(path) => link_of(&open_file(cfg, path)?),
    }
}

/// Valida a sintaxe de um filtro BPF sem abrir interface alguma (nao exige permissao).
pub fn check_bpf(expr: &str) -> Result<(), CaptureError> {
    Capture::dead(pcap::Linktype::ETHERNET)?.compile(expr, true)?;
    Ok(())
}

/// Abre a interface em modo nao bloqueante e inicia a thread de captura ao vivo.
fn spawn_live(cfg: &CaptureConfig, name: &str, ctx: Ctx) -> Result<CaptureThread, CaptureError> {
    // com immediate_mode o timeout do libpcap pode nao valer: espera via poll(2)
    let cap = open_live(cfg, name)?.setnonblock()?;
    let link = link_of(&cap)?;
    let fd = cap.as_raw_fd();
    std::thread::Builder::new()
        .name("pcap-live".into())
        .spawn(move || {
            run(
                cap,
                link,
                true,
                ctx,
                |c: &mut Capture<Active>| {
                    c.stats().ok().map(|s| KernelStats {
                        dropped: u64::from(s.dropped),
                        if_dropped: u64::from(s.if_dropped),
                    })
                },
                move || wait_readable(fd),
            )
        })
        .map_err(CaptureError::Thread)
}

/// Abre o arquivo pcap e inicia a thread de leitura (sem perdas, sem estatisticas do kernel).
fn spawn_file(cfg: &CaptureConfig, path: &Path, ctx: Ctx) -> Result<CaptureThread, CaptureError> {
    let cap = open_file(cfg, path)?;
    let link = link_of(&cap)?;
    std::thread::Builder::new()
        .name("pcap-file".into())
        .spawn(move || run(cap, link, false, ctx, |_| None, || {}))
        .map_err(CaptureError::Thread)
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
    mut stats: impl FnMut(&mut Capture<T>) -> Option<KernelStats>,
    mut idle_wait: impl FnMut(),
) -> Result<(), CaptureError> {
    let mut last_stats = Instant::now();
    let mut seen = KernelStats::default();
    while !ctx.stop.load(Relaxed) {
        apply_reconfig(&mut cap, live, &ctx);
        match cap.next_packet() {
            Ok(p) => {
                if forward(&ctx, link, live, &p) == Flow::Stop {
                    break;
                }
            }
            Err(PcapError::TimeoutExpired) => idle_wait(),
            Err(PcapError::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
        if last_stats.elapsed() >= STATS_EVERY {
            last_stats = Instant::now();
            record_kernel_drops(&ctx, &mut seen, stats(&mut cap));
        }
    }
    record_kernel_drops(&ctx, &mut seen, stats(&mut cap));
    Ok(())
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// Atende os pedidos de novo filtro BPF (so na captura ao vivo).
fn apply_reconfig<T: Activated + ?Sized>(cap: &mut Capture<T>, live: bool, ctx: &Ctx) {
    while let Ok(req) = ctx.reconfig.try_recv() {
        let r = if live {
            cap.filter(&req.bpf, true).map_err(|e| e.to_string())
        } else {
            Err("reconfiguracao nao suportada na leitura de arquivo".to_string())
        };
        let _ = req.reply.send(r);
    }
}

/// Conta o pacote e o entrega ao decodificador. Ao vivo, canal cheio = descarte contado;
/// arquivo, espera espaco (sem perdas). `Stop` quando o consumidor foi encerrado.
fn forward(ctx: &Ctx, link: LinkType, live: bool, p: &pcap::Packet<'_>) -> Flow {
    ctx.counters.captured.fetch_add(1, Relaxed);
    ctx.counters
        .bytes
        .fetch_add(u64::from(p.header.len), Relaxed);
    if ctx.paused.load(Relaxed) {
        return Flow::Continue; // continua drenando o pcap para nao encher o buffer do kernel
    }
    let pkt = Captured {
        ts: timestamp(p.header.ts.tv_sec, p.header.ts.tv_usec),
        wire_len: p.header.len,
        link,
        data: p.data.to_vec(),
    };
    if !live {
        return if ctx.tx.blocking_send(pkt).is_err() {
            Flow::Stop
        } else {
            Flow::Continue
        };
    }
    match ctx.tx.try_send(pkt) {
        Ok(()) => Flow::Continue,
        Err(mpsc::error::TrySendError::Full(_)) => {
            ctx.counters.channel_dropped.fetch_add(1, Relaxed);
            Flow::Continue
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Flow::Stop,
    }
}

/// Soma aos totais o que o kernel descartou desde a ultima leitura (`seen`). Se o valor
/// informado regride (as estatisticas reiniciaram, por exemplo ao trocar o filtro), ele e
/// tomado como novo ponto de partida em vez de ser descartado ou de apagar o total.
fn record_kernel_drops(ctx: &Ctx, seen: &mut KernelStats, now: Option<KernelStats>) {
    let Some(now) = now else { return };
    let c = &ctx.counters;
    c.kernel_dropped
        .fetch_add(growth(now.dropped, seen.dropped), Relaxed);
    c.interface_dropped
        .fetch_add(growth(now.if_dropped, seen.if_dropped), Relaxed);
    *seen = now;
}

fn growth(now: u64, seen: u64) -> u64 {
    if now >= seen { now - seen } else { now }
}

#[cfg(test)]
mod tests;
