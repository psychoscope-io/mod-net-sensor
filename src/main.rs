//! Binario do sensor: liga captura -> decode -> destino (Core ou terminal) e cuida da partida
//! e do encerramento. A logica de cada etapa vive nos modulos da biblioteca.
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mod_net_sensor::capture::sniffer::{self, CaptureConfig, CaptureHandle, Captured, Source};
use mod_net_sensor::config::{Config, PrintFormat};
use mod_net_sensor::explain::{self, CaptureContext};
use mod_net_sensor::ipc::client::{Client, ClientConfig, ClientCounters, Controller, Exit};
use mod_net_sensor::pipeline::{PipelineCounters, SensorController, decode_loop};
use mod_net_sensor::summary::{self, Destination, Snapshot};
use mod_net_sensor::{check, interfaces, output};
use psychoscope_proto::v1::EventoFluxoRede;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Intervalo da linha de resumo de `--verbose`.
const VERBOSE_EVERY: Duration = Duration::from_secs(10);

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ! {
    let mut cfg = Config::parse_checked();
    if cfg.list_interfaces {
        exit_after_listing_interfaces();
    }
    if cfg.check {
        let report = check::run(&cfg);
        print!("{}", report.render());
        std::process::exit(i32::from(!report.passed()));
    }
    if cfg.print.is_some() && cfg.pcap_file.is_some() {
        cfg.exit_on_eof = true; // replay para o terminal acaba quando o arquivo acaba
    }
    let source = source_of(&cfg);
    // Arquivo = sem perdas (espera espaco); captura ao vivo descarta e conta.
    let lossless = matches!(source, Source::File(_));
    let (pkt_tx, pkt_rx) = mpsc::channel(cfg.queue_size);
    let (ev_tx, ev_rx) = mpsc::channel(cfg.queue_size);

    let capture = start_capture(&cfg, source, pkt_tx);
    let pipeline = Arc::new(PipelineCounters::default());
    let ctl = Arc::new(SensorController {
        paused: capture.paused.clone(),
        capture: capture.counters.clone(),
        pipeline: pipeline.clone(),
        reconfig: capture.reconfig.clone(),
    });
    let decoder = tokio::spawn(decode_loop(pkt_rx, ev_tx, cfg.emit, lossless, pipeline));

    let (sink, run) = Sink::new(&cfg, ctl);
    let capture_end = watch_capture(capture);
    if cfg.verbose {
        tokio::spawn(report_periodically(run.clone()));
    }
    let (exit, failure) = sink
        .run(ev_rx, shutdown_on_signal(), capture_end.errors)
        .await;
    finish(
        exit,
        failure,
        capture_end.stop,
        capture_end.join,
        decoder,
        &run,
    )
    .await
}

/// Imprime as interfaces e sai (0, ou 1 se o libpcap nao as puder listar).
fn exit_after_listing_interfaces() -> ! {
    match interfaces::list() {
        Ok(list) => {
            print!("{}", interfaces::render(&list));
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("mod-net-sensor: nao foi possivel listar as interfaces: {e}");
            std::process::exit(1);
        }
    }
}

fn source_of(cfg: &Config) -> Source {
    match (&cfg.interface, &cfg.pcap_file) {
        (Some(i), _) => Source::Interface(i.clone()),
        (None, Some(f)) => Source::File(f.clone()),
        (None, None) => unreachable!("Config::parse_checked exige uma fonte"),
    }
}

/// Abre a captura; se falhar (permissao, interface, arquivo, filtro), explica o que fazer e
/// encerra com status 1.
fn start_capture(cfg: &Config, source: Source, tx: mpsc::Sender<Captured>) -> CaptureHandle {
    let capture_cfg = CaptureConfig {
        source,
        bpf: cfg.bpf.clone(),
        snaplen: cfg.snaplen,
        promisc: !cfg.no_promisc,
    };
    sniffer::spawn(&capture_cfg, tx).unwrap_or_else(|e| {
        eprintln!("mod-net-sensor: nao foi possivel iniciar a captura: {e}");
        let available = interfaces::list()
            .map(|l| interfaces::names(&l))
            .unwrap_or_default();
        let exe = std::env::current_exe()
            .map_or_else(|_| "<binario>".to_string(), |p| p.display().to_string());
        let ctx = CaptureContext {
            interface: cfg.interface.as_deref(),
            pcap_file: cfg.pcap_file.as_deref(),
            available: &available,
            exe: &exe,
        };
        if let Some(hint) = explain::capture_hint(&e.to_string(), &ctx) {
            eprintln!("  dica: {hint}");
        }
        eprintln!("  para conferir o ambiente inteiro: mod-net-sensor --check <as mesmas opcoes>");
        std::process::exit(1);
    })
}

/// Fim da thread de captura: erro (se houver), sinal de parada e tarefa que espera a thread.
struct CaptureEnd {
    errors: mpsc::Receiver<String>,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

/// Uma thread de captura que termina com erro (interface caiu, etc.) derruba o sensor com
/// status != 0, para que o supervisor o reinicie.
fn watch_capture(capture: CaptureHandle) -> CaptureEnd {
    let stop = capture.stop.clone();
    let (err_tx, errors) = mpsc::channel::<String>(1);
    let join = tokio::task::spawn_blocking(move || {
        if let Ok(Err(e)) = capture.join.join() {
            let _ = err_tx.blocking_send(e.to_string());
        }
    });
    CaptureEnd { errors, stop, join }
}

/// Canal que vira `true` ao receber SIGTERM ou SIGINT.
fn shutdown_on_signal() -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
    tokio::spawn(async move {
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        let _ = tx.send(true);
    });
    rx
}

/// O que o resumo precisa saber da execucao em andamento.
struct Run {
    ctl: Arc<SensorController>,
    started: Instant,
    dest: Destination,
    delivered: Delivered,
}

/// Onde ler quantos eventos ja foram entregues.
enum Delivered {
    Core(Arc<ClientCounters>),
    Printed(Arc<AtomicU64>),
}

impl Run {
    fn snapshot(&self) -> Snapshot {
        let stats = self.ctl.stats();
        let (delivered, ipc_dropped) = match &self.delivered {
            Delivered::Core(c) => (
                c.events_sent.load(Ordering::Relaxed),
                c.events_dropped.load(Ordering::Relaxed),
            ),
            Delivered::Printed(n) => (n.load(Ordering::Relaxed), 0),
        };
        Snapshot {
            elapsed: self.started.elapsed(),
            captured: stats.packets_captured,
            bytes: stats.bytes,
            counters: stats.counters,
            delivered,
            ipc_dropped,
        }
    }

    /// O destino com o numero de sessoes que o Core aceitou ate agora.
    fn destination(&self) -> Destination {
        match (&self.dest, &self.delivered) {
            (Destination::Core { socket, .. }, Delivered::Core(c)) => Destination::Core {
                socket: socket.clone(),
                sessions: c.sessions.load(Ordering::Relaxed),
            },
            _ => Destination::Print,
        }
    }
}

/// Imprime uma linha de resumo a cada `VERBOSE_EVERY` (opcao `--verbose`).
async fn report_periodically(run: Arc<Run>) {
    let mut prev = run.snapshot();
    let mut tick = tokio::time::interval(VERBOSE_EVERY);
    tick.tick().await; // o primeiro tick e imediato
    loop {
        tick.tick().await;
        let now = run.snapshot();
        eprintln!("mod-net-sensor: {}", summary::periodic_line(&prev, &now));
        prev = now;
    }
}

/// Para onde os eventos vao.
enum Sink {
    Core(Client<SensorController>),
    Print(PrintFormat, Arc<AtomicU64>),
}

impl Sink {
    fn new(cfg: &Config, ctl: Arc<SensorController>) -> (Self, Arc<Run>) {
        let (sink, dest, delivered) = match cfg.print {
            Some(format) => {
                let printed = Arc::new(AtomicU64::new(0));
                (
                    Self::Print(format, printed.clone()),
                    Destination::Print,
                    Delivered::Printed(printed),
                )
            }
            None => {
                let client = Client::new(
                    ClientConfig::new(
                        cfg.socket.clone(),
                        cfg.module_id.clone(),
                        env!("CARGO_PKG_VERSION").to_string(),
                    ),
                    ctl.clone(),
                )
                .exit_when_drained(cfg.exit_on_eof);
                let counters = client.counters.clone();
                let dest = Destination::Core {
                    socket: cfg.socket.clone(),
                    sessions: 0,
                };
                (Self::Core(client), dest, Delivered::Core(counters))
            }
        };
        let run = Arc::new(Run {
            ctl,
            started: Instant::now(),
            dest,
            delivered,
        });
        (sink, run)
    }

    /// Roda o destino ate sinal, ENCERRAR, fim dos eventos ou falha da captura.
    async fn run(
        self,
        events: mpsc::Receiver<EventoFluxoRede>,
        mut shutdown: watch::Receiver<bool>,
        mut capture_errors: mpsc::Receiver<String>,
    ) -> (Exit, Option<String>) {
        match self {
            Self::Core(client) => {
                tokio::select! {
                    e = client.run(events, shutdown) => (e, None),
                    Some(msg) = capture_errors.recv() => (Exit::Shutdown, Some(msg)),
                }
            }
            Self::Print(format, printed) => {
                let printer = spawn_printer(events, format, printed);
                tokio::select! {
                    _ = printer => (Exit::Drained, None),
                    _ = shutdown.wait_for(|stop| *stop) => (Exit::Shutdown, None),
                    Some(msg) = capture_errors.recv() => (Exit::Shutdown, Some(msg)),
                }
            }
        }
    }
}

/// Escreve cada evento no stdout (texto ou JSON). Termina quando os eventos acabam ou quando
/// o stdout fecha (por exemplo `| head`).
fn spawn_printer(
    mut events: mpsc::Receiver<EventoFluxoRede>,
    format: PrintFormat,
    printed: Arc<AtomicU64>,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        while let Some(ev) = events.blocking_recv() {
            let line = match format {
                PrintFormat::Text => output::render_text(&ev),
                PrintFormat::Json => output::render_json(&ev),
            };
            if writeln!(out, "{line}").is_err() {
                return; // stdout fechado
            }
            printed.fetch_add(1, Ordering::Relaxed);
            if events.is_empty() && out.flush().is_err() {
                return;
            }
        }
        let _ = out.flush();
    })
}

/// Encerramento ordenado, resumo e saida do processo.
async fn finish(
    exit: Exit,
    failure: Option<String>,
    stop: Arc<AtomicBool>,
    capture_join: JoinHandle<()>,
    decoder: JoinHandle<()>,
    run: &Run,
) -> ! {
    eprintln!("mod-net-sensor: encerrando ({exit:?})");
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(3), capture_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), decoder).await;
    eprint!(
        "mod-net-sensor: {}",
        summary::final_report(&run.snapshot(), &run.destination())
    );

    let code = match failure {
        Some(msg) => {
            eprintln!("mod-net-sensor: falha na captura: {msg}");
            1
        }
        None => 0,
    };
    // Sai sem esperar o runtime: uma tarefa bloqueante presa nao pode impedir o encerramento.
    std::process::exit(code);
}
