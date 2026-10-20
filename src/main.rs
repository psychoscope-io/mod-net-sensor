//! Binario do sensor: liga captura -> decode -> cliente IPC e cuida da partida e do
//! encerramento. A logica de cada etapa vive nos modulos da biblioteca.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mod_net_sensor::capture::sniffer::{self, CaptureConfig, CaptureHandle, Captured, Source};
use mod_net_sensor::config::Config;
use mod_net_sensor::ipc::client::{Client, ClientConfig, Exit};
use mod_net_sensor::pipeline::{PipelineCounters, SensorController, decode_loop};
use psychoscope_proto::v1::EventoFluxoRede;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ! {
    let cfg = Config::parse_checked();
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

    let client = Client::new(
        ClientConfig::new(
            cfg.socket.clone(),
            cfg.module_id.clone(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        ctl,
    )
    .exit_when_drained(cfg.exit_on_eof);

    let capture_end = watch_capture(capture);
    let (exit, failure) =
        run_until_done(client, ev_rx, shutdown_on_signal(), capture_end.errors).await;
    finish(exit, failure, capture_end.stop, capture_end.join, decoder).await
}

fn source_of(cfg: &Config) -> Source {
    match (&cfg.interface, &cfg.pcap_file) {
        (Some(i), _) => Source::Interface(i.clone()),
        (None, Some(f)) => Source::File(f.clone()),
        (None, None) => unreachable!("clap exige uma fonte"),
    }
}

/// Abre a captura; se falhar (por exemplo, sem permissao), explica e encerra com status 1.
fn start_capture(cfg: &Config, source: Source, tx: mpsc::Sender<Captured>) -> CaptureHandle {
    let capture_cfg = CaptureConfig {
        source,
        bpf: cfg.bpf.clone(),
        snaplen: cfg.snaplen,
        promisc: !cfg.no_promisc,
    };
    sniffer::spawn(&capture_cfg, tx).unwrap_or_else(|e| {
        eprintln!("mod-net-sensor: nao foi possivel iniciar a captura: {e}");
        if cfg.interface.is_some() {
            eprintln!(
                "  dica: a captura exige CAP_NET_RAW e CAP_NET_ADMIN (ex.: setcap cap_net_raw,cap_net_admin=eip <binario>) ou root"
            );
        }
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

/// Roda o cliente IPC ate sinal, ENCERRAR, fim dos eventos ou falha da captura.
async fn run_until_done(
    client: Client<SensorController>,
    events: mpsc::Receiver<EventoFluxoRede>,
    shutdown: watch::Receiver<bool>,
    mut capture_errors: mpsc::Receiver<String>,
) -> (Exit, Option<String>) {
    tokio::select! {
        e = client.run(events, shutdown) => (e, None),
        Some(msg) = capture_errors.recv() => (Exit::Shutdown, Some(msg)),
    }
}

/// Encerramento ordenado e saida do processo.
async fn finish(
    exit: Exit,
    failure: Option<String>,
    stop: Arc<AtomicBool>,
    capture_join: JoinHandle<()>,
    decoder: JoinHandle<()>,
) -> ! {
    eprintln!("mod-net-sensor: encerrando ({exit:?})");
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(3), capture_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), decoder).await;

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
