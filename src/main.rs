use std::sync::Arc;
use std::time::Duration;

use mod_net_sensor::capture::sniffer::{self, CaptureConfig, Source};
use mod_net_sensor::config::Config;
use mod_net_sensor::ipc::client::{Client, ClientConfig, Exit};
use mod_net_sensor::pipeline::{PipelineCounters, SensorController, decode_loop};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ! {
    let cfg = Config::parse_checked();
    let version = env!("CARGO_PKG_VERSION");

    let source = match (&cfg.interface, &cfg.pcap_file) {
        (Some(i), _) => Source::Interface(i.clone()),
        (None, Some(f)) => Source::File(f.clone()),
        (None, None) => unreachable!("clap exige uma fonte"),
    };
    let lossless = matches!(source, Source::File(_));
    let (pkt_tx, pkt_rx) = mpsc::channel(cfg.queue_size);
    let (ev_tx, ev_rx) = mpsc::channel(cfg.queue_size);

    let capture = match sniffer::spawn(
        &CaptureConfig {
            source,
            bpf: cfg.bpf.clone(),
            snaplen: cfg.snaplen,
            promisc: !cfg.no_promisc,
        },
        pkt_tx,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mod-net-sensor: nao foi possivel iniciar a captura: {e}");
            if cfg.interface.is_some() {
                eprintln!(
                    "  dica: a captura exige CAP_NET_RAW e CAP_NET_ADMIN (ex.: setcap cap_net_raw,cap_net_admin=eip <binario>) ou root"
                );
            }
            std::process::exit(1);
        }
    };

    let pipeline = Arc::new(PipelineCounters::default());
    let ctl = Arc::new(SensorController {
        paused: capture.paused.clone(),
        capture: capture.counters.clone(),
        pipeline: pipeline.clone(),
        reconfig: capture.reconfig.clone(),
    });
    let decoder = tokio::spawn(decode_loop(pkt_rx, ev_tx, cfg.emit, lossless, pipeline));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    {
        let tx = shutdown_tx.clone();
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
        tokio::spawn(async move {
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            let _ = tx.send(true);
        });
    }

    let client = Client::new(
        ClientConfig::new(
            cfg.socket.clone(),
            cfg.module_id.clone(),
            version.to_string(),
        ),
        ctl,
    )
    .exit_when_drained(cfg.exit_on_eof);

    // A thread de captura terminando com erro (interface caiu, etc.) derruba o sensor
    // com status != 0 para que o supervisor o reinicie.
    let stop = capture.stop.clone();
    let (cap_err_tx, mut cap_err_rx) = mpsc::channel::<String>(1);
    let cap_join = tokio::task::spawn_blocking(move || {
        if let Ok(Err(e)) = capture.join.join() {
            let _ = cap_err_tx.blocking_send(e.to_string());
        }
    });

    let mut failure = None;
    let exit = tokio::select! {
        e = client.run(ev_rx, shutdown_rx) => e,
        Some(msg) = cap_err_rx.recv() => { failure = Some(msg); Exit::Shutdown }
    };

    eprintln!("mod-net-sensor: encerrando ({exit:?})");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(3), cap_join).await;
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
