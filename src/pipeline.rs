//! Liga captura -> decode -> eventos e implementa o `Controller` (comandos do Core).
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use psychoscope_proto::v1::EventoFluxoRede;
use tokio::sync::{mpsc, oneshot};

use crate::capture::sniffer::{CaptureCounters, Captured, ReconfigRequest};
use crate::event::{EmitPolicy, build_event};
use crate::ipc::client::{Controller, StatsSnapshot};
use crate::protocols::decode_frame;

#[derive(Default, Debug)]
pub struct PipelineCounters {
    /// Quadros que nao puderam ser decodificados (truncados, malformados, protocolo nao suportado).
    pub decode_errors: AtomicU64,
    /// Eventos descartados porque o canal para o cliente IPC estava cheio.
    pub events_queue_dropped: AtomicU64,
}

/// Consome pacotes brutos, decodifica e emite eventos. Termina quando a captura fecha o canal.
/// `lossless` (leitura de arquivo) espera espaco em vez de descartar.
pub async fn decode_loop(
    mut rx: mpsc::Receiver<Captured>,
    tx: mpsc::Sender<EventoFluxoRede>,
    policy: EmitPolicy,
    lossless: bool,
    counters: Arc<PipelineCounters>,
) {
    while let Some(p) = rx.recv().await {
        let pkt = match decode_frame(p.link, &p.data) {
            Ok(pkt) => pkt,
            Err(_) => {
                counters.decode_errors.fetch_add(1, Relaxed);
                continue;
            }
        };
        let Some(ev) = build_event(&pkt, p.ts, u64::from(p.wire_len), policy) else {
            continue;
        };
        if lossless {
            if tx.send(ev).await.is_err() {
                break;
            }
        } else {
            match tx.try_send(ev) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    counters.events_queue_dropped.fetch_add(1, Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
    }
}

/// Aplica os comandos do Core ao sensor em execucao.
pub struct SensorController {
    pub paused: Arc<AtomicBool>,
    pub capture: Arc<CaptureCounters>,
    pub pipeline: Arc<PipelineCounters>,
    pub reconfig: std::sync::mpsc::Sender<ReconfigRequest>,
}

impl Controller for SensorController {
    fn pause(&self) {
        self.paused.store(true, Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Relaxed);
    }

    /// Parametros aceitos: `bpf` (filtro BPF; vazio = sem filtro).
    async fn reconfigure(&self, params: HashMap<String, String>) -> Result<(), String> {
        if let Some(k) = params.keys().find(|k| k.as_str() != "bpf") {
            return Err(format!("parametro desconhecido: {k}"));
        }
        let Some(bpf) = params.get("bpf") else {
            return Err("parametro obrigatorio ausente: bpf".to_string());
        };
        let (reply, rx) = oneshot::channel();
        self.reconfig
            .send(ReconfigRequest {
                bpf: bpf.clone(),
                reply,
            })
            .map_err(|_| "captura encerrada".to_string())?;
        rx.await
            .map_err(|_| "captura encerrada antes de responder".to_string())?
    }

    fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets_captured: self.capture.captured.load(Relaxed),
            bytes: self.capture.bytes.load(Relaxed),
            packets_dropped: self.capture.kernel_dropped.load(Relaxed)
                + self.capture.channel_dropped.load(Relaxed)
                + self.pipeline.events_queue_dropped.load(Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{LinkType, testutil::*};
    use std::time::SystemTime;

    fn cap(frame: Vec<u8>) -> Captured {
        Captured {
            ts: SystemTime::UNIX_EPOCH,
            wire_len: frame.len() as u32,
            link: LinkType::Ethernet,
            data: frame,
        }
    }

    #[tokio::test]
    async fn decodes_filters_and_counts_errors() {
        let (ptx, prx) = mpsc::channel(16);
        let (etx, mut erx) = mpsc::channel(16);
        let counters = Arc::new(PipelineCounters::default());
        let task = tokio::spawn(decode_loop(
            prx,
            etx,
            EmitPolicy::Interesting,
            true,
            counters.clone(),
        ));

        ptx.send(cap(eth_v4(17, &udp(1, 53, &dns_query("a.com", 1)))))
            .await
            .unwrap(); // evento
        ptx.send(cap(eth_v4(17, &udp(1, 2, b"x")))).await.unwrap(); // filtrado
        ptx.send(cap(vec![1, 2, 3])).await.unwrap(); // erro de decode
        ptx.send(cap(eth(0x0806, &[0; 28]))).await.unwrap(); // ARP: nao suportado
        drop(ptx);
        task.await.unwrap();

        assert!(erx.recv().await.is_some());
        assert!(erx.recv().await.is_none(), "so um evento esperado");
        assert_eq!(counters.decode_errors.load(Relaxed), 2);
    }

    #[tokio::test]
    async fn lossy_mode_drops_and_counts_when_queue_full() {
        let (ptx, prx) = mpsc::channel(16);
        let (etx, erx) = mpsc::channel(1);
        let counters = Arc::new(PipelineCounters::default());
        let task = tokio::spawn(decode_loop(
            prx,
            etx,
            EmitPolicy::Interesting,
            false,
            counters.clone(),
        ));
        for _ in 0..5 {
            ptx.send(cap(eth_v4(17, &udp(1, 53, &dns_query("a.com", 1)))))
                .await
                .unwrap();
        }
        drop(ptx);
        task.await.unwrap();
        assert_eq!(counters.events_queue_dropped.load(Relaxed), 4);
        drop(erx);
    }

    #[tokio::test]
    async fn controller_validates_reconfigure_params_and_aggregates_stats() {
        let (rtx, rrx) = std::sync::mpsc::channel::<ReconfigRequest>();
        let ctl = SensorController {
            paused: Arc::new(AtomicBool::new(false)),
            capture: Arc::new(CaptureCounters::default()),
            pipeline: Arc::new(PipelineCounters::default()),
            reconfig: rtx,
        };
        ctl.capture.captured.store(10, Relaxed);
        ctl.capture.bytes.store(999, Relaxed);
        ctl.capture.kernel_dropped.store(1, Relaxed);
        ctl.capture.channel_dropped.store(2, Relaxed);
        ctl.pipeline.events_queue_dropped.store(4, Relaxed);
        let s = ctl.stats();
        assert_eq!(
            (s.packets_captured, s.bytes, s.packets_dropped),
            (10, 999, 7)
        );

        ctl.pause();
        assert!(ctl.paused.load(Relaxed));
        ctl.resume();
        assert!(!ctl.paused.load(Relaxed));

        assert!(
            ctl.reconfigure(HashMap::new())
                .await
                .unwrap_err()
                .contains("bpf")
        );
        let bad = HashMap::from([
            ("bpf".to_string(), "udp".to_string()),
            ("x".to_string(), "1".to_string()),
        ]);
        assert!(
            ctl.reconfigure(bad)
                .await
                .unwrap_err()
                .contains("desconhecido")
        );

        // a thread de captura (simulada) aplica e responde
        let worker = std::thread::spawn(move || {
            let req = rrx.recv().unwrap();
            assert_eq!(req.bpf, "tcp");
            req.reply.send(Err("filtro invalido".into())).unwrap();
        });
        let err = ctl
            .reconfigure(HashMap::from([("bpf".to_string(), "tcp".to_string())]))
            .await
            .unwrap_err();
        assert_eq!(err, "filtro invalido");
        worker.join().unwrap();

        // thread de captura encerrada: receptor derrubado
        let err = ctl
            .reconfigure(HashMap::from([("bpf".to_string(), "tcp".to_string())]))
            .await
            .unwrap_err();
        assert!(err.contains("encerrada"));
    }
}
