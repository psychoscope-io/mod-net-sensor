//! Liga captura -> decode -> eventos e implementa o `Controller` (comandos do Core).
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use psychoscope_proto::v1::EventoFluxoRede;
use tokio::sync::{mpsc, oneshot};

use crate::capture::sniffer::{CaptureCounters, Captured, ReconfigRequest};
use crate::event::{EmitPolicy, build_event_reassembling};
use crate::ipc::client::{Controller, StatsSnapshot};
use crate::protocols::decode_frame;
use crate::reassembly::Reassembler;

#[derive(Default, Debug)]
pub struct PipelineCounters {
    /// Quadros que nao puderam ser decodificados (truncados, malformados, protocolo nao suportado).
    pub decode_errors: AtomicU64,
    /// Eventos descartados porque o canal para o cliente IPC estava cheio.
    pub events_queue_dropped: AtomicU64,
}

/// Estado do decodificador: remontagem TLS e politica de emissao.
struct Decoder {
    reasm: Reassembler,
    policy: EmitPolicy,
    counters: Arc<PipelineCounters>,
}

impl Decoder {
    /// Decodifica um pacote bruto; `None` se foi descartado (erro de decode ou politica).
    fn handle(&mut self, p: &Captured) -> Option<EventoFluxoRede> {
        let pkt = match decode_frame(p.link, &p.data) {
            Ok(pkt) => pkt,
            Err(_) => {
                self.counters.decode_errors.fetch_add(1, Relaxed);
                return None;
            }
        };
        let truncated = p.data.len() < p.wire_len as usize;
        build_event_reassembling(
            &mut self.reasm,
            &pkt,
            p.ts,
            u64::from(p.wire_len),
            truncated,
            self.policy,
        )
    }
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
    let mut decoder = Decoder {
        reasm: Reassembler::new(),
        policy,
        counters: counters.clone(),
    };
    while let Some(p) = rx.recv().await {
        let Some(ev) = decoder.handle(&p) else {
            continue;
        };
        let delivered = if lossless {
            tx.send(ev).await.is_ok()
        } else {
            match tx.try_send(ev) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    counters.events_queue_dropped.fetch_add(1, Relaxed);
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        };
        if !delivered {
            break;
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
    use crate::protocols::{LinkType, tcp, testutil::*};
    use psychoscope_proto::v1::evento_fluxo_rede::MetadadosL7;
    use std::time::{Duration, SystemTime};

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

    fn cap_at(frame: Vec<u8>, secs: u64) -> Captured {
        Captured {
            ts: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            ..cap(frame)
        }
    }

    /// Frame TCP 10.0.0.1:40000 -> 10.0.0.2:443 com `seq` e `payload` dados.
    fn seg_frame(seq: u32, payload: &[u8]) -> Vec<u8> {
        eth_v4(6, &tcp_seq(40000, 443, seq, tcp::PSH | tcp::ACK, payload))
    }

    async fn run(packets: Vec<Captured>, policy: EmitPolicy) -> Vec<EventoFluxoRede> {
        let (ptx, prx) = mpsc::channel(packets.len().max(1));
        let (etx, mut erx) = mpsc::channel(packets.len().max(1));
        for p in packets {
            ptx.send(p).await.unwrap();
        }
        drop(ptx);
        decode_loop(
            prx,
            etx,
            policy,
            true,
            Arc::new(PipelineCounters::default()),
        )
        .await;
        let mut out = Vec::new();
        while let Some(e) = erx.recv().await {
            out.push(e);
        }
        out
    }

    fn sni(e: &EventoFluxoRede) -> Option<&str> {
        match &e.metadados_l7 {
            Some(MetadadosL7::Tls(t)) => Some(t.sni_hostname.as_str()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn fragmented_client_hello_yields_one_event_with_sni_from_second_segment() {
        let h = client_hello_padded("quantum.example", 3000);
        assert!(h.len() > 3000);
        let evs = run(
            vec![
                cap_at(seg_frame(1000, &h[..1400]), 10),
                cap_at(seg_frame(2400, &h[1400..]), 10),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        assert_eq!(evs.len(), 1, "um evento por handshake, nao por fragmento");
        assert_eq!(sni(&evs[0]), Some("quantum.example"));
        assert_eq!(evs[0].flags_tcp, u32::from(tcp::PSH | tcp::ACK));
        // tamanho e o do ultimo pacote, nao o do registro remontado
        assert_eq!(
            evs[0].tamanho_bytes,
            seg_frame(2400, &h[1400..]).len() as u64
        );
    }

    #[tokio::test]
    async fn fragments_without_reassembly_carry_no_tls_metadata_under_all() {
        let h = client_hello_padded("quantum.example", 3000);
        let evs = run(
            vec![
                cap_at(seg_frame(1000, &h[..1400]), 10),
                cap_at(seg_frame(2400, &h[1400..]), 10),
            ],
            EmitPolicy::All,
        )
        .await;
        assert_eq!(evs.len(), 2);
        assert_eq!(sni(&evs[0]), None);
        assert_eq!(sni(&evs[1]), Some("quantum.example"));
    }

    #[tokio::test]
    async fn out_of_order_or_orphan_fragments_emit_nothing() {
        let h = client_hello_padded("quantum.example", 3000);
        // fora de ordem: o 2o segmento chega antes do 1o -> descartado
        let evs = run(
            vec![
                cap_at(seg_frame(2400, &h[1400..]), 10),
                cap_at(seg_frame(1000, &h[..1400]), 10),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        assert!(evs.is_empty());
        // segundo segmento chega depois do TTL de 5 s (tempo dos pacotes)
        let evs = run(
            vec![
                cap_at(seg_frame(1000, &h[..1400]), 10),
                cap_at(seg_frame(2400, &h[1400..]), 16),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        assert!(evs.is_empty());
    }

    #[tokio::test]
    async fn single_segment_client_hello_is_unchanged() {
        let h = client_hello(Some("one.example"), &[0x0304]);
        let evs = run(vec![cap(seg_frame(1, &h))], EmitPolicy::Interesting).await;
        assert_eq!(evs.len(), 1);
        assert_eq!(sni(&evs[0]), Some("one.example"));
    }

    #[tokio::test]
    async fn interleaved_flows_are_reassembled_independently() {
        let a = client_hello_padded("a.example", 3000);
        let b = client_hello_padded("b.example", 3000);
        let fa = |seq: u32, d: &[u8]| eth_v4(6, &tcp_seq(40000, 443, seq, tcp::ACK, d));
        let fb = |seq: u32, d: &[u8]| eth_v4(6, &tcp_seq(40001, 443, seq, tcp::ACK, d));
        let evs = run(
            vec![
                cap(fa(1, &a[..1400])),
                cap(fb(77, &b[..1000])),
                cap(fa(1401, &a[1400..])),
                cap(fb(1077, &b[1000..])),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        let names: Vec<_> = evs.iter().map(|e| sni(e).unwrap()).collect();
        assert_eq!(names, ["a.example", "b.example"]);
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
