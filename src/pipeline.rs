//! Liga captura -> decode -> eventos e implementa o `Controller` (comandos do Core).
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, SystemTime};

use psychoscope_proto::v1::EventoFluxoRede;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval};

use crate::capture::sniffer::{CaptureCounters, Captured, ReconfigRequest};
use crate::event::{EmitPolicy, build_event_reassembling};
use crate::ipc::client::{Controller, StatsSnapshot};
use crate::protocols::{DecodeError, Transport, decode_frame};
use crate::reassembly::Reassembler;

/// De quanto em quanto tempo, ao vivo, a remontagem expira fluxos sem novos pacotes.
const IDLE_EXPIRE_EVERY: Duration = Duration::from_secs(1);

#[derive(Default, Debug)]
pub struct PipelineCounters {
    /// Quadros truncados ou malformados.
    pub decode_malformed: AtomicU64,
    /// Quadros de protocolo nao suportado (ARP e afins): ruido esperado, nao defeito.
    pub decode_unsupported: AtomicU64,
    /// Pacotes decodificados que a politica de emissao nao transformou em evento.
    pub policy_filtered: AtomicU64,
    /// Fragmentos IP que nao sao o primeiro (o sensor nao remonta IP).
    pub ip_fragments: AtomicU64,
    /// ClientHellos fragmentados que a remontagem descartou sem completar.
    pub reassembly_discarded: AtomicU64,
    /// Eventos descartados porque o canal para o cliente IPC estava cheio.
    pub events_queue_dropped: AtomicU64,
}

/// Estado do decodificador: remontagem TLS e politica de emissao.
struct Decoder {
    reasm: Reassembler,
    /// Descartes da remontagem ja publicados em `counters`.
    reasm_published: u64,
    policy: EmitPolicy,
    counters: Arc<PipelineCounters>,
}

impl Decoder {
    /// Decodifica um pacote bruto; `None` se foi descartado (erro de decode ou politica).
    fn handle(&mut self, p: &Captured) -> Option<EventoFluxoRede> {
        let pkt = match decode_frame(p.link, &p.data) {
            Ok(pkt) => pkt,
            Err(e) => {
                let counter = match e {
                    DecodeError::Unsupported => &self.counters.decode_unsupported,
                    DecodeError::Truncated | DecodeError::Malformed => {
                        &self.counters.decode_malformed
                    }
                };
                counter.fetch_add(1, Relaxed);
                return None;
            }
        };
        if matches!(pkt.transport, Transport::Fragment { .. }) {
            self.counters.ip_fragments.fetch_add(1, Relaxed);
        }
        let truncated = p.data.len() < p.wire_len as usize;
        let ev = build_event_reassembling(
            &mut self.reasm,
            &pkt,
            p.ts,
            u64::from(p.wire_len),
            truncated,
            self.policy,
        );
        self.publish_reassembly_discards();
        if ev.is_none() {
            self.counters.policy_filtered.fetch_add(1, Relaxed);
        }
        ev
    }

    /// Expira fluxos ociosos da remontagem; `now` e o relogio desde a epoca Unix.
    fn expire_idle(&mut self, now: Duration) {
        self.reasm.expire(now);
        self.publish_reassembly_discards();
    }

    fn publish_reassembly_discards(&mut self) {
        let total = self.reasm.discarded();
        if total != self.reasm_published {
            self.counters
                .reassembly_discarded
                .fetch_add(total - self.reasm_published, Relaxed);
            self.reasm_published = total;
        }
    }
}

/// Entrega o evento ao canal. `false` quando o consumidor fechou o canal.
/// `lossless` espera espaco; senao, canal cheio descarta e conta.
async fn deliver(
    tx: &mpsc::Sender<EventoFluxoRede>,
    ev: EventoFluxoRede,
    lossless: bool,
    counters: &PipelineCounters,
) -> bool {
    if lossless {
        return tx.send(ev).await.is_ok();
    }
    match tx.try_send(ev) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            counters.events_queue_dropped.fetch_add(1, Relaxed);
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Consome pacotes brutos, decodifica e emite eventos. Termina quando a captura fecha o canal.
/// `lossless` (leitura de arquivo) espera espaco em vez de descartar. Ao vivo, a remontagem
/// tambem expira fluxos ociosos pelo relogio do sistema, para liberar memoria sem trafego.
pub async fn decode_loop(
    mut rx: mpsc::Receiver<Captured>,
    tx: mpsc::Sender<EventoFluxoRede>,
    policy: EmitPolicy,
    lossless: bool,
    counters: Arc<PipelineCounters>,
) {
    let mut decoder = Decoder {
        reasm: Reassembler::new(),
        reasm_published: 0,
        policy,
        counters: counters.clone(),
    };
    let mut idle = interval(IDLE_EXPIRE_EVERY);
    idle.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            p = rx.recv() => {
                let Some(p) = p else { break };
                let Some(ev) = decoder.handle(&p) else { continue };
                if !deliver(&tx, ev, lossless, &counters).await {
                    break;
                }
            }
            _ = idle.tick(), if !lossless => {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default();
                decoder.expire_idle(now);
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
        let (c, p) = (&self.capture, &self.pipeline);
        let losses = [
            ("perda.kernel", c.kernel_dropped.load(Relaxed)),
            ("perda.interface", c.interface_dropped.load(Relaxed)),
            ("perda.fila_captura", c.channel_dropped.load(Relaxed)),
            ("perda.fila_eventos", p.events_queue_dropped.load(Relaxed)),
        ];
        let mut counters = losses.to_vec();
        counters.extend([
            ("decode.malformado", p.decode_malformed.load(Relaxed)),
            ("decode.nao_suportado", p.decode_unsupported.load(Relaxed)),
            ("ip.fragmento", p.ip_fragments.load(Relaxed)),
            ("politica.filtrados", p.policy_filtered.load(Relaxed)),
            (
                "remontagem.descartados",
                p.reassembly_discarded.load(Relaxed),
            ),
        ]);
        StatsSnapshot {
            packets_captured: c.captured.load(Relaxed),
            bytes: c.bytes.load(Relaxed),
            packets_dropped: losses.iter().map(|(_, n)| n).sum(),
            counters,
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
        assert_eq!(counters.decode_malformed.load(Relaxed), 1);
        assert_eq!(counters.decode_unsupported.load(Relaxed), 1);
        assert_eq!(counters.policy_filtered.load(Relaxed), 1);
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
        run_counted(packets, policy).await.0
    }

    async fn run_counted(
        packets: Vec<Captured>,
        policy: EmitPolicy,
    ) -> (Vec<EventoFluxoRede>, Arc<PipelineCounters>) {
        let counters = Arc::new(PipelineCounters::default());
        let (ptx, prx) = mpsc::channel(packets.len().max(1));
        let (etx, mut erx) = mpsc::channel(packets.len().max(1));
        for p in packets {
            ptx.send(p).await.unwrap();
        }
        drop(ptx);
        decode_loop(prx, etx, policy, true, counters.clone()).await;
        let mut out = Vec::new();
        while let Some(e) = erx.recv().await {
            out.push(e);
        }
        (out, counters)
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
    #[tokio::test]
    async fn reassembly_discards_are_counted_once_per_flow() {
        let h = client_hello_padded("quantum.example", 3000);
        // lacuna: o 2o segmento nao comeca onde o 1o terminou
        let (_, c) = run_counted(
            vec![
                cap_at(seg_frame(1000, &h[..1400]), 10),
                cap_at(seg_frame(3000, &h[1400..]), 10),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        assert_eq!(c.reassembly_discarded.load(Relaxed), 1);
        // validade: o 2o segmento chega depois do TTL
        let (_, c) = run_counted(
            vec![
                cap_at(seg_frame(1000, &h[..1400]), 10),
                cap_at(seg_frame(2400, &h[1400..]), 16),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        assert_eq!(c.reassembly_discarded.load(Relaxed), 1);
        // registro completo: nada descartado
        let (evs, c) = run_counted(
            vec![
                cap_at(seg_frame(1000, &h[..1400]), 10),
                cap_at(seg_frame(2400, &h[1400..]), 10),
            ],
            EmitPolicy::Interesting,
        )
        .await;
        assert_eq!(evs.len(), 1);
        assert_eq!(c.reassembly_discarded.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn non_initial_ip_fragments_are_counted_not_decoded() {
        let mut ip = v4(17, &[0; 8]);
        ip[6] = 0x00; // flags/offset: offset 0x10 = fragmento que nao e o primeiro
        ip[7] = 0x10;
        let (evs, c) = run_counted(vec![cap(eth(0x0800, &ip))], EmitPolicy::Interesting).await;
        assert!(evs.is_empty());
        assert_eq!(c.ip_fragments.load(Relaxed), 1);
        assert_eq!(c.policy_filtered.load(Relaxed), 1);
        assert_eq!(c.decode_malformed.load(Relaxed), 0);
    }

    #[test]
    fn stats_keeps_each_loss_source_apart_and_sums_them() {
        let (reconfig, _rx) = std::sync::mpsc::channel();
        let ctl = SensorController {
            paused: Arc::new(AtomicBool::new(false)),
            capture: Arc::new(CaptureCounters::default()),
            pipeline: Arc::new(PipelineCounters::default()),
            reconfig,
        };
        ctl.capture.kernel_dropped.store(1, Relaxed);
        ctl.capture.interface_dropped.store(2, Relaxed);
        ctl.capture.channel_dropped.store(4, Relaxed);
        ctl.pipeline.events_queue_dropped.store(8, Relaxed);
        ctl.pipeline.decode_malformed.store(16, Relaxed);
        let st = ctl.stats();
        assert_eq!(
            st.packets_dropped, 15,
            "so perdas; erros de decode ficam de fora"
        );
        let get = |k: &str| st.counters.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
        assert_eq!(get("perda.kernel"), Some(1));
        assert_eq!(get("perda.interface"), Some(2));
        assert_eq!(get("perda.fila_captura"), Some(4));
        assert_eq!(get("perda.fila_eventos"), Some(8));
        assert_eq!(get("decode.malformado"), Some(16));
        assert_eq!(get("decode.nao_suportado"), Some(0));
    }
    #[test]
    fn idle_expiry_publishes_the_discarded_flow() {
        let h = client_hello_padded("idle.example", 3000);
        let counters = Arc::new(PipelineCounters::default());
        let mut d = Decoder {
            reasm: Reassembler::new(),
            reasm_published: 0,
            policy: EmitPolicy::Interesting,
            counters: counters.clone(),
        };
        assert!(d.handle(&cap_at(seg_frame(1000, &h[..1400]), 10)).is_none());
        d.expire_idle(Duration::from_secs(12)); // dentro do TTL (5 s)
        assert_eq!(counters.reassembly_discarded.load(Relaxed), 0);
        d.expire_idle(Duration::from_secs(16));
        assert_eq!(counters.reassembly_discarded.load(Relaxed), 1);
        d.expire_idle(Duration::from_secs(60)); // sem o que expirar: nao conta de novo
        assert_eq!(counters.reassembly_discarded.load(Relaxed), 1);
    }
    mod prop {
        use super::*;
        use crate::protocols::ALL_LINKS;
        use crate::reassembly::MAX_FLOWS;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2_000))]

            /// Qualquer sequencia de quadros, de qualquer tipo de enlace, passa pelo decodificador
            /// (com remontagem compartilhada) sem panico e sem estourar a tabela de fluxos.
            #[test]
            fn arbitrary_frame_sequences_never_panic(
                frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..24),
                policy_all in any::<bool>(),
            ) {
                let policy = if policy_all { EmitPolicy::All } else { EmitPolicy::Interesting };
                let counters = Arc::new(PipelineCounters::default());
                let mut d = Decoder {
                    reasm: Reassembler::new(),
                    reasm_published: 0,
                    policy,
                    counters,
                };
                for (i, data) in frames.into_iter().enumerate() {
                    for link in ALL_LINKS {
                        let p = Captured {
                            ts: SystemTime::UNIX_EPOCH + Duration::from_millis(i as u64),
                            wire_len: data.len() as u32,
                            link,
                            data: data.clone(),
                        };
                        let _ = d.handle(&p);
                        prop_assert!(d.reasm.len() <= MAX_FLOWS);
                    }
                }
            }
        }
    }
}
