//! Remontagem de ClientHello TLS que ocupa varios segmentos TCP.
//!
//! Clientes com chave pos-quantica passam de 1,4 KB, e o SNI pode cair no segundo segmento.
//! A tabela e deliberadamente minima: so guarda estado para fluxos cujo primeiro segmento com
//! payload comeca com um registro de handshake (`0x16 0x03`, ClientHello) que declara mais
//! bytes do que o segmento traz. Qualquer outro trafego passa sem alocar nada.
//!
//! Politica estrita (o sensor e passivo e nao ve o mesmo que o receptor): so aceita o segmento
//! com o `seq` esperado; lacuna, retransmissao, sobreposicao, RST ou captura truncada
//! descartam o fluxo. Limites: `MAX_RECORD_BYTES` por fluxo, `MAX_FLOWS` fluxos (despeja o
//! mais antigo) e `TTL` medido no tempo dos pacotes, nao no relogio do sistema.
//! Sem `unsafe`; nenhuma entrada causa panico.
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Duration;

use crate::protocols::tcp::RST;

/// Teto de bytes bufferizados por fluxo (registro TLS: 5 + ate 16384 + folga).
pub const MAX_RECORD_BYTES: usize = 18 * 1024;
/// Teto de fluxos simultaneos em remontagem.
pub const MAX_FLOWS: usize = 4096;
/// Tempo maximo para o registro completar, contado desde o primeiro segmento.
pub const TTL: Duration = Duration::from_secs(5);

const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 1;

/// Fluxo direcional (cliente -> servidor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// Um segmento TCP visto na captura.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
    /// O snaplen cortou o pacote: o payload capturado e menor que o real.
    pub truncated: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// O segmento nao participa de remontagem: analise o payload original.
    Passthrough,
    /// Fragmento retido: ainda nao ha registro completo para analisar.
    Pending,
    /// Registro TLS completo (cabecalho + corpo, sem bytes alem dele).
    Complete(Vec<u8>),
}

struct Flow {
    buf: Vec<u8>,
    /// Tamanho total do registro (cabecalho + corpo).
    total: usize,
    next_seq: u32,
    /// Instante do primeiro segmento; tambem ordena o indice de despejo.
    started: (Duration, u64),
}

#[derive(Default)]
pub struct Reassembler {
    flows: HashMap<FlowKey, Flow>,
    /// Do mais antigo ao mais novo: despejo e expiracao saem do inicio.
    by_age: BTreeMap<(Duration, u64), FlowKey>,
    serial: u64,
}

/// Tamanho total do registro se `payload` abre um ClientHello que nao cabe nele.
fn incomplete_client_hello(payload: &[u8]) -> Option<usize> {
    let hdr = payload.get(..=RECORD_HEADER)?; // 5 do registro + tipo do handshake
    if hdr[0] != CONTENT_HANDSHAKE || hdr[1] != 3 || hdr[5] != HS_CLIENT_HELLO {
        return None;
    }
    let total = RECORD_HEADER + usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    (total > payload.len() && total <= MAX_RECORD_BYTES).then_some(total)
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fluxos em remontagem agora.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Total de bytes retidos nos buffers.
    pub fn buffered_bytes(&self) -> usize {
        self.flows.values().map(|f| f.buf.len()).sum()
    }

    /// Processa um segmento. `now` e o instante do pacote (desde a epoca Unix).
    pub fn feed(&mut self, now: Duration, key: FlowKey, seg: Segment<'_>) -> Outcome {
        self.expire(now);

        if seg.flags & RST != 0 || seg.truncated {
            self.remove(&key);
            return Outcome::Passthrough;
        }
        if seg.payload.is_empty() {
            return Outcome::Passthrough; // ACK puro: nao muda o estado
        }

        let Some(flow) = self.flows.get_mut(&key) else {
            return self.start(now, key, seg);
        };

        if seg.seq != flow.next_seq {
            // lacuna, retransmissao ou sobreposicao: o fluxo nao e confiavel
            self.remove(&key);
            return Outcome::Passthrough;
        }
        let take = seg.payload.len().min(flow.total - flow.buf.len());
        flow.buf.extend_from_slice(&seg.payload[..take]);
        flow.next_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
        if flow.buf.len() < flow.total {
            return Outcome::Pending;
        }
        match self.remove(&key) {
            Some(done) => Outcome::Complete(done.buf),
            None => Outcome::Passthrough,
        }
    }

    fn start(&mut self, now: Duration, key: FlowKey, seg: Segment<'_>) -> Outcome {
        let Some(total) = incomplete_client_hello(seg.payload) else {
            return Outcome::Passthrough;
        };
        while self.flows.len() >= MAX_FLOWS {
            let Some((_, oldest)) = self.by_age.pop_first() else {
                break;
            };
            self.flows.remove(&oldest);
        }
        self.serial = self.serial.wrapping_add(1);
        let started = (now, self.serial);
        self.by_age.insert(started, key);
        self.flows.insert(
            key,
            Flow {
                buf: seg.payload.to_vec(),
                total,
                next_seq: seg.seq.wrapping_add(seg.payload.len() as u32),
                started,
            },
        );
        Outcome::Pending
    }

    fn remove(&mut self, key: &FlowKey) -> Option<Flow> {
        let flow = self.flows.remove(key)?;
        self.by_age.remove(&flow.started);
        Some(flow)
    }

    /// Descarta fluxos que passaram de `TTL`. O relogio dos pacotes pode andar para tras
    /// (pcap fora de ordem): nesse caso nada expira.
    fn expire(&mut self, now: Duration) {
        while let Some(entry) = self.by_age.first_entry() {
            if now.saturating_sub(entry.key().0) <= TTL {
                break;
            }
            let key = entry.remove();
            self.flows.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::tcp::{ACK, PSH};
    use crate::protocols::testutil::{client_hello, client_hello_padded};

    fn key(n: u16) -> FlowKey {
        FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 40000 + n,
            dst_ip: "10.0.0.2".parse().unwrap(),
            dst_port: 443,
        }
    }

    fn seg(seq: u32, payload: &[u8]) -> Segment<'_> {
        Segment {
            seq,
            flags: PSH | ACK,
            payload,
            truncated: false,
        }
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn big_hello(sni: &str) -> Vec<u8> {
        client_hello_padded(sni, 3000)
    }

    fn sni_of(rec: &[u8]) -> Option<String> {
        crate::protocols::tls::parse_client_hello(rec)?.sni
    }

    #[test]
    fn two_segments_sni_only_after_reassembly() {
        let h = big_hello("late.example");
        let cut = 1400;
        // o 1o segmento sozinho nao traz SNI: ele esta depois do enchimento
        assert_eq!(sni_of(&h[..cut]), None);
        let mut r = Reassembler::new();
        assert_eq!(
            r.feed(secs(1), key(0), seg(100, &h[..cut])),
            Outcome::Pending
        );
        assert_eq!(r.len(), 1);
        let Outcome::Complete(rec) = r.feed(secs(1), key(0), seg(100 + cut as u32, &h[cut..]))
        else {
            panic!("deveria completar")
        };
        assert_eq!(rec, h);
        assert_eq!(sni_of(&rec).as_deref(), Some("late.example"));
        assert!(r.is_empty(), "fluxo concluido libera o estado");
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn three_segments_in_order() {
        let h = big_hello("three.example");
        let (a, b) = (1000, 2200);
        let mut r = Reassembler::new();
        assert_eq!(r.feed(secs(0), key(0), seg(1, &h[..a])), Outcome::Pending);
        assert_eq!(
            r.feed(secs(0), key(0), seg(1 + a as u32, &h[a..b])),
            Outcome::Pending
        );
        assert_eq!(r.buffered_bytes(), b);
        assert_eq!(
            r.feed(secs(0), key(0), seg(1 + b as u32, &h[b..])),
            Outcome::Complete(h)
        );
    }

    #[test]
    fn sequence_wraparound_is_handled() {
        let h = big_hello("wrap.example");
        let start = u32::MAX - 500;
        let mut r = Reassembler::new();
        r.feed(secs(0), key(0), seg(start, &h[..1400]));
        assert_eq!(
            r.feed(secs(0), key(0), seg(start.wrapping_add(1400), &h[1400..])),
            Outcome::Complete(h)
        );
    }

    #[test]
    fn single_segment_and_non_tls_do_not_allocate() {
        let mut r = Reassembler::new();
        let whole = client_hello(Some("a.com"), &[]);
        assert_eq!(
            r.feed(secs(0), key(0), seg(1, &whole)),
            Outcome::Passthrough
        );
        for payload in [&b"GET / HTTP/1.1\r\n"[..], &[0x16, 0x03], &[0x16], &[]] {
            assert_eq!(
                r.feed(secs(0), key(1), seg(1, payload)),
                Outcome::Passthrough
            );
        }
        // handshake que nao e ClientHello (ex.: Finished/ServerHello) nao inicia buffer
        let mut not_ch = big_hello("x.com");
        not_ch[5] = 2;
        assert_eq!(
            r.feed(secs(0), key(2), seg(1, &not_ch[..1400])),
            Outcome::Passthrough
        );
        // registro maior que o limite por fluxo nao inicia buffer
        let mut huge = big_hello("x.com");
        huge[3..5].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(
            r.feed(secs(0), key(3), seg(1, &huge[..1400])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn out_of_order_segment_drops_the_flow() {
        let h = big_hello("order.example");
        let mut r = Reassembler::new();
        r.feed(secs(0), key(0), seg(1, &h[..1000]));
        // o 3o segmento chega antes do 2o: lacuna
        assert_eq!(
            r.feed(secs(0), key(0), seg(1 + 2000, &h[2000..])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
        // o 2o que chega depois nao reconstitui nada
        assert_eq!(
            r.feed(secs(0), key(0), seg(1 + 1000, &h[1000..2000])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
    }

    #[test]
    fn retransmission_and_overlap_drop_the_flow() {
        let h = big_hello("retx.example");
        let mut r = Reassembler::new();
        r.feed(secs(0), key(0), seg(1, &h[..1000]));
        // retransmissao do 1o segmento
        assert_eq!(
            r.feed(secs(0), key(0), seg(1, &h[..1000])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());

        r.feed(secs(0), key(1), seg(1, &h[..1000]));
        // sobreposicao: comeca antes do esperado
        assert_eq!(
            r.feed(secs(0), key(1), seg(500, &h[500..])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());

        r.feed(secs(0), key(2), seg(1, &h[..1000]));
        // sobreposicao parcial para frente (comeca depois do esperado) tambem e lacuna
        assert_eq!(
            r.feed(secs(0), key(2), seg(1500, &h[1500..])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
    }

    #[test]
    fn rst_truncation_and_acks() {
        let h = big_hello("rst.example");
        let mut r = Reassembler::new();
        r.feed(secs(0), key(0), seg(1, &h[..1000]));
        // ACK puro nao altera o estado
        assert_eq!(
            r.feed(secs(0), key(0), seg(1001, &[])),
            Outcome::Passthrough
        );
        assert_eq!(r.len(), 1);
        let rst = Segment {
            flags: RST,
            ..seg(1001, &[])
        };
        assert_eq!(r.feed(secs(0), key(0), rst), Outcome::Passthrough);
        assert!(r.is_empty());

        // primeiro segmento truncado pelo snaplen: nao inicia buffer
        let cut = Segment {
            truncated: true,
            ..seg(1, &h[..1000])
        };
        assert_eq!(r.feed(secs(0), key(1), cut), Outcome::Passthrough);
        assert!(r.is_empty());
        // segmento do meio truncado: descarta
        r.feed(secs(0), key(2), seg(1, &h[..1000]));
        let cut = Segment {
            truncated: true,
            ..seg(1001, &h[1000..1500])
        };
        assert_eq!(r.feed(secs(0), key(2), cut), Outcome::Passthrough);
        assert!(r.is_empty());
    }

    #[test]
    fn bytes_beyond_the_record_are_ignored() {
        let h = big_hello("extra.example");
        let mut tail = h[1400..].to_vec();
        tail.extend(b"dados-de-aplicacao-apos-o-hello");
        let mut r = Reassembler::new();
        r.feed(secs(0), key(0), seg(1, &h[..1400]));
        assert_eq!(
            r.feed(secs(0), key(0), seg(1401, &tail)),
            Outcome::Complete(h)
        );
    }

    #[test]
    fn orphan_flow_expires_by_packet_time() {
        let h = big_hello("orphan.example");
        let mut r = Reassembler::new();
        r.feed(secs(100), key(0), seg(1, &h[..1400]));
        // dentro do TTL: segue vivo (mesmo apos trafego de outros fluxos)
        assert_eq!(
            r.feed(secs(105), key(9), seg(1, b"qualquer coisa")),
            Outcome::Passthrough
        );
        assert_eq!(r.len(), 1);
        // passou de 5 s: qualquer pacote seguinte varre o orfao
        assert_eq!(
            r.feed(secs(106), key(9), seg(1, b"qualquer coisa")),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
        assert_eq!(r.buffered_bytes(), 0);
        // o segundo segmento tardio nao reconstitui o registro
        assert_eq!(
            r.feed(secs(107), key(0), seg(1401, &h[1400..])),
            Outcome::Passthrough
        );
    }

    #[test]
    fn late_segment_of_the_same_flow_is_not_accepted_after_ttl() {
        let h = big_hello("late2.example");
        let mut r = Reassembler::new();
        r.feed(secs(0), key(0), seg(1, &h[..1400]));
        assert_eq!(
            r.feed(secs(6), key(0), seg(1401, &h[1400..])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
    }

    #[test]
    fn clock_going_backwards_does_not_expire_or_panic() {
        let h = big_hello("clock.example");
        let mut r = Reassembler::new();
        r.feed(secs(1000), key(0), seg(1, &h[..1400]));
        assert_eq!(
            r.feed(secs(10), key(0), seg(1401, &h[1400..])),
            Outcome::Complete(h)
        );
    }

    #[test]
    fn flow_table_is_bounded_and_evicts_oldest() {
        let h = big_hello("flood.example");
        let mut r = Reassembler::new();
        let mut keys = Vec::new();
        for i in 0..(MAX_FLOWS + 10) {
            let k = FlowKey {
                src_ip: IpAddr::from([10, 1, (i >> 8) as u8, i as u8]),
                src_port: 1000,
                dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 443,
            };
            keys.push(k);
            assert_eq!(r.feed(secs(0), k, seg(1, &h[..1400])), Outcome::Pending);
            assert!(r.len() <= MAX_FLOWS);
        }
        assert_eq!(r.len(), MAX_FLOWS);
        assert!(r.buffered_bytes() <= MAX_FLOWS * MAX_RECORD_BYTES);
        // os 10 mais antigos foram despejados: nao completam
        assert_eq!(
            r.feed(secs(0), keys[0], seg(1401, &h[1400..])),
            Outcome::Passthrough
        );
        // o mais novo completa
        assert_eq!(
            r.feed(secs(0), keys[MAX_FLOWS + 9], seg(1401, &h[1400..])),
            Outcome::Complete(h)
        );
    }

    #[test]
    fn per_flow_memory_never_exceeds_the_cap() {
        // registro declarado exatamente no limite: ainda e aceito
        let mut h = big_hello("cap.example");
        let declared = MAX_RECORD_BYTES - RECORD_HEADER;
        h[3..5].copy_from_slice(&(declared as u16).to_be_bytes());
        let mut r = Reassembler::new();
        assert_eq!(
            r.feed(secs(0), key(0), seg(1, &h[..1400])),
            Outcome::Pending
        );
        // alimenta ate o limite em segmentos de 1400 bytes
        let mut seq = 1401u32;
        let chunk = vec![0u8; 1400];
        let mut last = Outcome::Pending;
        while last == Outcome::Pending {
            assert!(r.buffered_bytes() <= MAX_RECORD_BYTES);
            last = r.feed(secs(0), key(0), seg(seq, &chunk));
            seq = seq.wrapping_add(1400);
        }
        let Outcome::Complete(rec) = last else {
            panic!("deveria completar")
        };
        assert_eq!(rec.len(), MAX_RECORD_BYTES);
        // um registro que declara mais que o limite nunca e bufferizado
        h[3..5].copy_from_slice(&((declared + 1) as u16).to_be_bytes());
        assert_eq!(
            r.feed(secs(0), key(1), seg(1, &h[..1400])),
            Outcome::Passthrough
        );
        assert!(r.is_empty());
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_segments_keep_invariants(
                ops in proptest::collection::vec(
                    (0u16..6, 0u64..12, 0u32..4000, any::<u8>(), 0usize..1500, any::<bool>()),
                    0..120,
                ),
            ) {
                let h = client_hello_padded("prop.example", 3000);
                let mut r = Reassembler::new();
                for (flow, t, seq, flags, len, from_hello) in ops {
                    let start = if from_hello { 0 } else { seq as usize % h.len() };
                    let payload = &h[start..(start + len).min(h.len())];
                    let seg = Segment { seq, flags, payload, truncated: false };
                    if let Outcome::Complete(rec) = r.feed(secs(t), key(flow), seg) {
                        prop_assert!(rec.len() <= MAX_RECORD_BYTES);
                        prop_assert_eq!(&rec[..2], &[0x16, 0x03][..]);
                    }
                    prop_assert!(r.len() <= MAX_FLOWS);
                    prop_assert!(r.buffered_bytes() <= r.len() * MAX_RECORD_BYTES);
                }
            }
        }
    }
}
