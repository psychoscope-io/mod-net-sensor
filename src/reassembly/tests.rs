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
    let Outcome::Complete(rec) = r.feed(secs(1), key(0), seg(100 + cut as u32, &h[cut..])) else {
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

fn key_from(src: [u8; 4], port: u16) -> FlowKey {
    FlowKey {
        src_ip: IpAddr::from(src),
        src_port: port,
        dst_ip: "10.0.0.2".parse().unwrap(),
        dst_port: 443,
    }
}

#[test]
fn one_source_cannot_take_the_whole_table() {
    let h = big_hello("hog.example");
    let mut r = Reassembler::new();
    let hog = [10, 6, 6, 6];
    for port in 0..MAX_FLOWS_PER_SOURCE as u16 {
        let k = key_from(hog, 1000 + port);
        assert_eq!(r.feed(secs(0), k, seg(1, &h[..1400])), Outcome::Pending);
    }
    assert_eq!(r.flows_from(hog.into()), MAX_FLOWS_PER_SOURCE);
    // a cota estourou: o excedente nao entra, e nada de outra origem e despejado
    let victim = key_from([10, 7, 7, 7], 5000);
    assert_eq!(
        r.feed(secs(0), victim, seg(1, &h[..1400])),
        Outcome::Pending
    );
    let extra = key_from(hog, 9000);
    assert_eq!(
        r.feed(secs(0), extra, seg(1, &h[..1400])),
        Outcome::Passthrough
    );
    assert_eq!(r.flows_from(hog.into()), MAX_FLOWS_PER_SOURCE);
    assert_eq!(r.discarded(), 1);
    assert_eq!(
        r.feed(secs(0), victim, seg(1401, &h[1400..])),
        Outcome::Complete(h),
        "o fluxo da outra origem sobreviveu"
    );
}

#[test]
fn source_quota_is_released_when_flows_end() {
    let h = big_hello("quota.example");
    let mut r = Reassembler::new();
    let src = [10, 8, 8, 8];
    for port in 0..MAX_FLOWS_PER_SOURCE as u16 {
        r.feed(secs(0), key_from(src, port), seg(1, &h[..1400]));
    }
    // completar um fluxo, descartar outro por lacuna e expirar o resto devolvem a cota
    assert!(matches!(
        r.feed(secs(0), key_from(src, 0), seg(1401, &h[1400..])),
        Outcome::Complete(_)
    ));
    assert_eq!(r.flows_from(src.into()), MAX_FLOWS_PER_SOURCE - 1);
    r.feed(secs(0), key_from(src, 1), seg(5000, &h[1400..]));
    assert_eq!(r.flows_from(src.into()), MAX_FLOWS_PER_SOURCE - 2);
    r.expire(secs(60));
    assert_eq!(r.flows_from(src.into()), 0);
    assert!(r.is_empty() && r.buffered_bytes() == 0);
}

#[test]
fn idle_expiry_frees_memory_without_new_traffic() {
    let h = big_hello("idle.example");
    let mut r = Reassembler::new();
    r.feed(secs(100), key(0), seg(1, &h[..1400]));
    r.expire(secs(105));
    assert_eq!(r.len(), 1, "dentro do TTL");
    r.expire(secs(106));
    assert!(r.is_empty());
    assert_eq!(r.discarded(), 1);
    r.expire(secs(0)); // relogio para tras: nada acontece
}
