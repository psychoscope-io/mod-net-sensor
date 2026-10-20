//! Remontador de ClientHello: o fuzzer escreve uma sequencia de segmentos (fluxo, relogio,
//! desvio de seq, flags e payload) e o alvo confere os invariantes de memoria e de saida.
//!
//! Formato de cada operacao: [fluxo: u16][tempo: u8 (x250 ms)][ajuste de seq: i8][ctrl: u8]
//! [len: u8][len bytes]. `ctrl`: bit 0 RST, bit 1 truncado, bit 2 prefixa um inicio de
//! ClientHello valido (5 bytes de registro + tipo 1) cujo tamanho declarado vem dos 2 bytes
//! seguintes do payload, o que deixa o fuzzer iniciar buffers facilmente.
#![no_main]
use std::collections::HashMap;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use mod_net_sensor::protocols::tcp::RST;
use mod_net_sensor::reassembly::{
    FlowKey, MAX_FLOWS, MAX_RECORD_BYTES, Outcome, Reassembler, Segment,
};

fuzz_target!(|data: &[u8]| {
    let mut r = Reassembler::new();
    let mut next_seq: HashMap<u16, u32> = HashMap::new();
    let mut now = Duration::from_secs(1_700_000_000);
    let mut rest = data;
    while let [f0, f1, dt, adj, ctrl, len, tail @ ..] = rest {
        let flow = u16::from_be_bytes([*f0, *f1]);
        let n = usize::from(*len).min(tail.len());
        let (body, after) = tail.split_at(n);
        rest = after;

        let mut payload = Vec::with_capacity(n + 6);
        if ctrl & 4 != 0 {
            let declared = body.get(..2).map_or(0x0400, |b| u16::from_be_bytes([b[0], b[1]]));
            payload.extend([0x16, 0x03, 0x01]);
            payload.extend(declared.to_be_bytes());
            payload.push(0x01);
        }
        payload.extend(body);

        now += Duration::from_millis(u64::from(*dt) * 250);
        let expected = next_seq.entry(flow).or_insert(0x1000);
        let seq = expected.wrapping_add(i32::from(*adj as i8) as u32);
        *expected = seq.wrapping_add(payload.len() as u32);

        let key = FlowKey {
            src_ip: [10, 0, *f0, *f1].into(),
            src_port: 40000,
            dst_ip: [10, 9, 9, 9].into(),
            dst_port: 443,
        };
        let seg = Segment {
            seq,
            flags: if ctrl & 1 != 0 { RST } else { 0 },
            payload: &payload,
            truncated: ctrl & 2 != 0,
        };
        if let Outcome::Complete(rec) = r.feed(now, key, seg) {
            assert!(rec.len() <= MAX_RECORD_BYTES);
            assert!(rec.starts_with(&[0x16, 0x03]));
        }
        assert!(r.len() <= MAX_FLOWS);
        assert!(r.buffered_bytes() <= r.len() * MAX_RECORD_BYTES);
    }
});
