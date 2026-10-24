//! Decodifica bytes arbitrarios como uma sequencia de quadros de cada tipo de enlace, passando
//! pelo mesmo remontador de ClientHello, e gera o evento de cada um: nenhum caminho pode
//! entrar em panico nem estourar os limites da remontagem.
//!
//! Formato: [tamanho: u8][tamanho bytes de quadro]..., repetido; o que sobra e descartado.
#![no_main]
use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use mod_net_sensor::event::{EmitPolicy, build_event_reassembling};
use mod_net_sensor::protocols::{ALL_LINKS, decode_frame};
use mod_net_sensor::reassembly::{MAX_FLOWS, Reassembler};

fuzz_target!(|data: &[u8]| {
    let mut reasm = Reassembler::new();
    let mut rest = data;
    let mut at = 0u64;
    while let [len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (frame, after) = tail.split_at(n);
        rest = after;
        at += 1;
        for link in ALL_LINKS {
            let Ok(pkt) = decode_frame(link, frame) else {
                continue;
            };
            for policy in [EmitPolicy::Interesting, EmitPolicy::All] {
                let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(at);
                let _ = build_event_reassembling(
                    &mut reasm,
                    &pkt,
                    ts,
                    frame.len() as u64,
                    false,
                    policy,
                );
                assert!(reasm.len() <= MAX_FLOWS);
            }
        }
    }
});
