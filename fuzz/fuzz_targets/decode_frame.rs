//! Decodifica bytes arbitrarios como quadro de cada tipo de enlace e gera o evento
//! correspondente: nenhum caminho pode entrar em panico.
#![no_main]
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use mod_net_sensor::event::{EmitPolicy, build_event};
use mod_net_sensor::protocols::{ALL_LINKS, decode_frame};

fuzz_target!(|data: &[u8]| {
    for link in ALL_LINKS {
        if let Ok(pkt) = decode_frame(link, data) {
            for policy in [EmitPolicy::Interesting, EmitPolicy::All] {
                let _ = build_event(&pkt, SystemTime::UNIX_EPOCH, data.len() as u64, policy);
            }
        }
    }
});
