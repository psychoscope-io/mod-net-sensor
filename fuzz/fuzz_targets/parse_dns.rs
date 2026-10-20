//! Mensagem DNS arbitraria (UDP ou TCP, sem o prefixo de tamanho).
#![no_main]
use libfuzzer_sys::fuzz_target;
use mod_net_sensor::protocols::dns::parse_dns;

fuzz_target!(|data: &[u8]| {
    let _ = parse_dns(data);
});
