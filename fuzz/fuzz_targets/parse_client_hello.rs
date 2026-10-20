//! Payload TCP arbitrario tratado como inicio de um ClientHello TLS.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mod_net_sensor::protocols::tls::parse_client_hello;

fuzz_target!(|data: &[u8]| {
    let _ = parse_client_hello(data);
});
