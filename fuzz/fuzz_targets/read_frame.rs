//! Framer length-prefixed do IPC (e a decodificacao protobuf) sobre um stream arbitrario.
//! Le frames ate EOF ou erro, com varios tetos de tamanho; o framer async roda em um
//! runtime `current_thread` criado uma vez por processo.
#![no_main]
use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use mod_net_sensor::ipc::framer::{MAX_FRAME_SIZE, read_frame, read_message};
use tokio::runtime::{Builder, Runtime};

thread_local! {
    static RT: RefCell<Runtime> = RefCell::new(
        Builder::new_current_thread().build().expect("runtime tokio")
    );
}

fuzz_target!(|data: &[u8]| {
    // o primeiro byte escolhe o teto: 0 (= MAX_FRAME_SIZE), pequeno, medio ou acima do maximo
    let (max, stream) = match data.split_first() {
        Some((m, rest)) => (
            match m % 4 {
                0 => 0,
                1 => 16,
                2 => 4096,
                _ => MAX_FRAME_SIZE + 1,
            },
            rest,
        ),
        None => (0, data),
    };
    RT.with(|rt| {
        rt.borrow().block_on(async {
            let mut r = stream;
            while let Ok(Some(_)) = read_frame(&mut r, max).await {}
            let mut r = stream;
            while let Ok(Some(_)) = read_message(&mut r, max).await {}
        });
    });
});
