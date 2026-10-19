use clap::Parser;
use mod_net_sensor::config::Config;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cfg = Config::parse();
    // Fase 4: captura, decode e envio. Por enquanto apenas valida a configuracao.
    println!(
        "mod-net-sensor {} (modulo={}, socket={})",
        env!("CARGO_PKG_VERSION"),
        cfg.module_id,
        cfg.socket.display()
    );
}
