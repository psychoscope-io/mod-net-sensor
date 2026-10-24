//! Benchmark do caminho quente: decodificacao e montagem do evento por pacote, e o
//! `decode_loop` ponta a ponta. Le os quadros de um pcap gerado por `scripts/gen_pcap.py`
//! (`make bench` o gera em `target/bench.pcap`; outro caminho em `BENCH_PCAP`) e, antes da
//! medicao de tempo, imprime as alocacoes por pacote de cada politica.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, SystemTime};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mod_net_sensor::capture::sniffer::Captured;
use mod_net_sensor::event::to_timestamp;
use mod_net_sensor::event::{EmitPolicy, build_event_reassembling};
use mod_net_sensor::ipc::framer::{append_frame, write_message};
use mod_net_sensor::pipeline::{PipelineCounters, decode_loop};
use mod_net_sensor::protocols::{LinkType, decode_frame};
use mod_net_sensor::reassembly::Reassembler;
use psychoscope_proto::v1::mensagem_ipc::Payload;
use psychoscope_proto::v1::{
    EventoFluxoRede, EventoTelemetria, MensagemIpc, ProtocoloTransporte,
    evento_fluxo_rede::MetadadosDns, evento_fluxo_rede::MetadadosL7, evento_telemetria,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// Conta chamadas e bytes de alocacao para reportar alocacoes por pacote.
struct CountingAlloc;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

// SAFETY: delega tudo ao alocador do sistema; so acrescenta contadores atomicos.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(new_size as u64, Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

struct Frame {
    ts: SystemTime,
    wire_len: u32,
    data: Vec<u8>,
}

fn load_frames() -> Vec<Frame> {
    let path = std::env::var("BENCH_PCAP").unwrap_or_else(|_| "target/bench.pcap".to_string());
    let mut cap = pcap::Capture::from_file(&path).unwrap_or_else(|e| {
        panic!("nao abriu {path}: {e}; rode `make bench` (gera o pcap com scripts/gen_pcap.py)")
    });
    let mut out = Vec::new();
    while let Ok(p) = cap.next_packet() {
        let ts = SystemTime::UNIX_EPOCH
            + Duration::new(p.header.ts.tv_sec as u64, p.header.ts.tv_usec as u32 * 1000);
        out.push(Frame {
            ts,
            wire_len: p.header.len,
            data: p.data.to_vec(),
        });
    }
    out
}

/// Decodifica e monta o evento de todos os quadros; devolve quantos viraram evento.
fn decode_all(frames: &[Frame], policy: EmitPolicy) -> usize {
    let mut reasm = Reassembler::new();
    let mut events = 0;
    for f in frames {
        let Ok(pkt) = decode_frame(LinkType::Ethernet, &f.data) else {
            continue;
        };
        let truncated = f.data.len() < f.wire_len as usize;
        let ev = build_event_reassembling(
            &mut reasm,
            &pkt,
            f.ts,
            u64::from(f.wire_len),
            truncated,
            policy,
        );
        events += usize::from(ev.is_some());
    }
    events
}

fn report_allocations(frames: &[Frame]) {
    for (name, policy) in [
        ("interesting", EmitPolicy::Interesting),
        ("all", EmitPolicy::All),
    ] {
        let (a0, b0) = (ALLOCS.load(Relaxed), BYTES.load(Relaxed));
        let events = decode_all(frames, policy);
        let allocs = ALLOCS.load(Relaxed) - a0;
        let bytes = BYTES.load(Relaxed) - b0;
        let n = frames.len() as f64;
        eprintln!(
            "alocacoes/pacote [{name}]: {:.2} ({:.0} bytes) | {} pacotes, {} eventos",
            allocs as f64 / n,
            bytes as f64 / n,
            frames.len(),
            events
        );
    }
}

fn bench_decode_event(c: &mut Criterion) {
    let frames = load_frames();
    report_allocations(&frames);
    let mut g = c.benchmark_group("decode_event");
    g.throughput(Throughput::Elements(frames.len() as u64));
    for (name, policy) in [
        ("interesting", EmitPolicy::Interesting),
        ("all", EmitPolicy::All),
    ] {
        g.bench_function(name, |b| {
            b.iter(|| black_box(decode_all(black_box(&frames), policy)))
        });
    }
    g.finish();
}

/// `decode_loop` com canal de entrada e consumidor de eventos, como em `main`.
fn bench_decode_loop(c: &mut Criterion) {
    let frames = load_frames();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .expect("runtime do benchmark");
    let mut g = c.benchmark_group("decode_loop");
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.sample_size(20);
    for (name, policy) in [
        ("interesting", EmitPolicy::Interesting),
        ("all", EmitPolicy::All),
    ] {
        g.bench_function(name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (ptx, prx) = mpsc::channel::<Captured>(8192);
                    let (etx, mut erx) = mpsc::channel(8192);
                    let counters = Arc::new(PipelineCounters::default());
                    let task = tokio::spawn(decode_loop(prx, etx, policy, true, counters));
                    let sink = tokio::spawn(async move {
                        let mut n = 0usize;
                        while erx.recv().await.is_some() {
                            n += 1;
                        }
                        n
                    });
                    for f in &frames {
                        let cap = Captured {
                            ts: f.ts,
                            wire_len: f.wire_len,
                            link: LinkType::Ethernet,
                            data: f.data.clone(),
                        };
                        if ptx.send(cap).await.is_err() {
                            break;
                        }
                    }
                    drop(ptx);
                    task.await.expect("decode_loop");
                    black_box(sink.await.expect("consumidor"))
                })
            })
        });
    }
    g.finish();
}

/// Mensagens de telemetria como o cliente IPC as monta (evento DNS dentro do envelope).
fn telemetry_messages(n: usize) -> Vec<MensagemIpc> {
    (0..n)
        .map(|i| MensagemIpc {
            id_mensagem: format!("mod-net-sensor-{i}"),
            timestamp: Some(to_timestamp(SystemTime::now())),
            payload: Some(Payload::Telemetria(EventoTelemetria {
                id_modulo: "mod-net-sensor".to_string(),
                dado: Some(evento_telemetria::Dado::Rede(EventoFluxoRede {
                    ip_origem: "192.168.0.8".to_string(),
                    ip_destino: "192.168.0.1".to_string(),
                    porta_origem: 51000,
                    porta_destino: 53,
                    protocolo: ProtocoloTransporte::ProtoUdp as i32,
                    tamanho_bytes: 74,
                    metadados_l7: Some(MetadadosL7::Dns(MetadadosDns {
                        dominio_consultado: "www.example.com".to_string(),
                        tipo_registro: 1,
                        ..Default::default()
                    })),
                    timestamp_captura: Some(to_timestamp(SystemTime::now())),
                    ..Default::default()
                })),
            })),
        })
        .collect()
}

/// Escrita de eventos num socket Unix real (um leitor descarta o que chega): mede a
/// serializacao, as alocacoes e as chamadas de escrita do caminho do cliente IPC.
fn bench_ipc_write(c: &mut Criterion) {
    const N: usize = 4096;
    let msgs = telemetry_messages(N);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime do benchmark");
    let mut g = c.benchmark_group("ipc_write");
    g.throughput(Throughput::Elements(N as u64));
    g.sample_size(30);
    g.bench_function("um_frame_por_escrita", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut tx, mut rx) = UnixStream::pair().expect("socketpair");
                let reader = tokio::spawn(async move {
                    let mut sink = vec![0u8; 1 << 16];
                    while rx.read(&mut sink).await.map(|n| n > 0).unwrap_or(false) {}
                });
                for m in &msgs {
                    write_message(&mut tx, m).await.expect("escrita");
                }
                drop(tx);
                reader.await.expect("leitor");
            })
        })
    });
    // como o cliente envia: frames de ate `batch` eventos num buffer reaproveitado, uma escrita
    for batch in [16usize, 64] {
        g.bench_function(format!("lote_de_{batch}"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut tx, mut rx) = UnixStream::pair().expect("socketpair");
                    let reader = tokio::spawn(async move {
                        let mut sink = vec![0u8; 1 << 16];
                        while rx.read(&mut sink).await.map(|n| n > 0).unwrap_or(false) {}
                    });
                    let mut buf = Vec::new();
                    for chunk in msgs.chunks(batch) {
                        buf.clear();
                        for m in chunk {
                            append_frame(&mut buf, m).expect("frame");
                        }
                        tx.write_all(&buf).await.expect("escrita");
                    }
                    drop(tx);
                    reader.await.expect("leitor");
                })
            })
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_decode_event,
    bench_decode_loop,
    bench_ipc_write
);
criterion_main!(benches);
