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
use mod_net_sensor::event::{EmitPolicy, build_event_reassembling};
use mod_net_sensor::pipeline::{PipelineCounters, decode_loop};
use mod_net_sensor::protocols::{LinkType, decode_frame};
use mod_net_sensor::reassembly::Reassembler;
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

criterion_group!(benches, bench_decode_event, bench_decode_loop);
criterion_main!(benches);
