use super::*;
use crate::capture::pcapfile::{LINKTYPE_ETHERNET, PcapPacket, write_pcap};
use crate::protocols::testutil::*;

fn fixture(dir: &tempfile_dir::Dir, linktype: u32, pkts: &[PcapPacket<'_>]) -> PathBuf {
    let path = dir.path.join("t.pcap");
    let mut f = std::fs::File::create(&path).unwrap();
    write_pcap(&mut f, linktype, 65535, pkts).unwrap();
    path
}

/// Diretorio temporario sem dependencia externa.
mod tempfile_dir {
    use std::path::PathBuf;
    pub struct Dir {
        pub path: PathBuf,
    }
    impl Dir {
        pub fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sniffer-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn cfg(path: PathBuf, bpf: Option<&str>) -> CaptureConfig {
    CaptureConfig {
        source: Source::File(path),
        bpf: bpf.map(String::from),
        snaplen: DEFAULT_SNAPLEN,
        promisc: false,
    }
}

fn drain(mut rx: mpsc::Receiver<Captured>) -> Vec<Captured> {
    let mut v = Vec::new();
    while let Ok(p) = rx.try_recv() {
        v.push(p);
    }
    v
}

#[test]
fn replays_file_in_order_with_timestamps_and_wire_len() {
    let dir = tempfile_dir::Dir::new("order");
    let dns = eth_v4(17, &udp(5000, 53, &dns_query("a.com", 1)));
    let syn = eth_v4(6, &tcp(1, 80, 0x02, &[]));
    let path = fixture(
        &dir,
        LINKTYPE_ETHERNET,
        &[
            PcapPacket {
                ts_sec: 1_700_000_000,
                ts_usec: 250_000,
                data: &dns,
                wire_len: None,
            },
            PcapPacket {
                ts_sec: 1_700_000_001,
                ts_usec: 0,
                data: &syn[..30],
                wire_len: Some(syn.len() as u32),
            },
        ],
    );
    let (tx, rx) = mpsc::channel(16);
    let h = spawn(&cfg(path, None), tx).unwrap();
    assert!(!h.live);
    h.join.join().unwrap().unwrap();
    let got = drain(rx);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].data, dns);
    assert_eq!(got[0].link, LinkType::Ethernet);
    assert_eq!(
        got[0].ts,
        SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 250_000_000)
    );
    assert_eq!(
        (got[1].data.len(), got[1].wire_len),
        (30, syn.len() as u32),
        "snaplen truncou, wire_len preservado"
    );
    assert_eq!(h.counters.captured.load(Relaxed), 2);
    assert_eq!(
        h.counters.bytes.load(Relaxed),
        (dns.len() + syn.len()) as u64
    );
}

#[test]
fn bpf_filter_applies_to_files() {
    let dir = tempfile_dir::Dir::new("bpf");
    let dns = eth_v4(17, &udp(5000, 53, &dns_query("a.com", 1)));
    let other = eth_v4(17, &udp(5000, 9999, b"x"));
    let path = fixture(
        &dir,
        LINKTYPE_ETHERNET,
        &[
            PcapPacket {
                ts_sec: 1,
                ts_usec: 0,
                data: &other,
                wire_len: None,
            },
            PcapPacket {
                ts_sec: 2,
                ts_usec: 0,
                data: &dns,
                wire_len: None,
            },
        ],
    );
    let (tx, rx) = mpsc::channel(16);
    let h = spawn(&cfg(path, Some("udp port 53")), tx).unwrap();
    h.join.join().unwrap().unwrap();
    let got = drain(rx);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data, dns);
}

#[test]
fn invalid_bpf_unsupported_link_and_missing_file_fail_synchronously() {
    let dir = tempfile_dir::Dir::new("errs");
    let path = fixture(&dir, LINKTYPE_ETHERNET, &[]);
    let (tx, _rx) = mpsc::channel(1);
    assert!(matches!(
        spawn(&cfg(path.clone(), Some("isto nao e bpf ((")), tx.clone()),
        Err(CaptureError::Pcap(_))
    ));

    let weird = dir.path.join("weird.pcap");
    let mut f = std::fs::File::create(&weird).unwrap();
    write_pcap(&mut f, 147, 65535, &[]).unwrap();
    assert!(matches!(
        spawn(&cfg(weird, None), tx.clone()),
        Err(CaptureError::UnsupportedLink(147))
    ));

    assert!(matches!(
        spawn(&cfg(dir.path.join("nao-existe.pcap"), None), tx),
        Err(CaptureError::Pcap(_))
    ));
}

#[test]
fn reconfigure_is_rejected_for_files_and_stop_ends_thread() {
    let dir = tempfile_dir::Dir::new("reconf");
    let pkt = eth_v4(17, &udp(1, 2, b"x"));
    let many: Vec<PcapPacket<'_>> = (0..1000)
        .map(|i| PcapPacket {
            ts_sec: i,
            ts_usec: 0,
            data: &pkt,
            wire_len: None,
        })
        .collect();
    let path = fixture(&dir, LINKTYPE_ETHERNET, &many);
    let (tx, rx) = mpsc::channel(1); // pequeno: a thread bloqueia no blocking_send
    let h = spawn(&cfg(path, None), tx).unwrap();

    let (otx, orx) = oneshot::channel();
    h.reconfig
        .send(ReconfigRequest {
            bpf: "udp".into(),
            reply: otx,
        })
        .unwrap();
    h.stop.store(true, Relaxed);
    drop(rx); // libera a thread bloqueada no envio
    let _ = h.join.join().unwrap();
    // A resposta pode nao ter sido processada se stop venceu a corrida; se foi, deve ser erro.
    if let Ok(r) = orx.blocking_recv() {
        assert!(r.is_err());
    }
}

#[test]
fn timestamp_helper_clamps_garbage() {
    assert_eq!(timestamp(-5, -1), SystemTime::UNIX_EPOCH);
    assert_eq!(
        timestamp(1, 5_000_000),
        SystemTime::UNIX_EPOCH + Duration::new(1, 999_999_000)
    );
}

fn live_ctx() -> (Ctx, Arc<CaptureCounters>) {
    let (tx, _rx) = mpsc::channel(1);
    let (_rtx, rrx) = std::sync::mpsc::channel();
    let counters = Arc::new(CaptureCounters::default());
    let ctx = Ctx {
        tx,
        stop: Arc::new(AtomicBool::new(false)),
        paused: Arc::new(AtomicBool::new(false)),
        counters: counters.clone(),
        reconfig: rrx,
    };
    (ctx, counters)
}

#[test]
fn kernel_drops_accumulate_and_survive_a_counter_reset() {
    let (ctx, counters) = live_ctx();
    let mut seen = KernelStats::default();
    let mut feed = |dropped, if_dropped| {
        record_kernel_drops(
            &ctx,
            &mut seen,
            Some(KernelStats {
                dropped,
                if_dropped,
            }),
        );
        (
            counters.kernel_dropped.load(Relaxed),
            counters.interface_dropped.load(Relaxed),
        )
    };
    assert_eq!(feed(5, 1), (5, 1));
    assert_eq!(feed(8, 1), (8, 1), "so o acrescimo e somado");
    assert_eq!(feed(8, 1), (8, 1), "sem mudanca, sem soma");
    // as estatisticas reiniciaram (valor menor): o total nao regride e o novo valor conta
    assert_eq!(feed(2, 0), (10, 1));
    assert_eq!(feed(3, 4), (11, 5));
}

#[test]
fn missing_kernel_stats_leave_the_totals_alone() {
    let (ctx, counters) = live_ctx();
    let mut seen = KernelStats::default();
    record_kernel_drops(&ctx, &mut seen, None);
    assert_eq!(counters.kernel_dropped.load(Relaxed), 0);
}
