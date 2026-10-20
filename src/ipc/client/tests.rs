use super::*;
use crate::ipc::framer::{read_frame, write_frame, write_message};
use psychoscope_proto::v1::HelloResposta;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use tokio::net::UnixListener;

#[derive(Default)]
struct MockCtl {
    paused: AtomicBool,
    reconfigs: AtomicUsize,
    fail_reconfig: AtomicBool,
}
impl Controller for MockCtl {
    fn pause(&self) {
        self.paused.store(true, Relaxed);
    }
    fn resume(&self) {
        self.paused.store(false, Relaxed);
    }
    async fn reconfigure(&self, p: HashMap<String, String>) -> Result<(), String> {
        self.reconfigs.fetch_add(1, Relaxed);
        if self.fail_reconfig.load(Relaxed) || !p.contains_key("bpf") {
            return Err("bpf ausente ou recusado".into());
        }
        Ok(())
    }
    fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets_captured: 11,
            bytes: 2222,
            packets_dropped: 3,
        }
    }
}

fn sock_path(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("client-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join("core.sock")
}

fn cfg(sock: &std::path::Path) -> ClientConfig {
    let mut c = ClientConfig::new(sock.to_path_buf(), "mod-net-sensor".into(), "9.9.9".into());
    c.min_backoff = Duration::from_millis(30);
    c.max_backoff = Duration::from_millis(100);
    c.hello_timeout = Duration::from_millis(500);
    c.status_interval_override = Some(Duration::from_millis(50));
    c
}

fn accept_msg(accepted: bool, err: &str) -> MensagemIpc {
    MensagemIpc {
        id_mensagem: "ack".into(),
        timestamp: None,
        payload: Some(Payload::HelloResposta(HelloResposta {
            aceito: accepted,
            mensagem_erro: err.into(),
            versao_core: "test".into(),
            intervalo_status_seg: 5,
        })),
    }
}

fn ev(domain: &str) -> EventoFluxoRede {
    EventoFluxoRede {
        ip_origem: "10.0.0.1".into(),
        tamanho_bytes: 60,
        porta_destino: 53,
        ..Default::default()
    }
    .tap(|e| e.ip_destino = domain.into())
}
trait Tap: Sized {
    fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
        f(&mut self);
        self
    }
}
impl Tap for EventoFluxoRede {}

async fn recv_msg(s: &mut UnixStream) -> MensagemIpc {
    timeout(Duration::from_secs(3), read_message(s, 0))
        .await
        .expect("timeout lendo do cliente")
        .unwrap()
        .expect("EOF")
}

async fn handshake(l: &UnixListener) -> (UnixStream, HelloModulo) {
    let (mut s, _) = timeout(Duration::from_secs(3), l.accept())
        .await
        .expect("cliente nao conectou")
        .unwrap();
    let m = recv_msg(&mut s).await;
    let Some(Payload::Hello(h)) = m.payload else {
        panic!("primeira mensagem nao e Hello: {m:?}")
    };
    write_message(&mut s, &accept_msg(true, "")).await.unwrap();
    (s, h)
}

struct Harness {
    listener: UnixListener,
    events: mpsc::Sender<EventoFluxoRede>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Exit>,
    ctl: Arc<MockCtl>,
    counters: Arc<ClientCounters>,
}

fn start(tag: &str, drained: bool) -> Harness {
    let sock = sock_path(tag);
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();
    let ctl = Arc::new(MockCtl::default());
    let client = Client::new(cfg(&sock), ctl.clone()).exit_when_drained(drained);
    let counters = client.counters.clone();
    let (etx, erx) = mpsc::channel(64);
    let (stx, srx) = watch::channel(false);
    let task = tokio::spawn(async move { client.run(erx, srx).await });
    Harness {
        listener,
        events: etx,
        shutdown: stx,
        task,
        ctl,
        counters,
    }
}

#[tokio::test]
async fn hello_telemetry_status_and_clean_shutdown() {
    let h = start("basic", false);
    let (mut core, hello) = handshake(&h.listener).await;
    assert_eq!(
        (
            hello.id_modulo.as_str(),
            hello.versao_protocolo,
            hello.versao_modulo.as_str(),
            hello.pid
        ),
        (
            "mod-net-sensor",
            PROTOCOL_VERSION,
            "9.9.9",
            std::process::id()
        )
    );

    h.events.send(ev("1.1.1.1")).await.unwrap();
    let (mut got_event, mut got_status) = (false, false);
    while !(got_event && got_status) {
        let m = recv_msg(&mut core).await;
        assert!(m.timestamp.is_some() && !m.id_mensagem.is_empty());
        match m.payload {
            Some(Payload::Telemetria(t)) => {
                assert_eq!(t.id_modulo, "mod-net-sensor");
                let Some(evento_telemetria::Dado::Rede(r)) = t.dado else {
                    panic!()
                };
                assert_eq!(r.ip_destino, "1.1.1.1");
                got_event = true;
            }
            Some(Payload::Status(s)) => {
                assert_eq!(s.id_modulo, "mod-net-sensor");
                assert_eq!(
                    (
                        s.pacotes_capturados,
                        s.bytes_processados,
                        s.pacotes_descartados
                    ),
                    (11, 2222, 3)
                );
                assert!(s.uso_memoria_mb > 0.0);
                got_status = true;
            }
            other => panic!("payload inesperado: {other:?}"),
        }
    }
    h.shutdown.send(true).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), h.task)
            .await
            .unwrap()
            .unwrap(),
        Exit::Shutdown
    );
    assert_eq!(h.counters.events_sent.load(Relaxed), 1);
}

#[tokio::test]
async fn status_reports_events_sent_total() {
    let h = start("evcount", false);
    let (mut core, _) = handshake(&h.listener).await;
    for _ in 0..3 {
        h.events.send(ev("x")).await.unwrap();
    }
    loop {
        if let Some(Payload::Status(s)) = recv_msg(&mut core).await.payload
            && s.eventos_processados == 3
        {
            break;
        }
    }
    h.shutdown.send(true).unwrap();
    let _ = h.task.await;
}

async fn command(
    core: &mut UnixStream,
    id: &str,
    acao: TipoAcao,
    params: &[(&str, &str)],
) -> RespostaComando {
    let m = MensagemIpc {
        id_mensagem: "c".into(),
        timestamp: None,
        payload: Some(Payload::Comando(ComandoControle {
            id_comando: id.into(),
            acao: acao as i32,
            parametros: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })),
    };
    write_message(core, &m).await.unwrap();
    loop {
        // pula telemetria/status intercalados
        if let Some(Payload::Resposta(r)) = recv_msg(core).await.payload {
            return r;
        }
    }
}

#[tokio::test]
async fn commands_ack_nack_and_encerrar() {
    let h = start("cmds", false);
    let (mut core, _) = handshake(&h.listener).await;

    let r = command(&mut core, "c1", TipoAcao::Pausar, &[]).await;
    assert!(r.sucesso && r.id_comando_referencia == "c1");
    assert!(h.ctl.paused.load(Relaxed));
    let r = command(&mut core, "c2", TipoAcao::Retomar, &[]).await;
    assert!(r.sucesso && !h.ctl.paused.load(Relaxed));

    let r = command(&mut core, "c3", TipoAcao::Reconfigurar, &[("bpf", "udp")]).await;
    assert!(r.sucesso);
    let r = command(&mut core, "c4", TipoAcao::Reconfigurar, &[]).await;
    assert!(!r.sucesso && r.mensagem_erro.contains("bpf") && r.id_comando_referencia == "c4");
    let r = command(&mut core, "c5", TipoAcao::AcaoDesconhecida, &[]).await;
    assert!(!r.sucesso);

    // acao com valor de enum fora da faixa tambem e NACK, sem panico
    let m = MensagemIpc {
        id_mensagem: "c".into(),
        timestamp: None,
        payload: Some(Payload::Comando(ComandoControle {
            id_comando: "c6".into(),
            acao: 99,
            parametros: HashMap::new(),
        })),
    };
    write_message(&mut core, &m).await.unwrap();
    loop {
        if let Some(Payload::Resposta(r)) = recv_msg(&mut core).await.payload {
            assert!(!r.sucesso && r.id_comando_referencia == "c6");
            break;
        }
    }

    let r = command(&mut core, "c7", TipoAcao::Encerrar, &[]).await;
    assert!(
        r.sucesso,
        "o ACK do ENCERRAR deve ser enviado antes de sair"
    );
    assert_eq!(
        timeout(Duration::from_secs(2), h.task)
            .await
            .unwrap()
            .unwrap(),
        Exit::Commanded
    );
}

#[tokio::test]
async fn reconnects_after_core_drops_connection_and_counts_drops_meanwhile() {
    let h = start("reconn", false);
    let (core, _) = handshake(&h.listener).await;
    drop(core); // Core derruba a sessao

    // Sem listener aceitando por um instante, eventos sao descartados e contados.
    for _ in 0..5 {
        h.events.send(ev("x")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    let (mut core2, hello2) = handshake(&h.listener).await; // reconectou e refez o Hello
    assert_eq!(hello2.id_modulo, "mod-net-sensor");
    assert!(h.counters.events_dropped.load(Relaxed) <= 5);

    h.events.send(ev("depois")).await.unwrap();
    loop {
        if let Some(Payload::Telemetria(_)) = recv_msg(&mut core2).await.payload {
            break;
        }
    }
    h.shutdown.send(true).unwrap();
    let _ = h.task.await;
}

#[tokio::test]
async fn rejected_hello_is_retried_with_backoff() {
    let sock = sock_path("reject");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();
    let ctl = Arc::new(MockCtl::default());
    let client = Client::new(cfg(&sock), ctl);
    let (_etx, erx) = mpsc::channel(1);
    let (stx, srx) = watch::channel(false);
    let task = tokio::spawn(async move { client.run(erx, srx).await });

    let started = std::time::Instant::now();
    for _ in 0..3 {
        let (mut s, _) = timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let _ = recv_msg(&mut s).await;
        write_message(&mut s, &accept_msg(false, "nao autorizado"))
            .await
            .unwrap();
    }
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "backoff 30ms + 60ms entre tentativas"
    );
    stx.send(true).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Exit::Shutdown
    );
}

#[tokio::test]
async fn waits_for_core_to_appear() {
    let sock = sock_path("late");
    let _ = std::fs::remove_file(&sock);
    let client = Client::new(cfg(&sock), Arc::new(MockCtl::default()));
    let (_etx, erx) = mpsc::channel(1);
    let (stx, srx) = watch::channel(false);
    let task = tokio::spawn(async move { client.run(erx, srx).await });

    tokio::time::sleep(Duration::from_millis(250)).await; // varias tentativas falhas
    let listener = UnixListener::bind(&sock).unwrap();
    let (_s, hello) = handshake(&listener).await;
    assert_eq!(hello.id_modulo, "mod-net-sensor");
    stx.send(true).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Exit::Shutdown
    );
}

#[tokio::test]
async fn shutdown_interrupts_backoff_promptly() {
    let sock = sock_path("sdbackoff");
    let _ = std::fs::remove_file(&sock);
    let mut c = cfg(&sock);
    c.min_backoff = Duration::from_secs(30);
    c.max_backoff = Duration::from_secs(30);
    let client = Client::new(c, Arc::new(MockCtl::default()));
    let (_etx, erx) = mpsc::channel(1);
    let (stx, srx) = watch::channel(false);
    let task = tokio::spawn(async move { client.run(erx, srx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    stx.send(true).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        Exit::Shutdown
    );
}

#[tokio::test]
async fn garbage_from_core_forces_reconnect() {
    let h = start("garbage", false);
    let (mut core, _) = handshake(&h.listener).await;
    use tokio::io::AsyncWriteExt;
    core.write_all(&[0x00, 0x10, 0x00, 0x01]).await.unwrap(); // frame de 1 MiB + 1
    let (_core2, _) = handshake(&h.listener).await; // cliente derrubou e reconectou
    h.shutdown.send(true).unwrap();
    let _ = h.task.await;
}

#[tokio::test]
async fn drained_exit_sends_final_status() {
    let h = start("drain", true);
    let (mut core, _) = handshake(&h.listener).await;
    for _ in 0..2 {
        h.events.send(ev("x")).await.unwrap();
    }
    drop(h.events);
    let mut sent = 0;
    let mut last_status = None;
    loop {
        let m = timeout(Duration::from_secs(3), read_message(&mut core, 0))
            .await
            .unwrap()
            .unwrap();
        let Some(m) = m else { break };
        match m.payload {
            Some(Payload::Telemetria(_)) => sent += 1,
            Some(Payload::Status(s)) => last_status = Some(s),
            _ => {}
        }
    }
    assert_eq!(
        timeout(Duration::from_secs(2), h.task)
            .await
            .unwrap()
            .unwrap(),
        Exit::Drained
    );
    assert_eq!(sent, 2);
    assert_eq!(last_status.expect("status final").eventos_processados, 2);
}

#[tokio::test]
async fn unexpected_first_reply_is_not_accepted() {
    let sock = sock_path("badreply");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();
    let client = Client::new(cfg(&sock), Arc::new(MockCtl::default()));
    let (_etx, erx) = mpsc::channel(1);
    let (stx, srx) = watch::channel(false);
    let task = tokio::spawn(async move { client.run(erx, srx).await });

    let (mut s, _) = listener.accept().await.unwrap();
    let _ = recv_msg(&mut s).await;
    // responde com um frame que nao e HelloResposta
    let bogus = MensagemIpc {
        id_mensagem: "x".into(),
        timestamp: None,
        payload: None,
    };
    write_message(&mut s, &bogus).await.ok();
    // ... e o cliente tenta de novo (nova conexao), nunca entrando em sessao
    let (mut s2, _) = timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let _ = recv_msg(&mut s2).await;
    let _ = read_frame(&mut s2, 0).await; // sem silencio: so fecha
    let _ = write_frame(&mut s2, &[1]).await;
    stx.send(true).unwrap();
    let _ = timeout(Duration::from_secs(2), task).await;
}
