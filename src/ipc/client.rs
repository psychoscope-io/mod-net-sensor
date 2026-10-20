//! SINK: cliente IPC do modulo. Conecta ao `core.sock`, faz o handshake `Hello`, envia
//! telemetria e status periodico (heartbeat), atende comandos de controle com ACK/NACK
//! e reconecta com backoff exponencial quando a conexao cai.
//!
//! Enquanto desconectado, os eventos recebidos sao descartados (e contados): a captura
//! nunca fica retida esperando o Core.
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, SystemTime};

use psychoscope_proto::v1::{
    ComandoControle, EventoFluxoRede, EventoTelemetria, HelloModulo, MensagemIpc, RespostaComando,
    StatusModulo, comando_controle::TipoAcao, evento_telemetria, mensagem_ipc::Payload,
};
use tokio::io::AsyncWrite;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval, sleep, timeout};

use super::framer::{FrameError, read_message, write_message};
use crate::event::to_timestamp;
use crate::procstats::{CpuMeter, rss_mb};

/// Versao do protocolo IPC falada por este modulo (deve casar com o Core).
pub const PROTOCOL_VERSION: u32 = 1;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const RECONFIGURE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub socket: PathBuf,
    pub module_id: String,
    pub module_version: String,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub hello_timeout: Duration,
    /// Substitui o intervalo de status informado pelo Core (testes).
    pub status_interval_override: Option<Duration>,
}

impl ClientConfig {
    pub fn new(socket: PathBuf, module_id: String, module_version: String) -> Self {
        Self {
            socket,
            module_id,
            module_version,
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            hello_timeout: Duration::from_secs(5),
            status_interval_override: None,
        }
    }
}

/// Numeros do pipeline reportados no `StatusModulo`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StatsSnapshot {
    pub packets_captured: u64,
    pub bytes: u64,
    /// Pacotes perdidos em qualquer etapa (kernel, canal do sniffer).
    pub packets_dropped: u64,
}

/// Interface entre os comandos do Core e o resto do sensor.
pub trait Controller: Send + Sync + 'static {
    fn pause(&self);
    fn resume(&self);
    fn reconfigure(
        &self,
        params: HashMap<String, String>,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn stats(&self) -> StatsSnapshot;
}

/// Contadores do proprio cliente, compartilhados com o restante do processo.
#[derive(Debug, Default)]
pub struct ClientCounters {
    pub events_sent: AtomicU64,
    /// Eventos descartados por estar desconectado ou por falha de escrita.
    pub events_dropped: AtomicU64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// `shutdown` foi acionado (sinal do processo).
    Shutdown,
    /// O Core enviou ENCERRAR (e recebeu o ACK).
    Commanded,
    /// O canal de eventos fechou e nao ha mais o que enviar (apenas com `exit_when_drained`).
    Drained,
}

#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("conexao: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Frame(#[from] FrameError),
    #[error("core recusou o Hello: {0}")]
    Rejected(String),
    #[error("resposta inesperada ao Hello")]
    UnexpectedReply,
    #[error("tempo esgotado: {0}")]
    Timeout(&'static str),
    #[error("conexao encerrada pelo core")]
    Closed,
}

struct Ids {
    prefix: String,
    n: AtomicU64,
}

impl Ids {
    fn next(&self) -> String {
        format!("{}-{}", self.prefix, self.n.fetch_add(1, Relaxed))
    }
}

pub struct Client<C: Controller> {
    cfg: ClientConfig,
    ctl: Arc<C>,
    pub counters: Arc<ClientCounters>,
    ids: Ids,
    exit_when_drained: bool,
}

impl<C: Controller> Client<C> {
    pub fn new(cfg: ClientConfig, ctl: Arc<C>) -> Self {
        let ids = Ids {
            prefix: cfg.module_id.clone(),
            n: AtomicU64::new(1),
        };
        Self {
            cfg,
            ctl,
            counters: Arc::new(ClientCounters::default()),
            ids,
            exit_when_drained: false,
        }
    }

    /// Faz `run` retornar `Exit::Drained` quando o canal de eventos fecha e esvazia.
    pub fn exit_when_drained(mut self, yes: bool) -> Self {
        self.exit_when_drained = yes;
        self
    }

    fn envelope(&self, payload: Payload) -> MensagemIpc {
        MensagemIpc {
            id_mensagem: self.ids.next(),
            timestamp: Some(to_timestamp(SystemTime::now())),
            payload: Some(payload),
        }
    }

    /// Executa ate `shutdown`, ENCERRAR do Core ou (opcionalmente) fim dos eventos.
    pub async fn run(
        &self,
        mut events: mpsc::Receiver<EventoFluxoRede>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Exit {
        let mut backoff = self.cfg.min_backoff;
        let mut events_open = true;
        loop {
            if *shutdown.borrow() {
                return Exit::Shutdown;
            }
            match self.connect().await {
                Ok((stream, core_interval)) => {
                    tracing_log(format_args!(
                        "conectado ao core ({})",
                        self.cfg.socket.display()
                    ));
                    backoff = self.cfg.min_backoff;
                    let every = self.cfg.status_interval_override.unwrap_or(core_interval);
                    match self
                        .session(stream, every, &mut events, &mut events_open, &mut shutdown)
                        .await
                    {
                        Ok(exit) => return exit,
                        Err(e) => tracing_log(format_args!("sessao encerrada: {e}")),
                    }
                }
                Err(e) => tracing_log(format_args!(
                    "falha ao conectar: {e} (nova tentativa em {backoff:?})"
                )),
            }

            // Espera o backoff descartando eventos (nao retem a captura) e atento ao shutdown.
            let deadline = Instant::now() + backoff;
            backoff = (backoff * 2).min(self.cfg.max_backoff);
            loop {
                tokio::select! {
                    _ = sleep(deadline.saturating_duration_since(Instant::now())) => break,
                    _ = shutdown.changed() => { if *shutdown.borrow() { return Exit::Shutdown; } }
                    ev = events.recv(), if events_open => match ev {
                        Some(_) => { self.counters.events_dropped.fetch_add(1, Relaxed); }
                        None => {
                            events_open = false;
                            if self.exit_when_drained { return Exit::Drained; }
                        }
                    },
                }
            }
        }
    }

    async fn connect(&self) -> Result<(UnixStream, Duration), SessionError> {
        let mut s = timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.cfg.socket))
            .await
            .map_err(|_| SessionError::Timeout("connect"))??;

        let hello = self.envelope(Payload::Hello(HelloModulo {
            id_modulo: self.cfg.module_id.clone(),
            versao_protocolo: PROTOCOL_VERSION,
            versao_modulo: self.cfg.module_version.clone(),
            pid: std::process::id(),
        }));
        timeout(WRITE_TIMEOUT, write_message(&mut s, &hello))
            .await
            .map_err(|_| SessionError::Timeout("hello"))??;

        let reply = timeout(self.cfg.hello_timeout, read_message(&mut s, 0))
            .await
            .map_err(|_| SessionError::Timeout("HelloResposta"))??
            .ok_or(SessionError::Closed)?;
        match reply.payload {
            Some(Payload::HelloResposta(r)) if r.aceito => Ok((
                s,
                Duration::from_secs(u64::from(r.intervalo_status_seg.max(1))),
            )),
            Some(Payload::HelloResposta(r)) => Err(SessionError::Rejected(r.mensagem_erro)),
            _ => Err(SessionError::UnexpectedReply),
        }
    }

    async fn session(
        &self,
        stream: UnixStream,
        status_every: Duration,
        events: &mut mpsc::Receiver<EventoFluxoRede>,
        events_open: &mut bool,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Exit, SessionError> {
        let (mut rd, mut wr) = stream.into_split();

        // A leitura nao e cancel-safe: roda em task propria e entrega mensagens por canal.
        let (in_tx, mut inbox) = mpsc::channel::<MensagemIpc>(16);
        let reader = tokio::spawn(async move {
            while let Ok(Some(m)) = read_message(&mut rd, 0).await {
                if in_tx.send(m).await.is_err() {
                    break;
                }
            }
        });
        let _guard = AbortOnDrop(reader);

        let mut tick = interval(status_every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut cpu = CpuMeter::new();

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return Ok(Exit::Shutdown); }
                }
                msg = inbox.recv() => {
                    let Some(m) = msg else { return Err(SessionError::Closed) };
                    if let Some(exit) = self.handle(m, &mut wr).await? { return Ok(exit); }
                }
                ev = events.recv(), if *events_open => match ev {
                    Some(ev) => {
                        let m = self.envelope(Payload::Telemetria(EventoTelemetria {
                            id_modulo: self.cfg.module_id.clone(),
                            dado: Some(evento_telemetria::Dado::Rede(ev)),
                        }));
                        match self.send(&mut wr, &m).await {
                            Ok(()) => { self.counters.events_sent.fetch_add(1, Relaxed); }
                            Err(e) => { self.counters.events_dropped.fetch_add(1, Relaxed); return Err(e); }
                        }
                    }
                    None => {
                        *events_open = false;
                        if self.exit_when_drained {
                            let st = self.status(&mut cpu);
                            self.send(&mut wr, &st).await?; // ultimo status com os totais finais
                            return Ok(Exit::Drained);
                        }
                    }
                },
                _ = tick.tick() => {
                    let st = self.status(&mut cpu);
                    self.send(&mut wr, &st).await?;
                }
            }
        }
    }

    fn status(&self, cpu: &mut CpuMeter) -> MensagemIpc {
        let s = self.ctl.stats();
        self.envelope(Payload::Status(StatusModulo {
            id_modulo: self.cfg.module_id.clone(),
            eventos_processados: self.counters.events_sent.load(Relaxed),
            bytes_processados: s.bytes,
            uso_memoria_mb: rss_mb(),
            uso_cpu_percent: cpu.sample(),
            pacotes_capturados: s.packets_captured,
            pacotes_descartados: s.packets_dropped,
        }))
    }

    async fn send<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        m: &MensagemIpc,
    ) -> Result<(), SessionError> {
        timeout(WRITE_TIMEOUT, write_message(w, m))
            .await
            .map_err(|_| SessionError::Timeout("escrita"))??;
        Ok(())
    }

    /// Atende uma mensagem do Core. `Some(exit)` encerra a sessao com esse resultado.
    async fn handle<W: AsyncWrite + Unpin>(
        &self,
        m: MensagemIpc,
        w: &mut W,
    ) -> Result<Option<Exit>, SessionError> {
        let Some(Payload::Comando(cmd)) = m.payload else {
            tracing_log(format_args!("mensagem inesperada do core ignorada"));
            return Ok(None);
        };
        let (result, exit) = self.execute(&cmd).await;
        let reply = self.envelope(Payload::Resposta(RespostaComando {
            id_comando_referencia: cmd.id_comando.clone(),
            sucesso: result.is_ok(),
            mensagem_erro: result.err().unwrap_or_default(),
        }));
        self.send(w, &reply).await?; // o ACK sai antes de qualquer encerramento
        Ok(exit)
    }

    async fn execute(&self, cmd: &ComandoControle) -> (Result<(), String>, Option<Exit>) {
        match TipoAcao::try_from(cmd.acao).unwrap_or(TipoAcao::AcaoDesconhecida) {
            TipoAcao::Pausar => {
                self.ctl.pause();
                (Ok(()), None)
            }
            TipoAcao::Retomar => {
                self.ctl.resume();
                (Ok(()), None)
            }
            TipoAcao::Reconfigurar => {
                let r = match timeout(
                    RECONFIGURE_TIMEOUT,
                    self.ctl.reconfigure(cmd.parametros.clone()),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err("tempo esgotado ao reconfigurar".to_string()),
                };
                (r, None)
            }
            TipoAcao::Encerrar => (Ok(()), Some(Exit::Commanded)),
            TipoAcao::AcaoDesconhecida => (Err("acao desconhecida".to_string()), None),
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Log minimo em stderr (o supervisor do Core captura e registra a saida do filho).
fn tracing_log(args: std::fmt::Arguments<'_>) {
    eprintln!("mod-net-sensor: {args}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::framer::{read_frame, write_frame, write_message};
    use psychoscope_proto::v1::HelloResposta;
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
}
