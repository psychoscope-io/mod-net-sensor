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
mod tests;
