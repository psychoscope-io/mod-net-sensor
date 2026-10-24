//! Remontagem de ClientHello TLS que ocupa varios segmentos TCP.
//!
//! Clientes com chave pos-quantica passam de 1,4 KB, e o SNI pode cair no segundo segmento.
//! A tabela e deliberadamente minima: so guarda estado para fluxos cujo primeiro segmento com
//! payload comeca com um registro de handshake (`0x16 0x03`, ClientHello) que declara mais
//! bytes do que o segmento traz. Qualquer outro trafego passa sem alocar nada.
//!
//! Politica estrita (o sensor e passivo e nao ve o mesmo que o receptor): so aceita o segmento
//! com o `seq` esperado; lacuna, retransmissao, sobreposicao, RST ou captura truncada
//! descartam o fluxo. Limites: `MAX_RECORD_BYTES` por fluxo, `MAX_FLOWS` fluxos (despeja o
//! mais antigo) e `TTL` medido no tempo dos pacotes, nao no relogio do sistema.
//! Sem `unsafe`; nenhuma entrada causa panico.
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Duration;

use crate::protocols::tcp::RST;

/// Teto de bytes bufferizados por fluxo (registro TLS: 5 + ate 16384 + folga).
pub const MAX_RECORD_BYTES: usize = 18 * 1024;
/// Teto de fluxos simultaneos em remontagem.
pub const MAX_FLOWS: usize = 4096;
/// Tempo maximo para o registro completar, contado desde o primeiro segmento.
pub const TTL: Duration = Duration::from_secs(5);

const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 1;

/// Fluxo direcional (cliente -> servidor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// Um segmento TCP visto na captura.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
    /// O snaplen cortou o pacote: o payload capturado e menor que o real.
    pub truncated: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// O segmento nao participa de remontagem: analise o payload original.
    Passthrough,
    /// Fragmento retido: ainda nao ha registro completo para analisar.
    Pending,
    /// Registro TLS completo (cabecalho + corpo, sem bytes alem dele).
    Complete(Vec<u8>),
}

struct Flow {
    buf: Vec<u8>,
    /// Tamanho total do registro (cabecalho + corpo).
    total: usize,
    next_seq: u32,
    /// Instante do primeiro segmento; tambem ordena o indice de despejo.
    started: (Duration, u64),
}

#[derive(Default)]
pub struct Reassembler {
    flows: HashMap<FlowKey, Flow>,
    /// Do mais antigo ao mais novo: despejo e expiracao saem do inicio.
    by_age: BTreeMap<(Duration, u64), FlowKey>,
    serial: u64,
    /// Fluxos descartados sem completar (lacuna, RST, truncamento, despejo ou validade).
    discarded: u64,
}

/// Tamanho total do registro se `payload` abre um ClientHello que nao cabe nele.
fn incomplete_client_hello(payload: &[u8]) -> Option<usize> {
    let hdr = payload.get(..=RECORD_HEADER)?; // 5 do registro + tipo do handshake
    if hdr[0] != CONTENT_HANDSHAKE || hdr[1] != 3 || hdr[5] != HS_CLIENT_HELLO {
        return None;
    }
    let total = RECORD_HEADER + usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    (total > payload.len() && total <= MAX_RECORD_BYTES).then_some(total)
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fluxos em remontagem agora.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Fluxos descartados sem completar desde a criacao: mede quantos ClientHellos
    /// fragmentados o sensor deixou de analisar.
    pub fn discarded(&self) -> u64 {
        self.discarded
    }

    /// Total de bytes retidos nos buffers.
    pub fn buffered_bytes(&self) -> usize {
        self.flows.values().map(|f| f.buf.len()).sum()
    }

    /// Processa um segmento. `now` e o instante do pacote (desde a epoca Unix).
    pub fn feed(&mut self, now: Duration, key: FlowKey, seg: Segment<'_>) -> Outcome {
        self.expire(now);

        if seg.flags & RST != 0 || seg.truncated {
            self.discard(&key);
            return Outcome::Passthrough;
        }
        if seg.payload.is_empty() {
            return Outcome::Passthrough; // ACK puro: nao muda o estado
        }

        let Some(flow) = self.flows.get_mut(&key) else {
            return self.start(now, key, seg);
        };

        if seg.seq != flow.next_seq {
            // lacuna, retransmissao ou sobreposicao: o fluxo nao e confiavel
            self.discard(&key);
            return Outcome::Passthrough;
        }
        let take = seg.payload.len().min(flow.total - flow.buf.len());
        flow.buf.extend_from_slice(&seg.payload[..take]);
        flow.next_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
        if flow.buf.len() < flow.total {
            return Outcome::Pending;
        }
        match self.remove(&key) {
            Some(done) => Outcome::Complete(done.buf),
            None => Outcome::Passthrough,
        }
    }

    fn start(&mut self, now: Duration, key: FlowKey, seg: Segment<'_>) -> Outcome {
        let Some(total) = incomplete_client_hello(seg.payload) else {
            return Outcome::Passthrough;
        };
        while self.flows.len() >= MAX_FLOWS {
            let Some((_, oldest)) = self.by_age.pop_first() else {
                break;
            };
            self.flows.remove(&oldest);
            self.discarded += 1;
        }
        self.serial = self.serial.wrapping_add(1);
        let started = (now, self.serial);
        self.by_age.insert(started, key);
        self.flows.insert(
            key,
            Flow {
                buf: seg.payload.to_vec(),
                total,
                next_seq: seg.seq.wrapping_add(seg.payload.len() as u32),
                started,
            },
        );
        Outcome::Pending
    }

    /// Remove o fluxo por ser inutilizavel e o conta como descartado (se existia).
    fn discard(&mut self, key: &FlowKey) {
        if self.remove(key).is_some() {
            self.discarded += 1;
        }
    }

    fn remove(&mut self, key: &FlowKey) -> Option<Flow> {
        let flow = self.flows.remove(key)?;
        self.by_age.remove(&flow.started);
        Some(flow)
    }

    /// Descarta fluxos que passaram de `TTL`. O relogio dos pacotes pode andar para tras
    /// (pcap fora de ordem): nesse caso nada expira.
    fn expire(&mut self, now: Duration) {
        while let Some(entry) = self.by_age.first_entry() {
            if now.saturating_sub(entry.key().0) <= TTL {
                break;
            }
            let key = entry.remove();
            self.flows.remove(&key);
            self.discarded += 1;
        }
    }
}

#[cfg(test)]
mod tests;
