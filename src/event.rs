//! Converte pacotes decodificados em `EventoFluxoRede` (contrato psychoscope.v1).
use std::time::SystemTime;

use prost_types::Timestamp;
use psychoscope_proto::v1::{
    EventoFluxoRede, ProtocoloTransporte,
    evento_fluxo_rede::{MetadadosDns, MetadadosL7, MetadadosTls},
};

use crate::protocols::{
    Packet, Transport,
    dns::{self, DnsInfo},
    tcp, tls,
};

/// Quais pacotes viram evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EmitPolicy {
    /// DNS, TLS ClientHello, TCP com SYN ou RST, e ICMP (suficiente para as regras de DNS e varredura).
    Interesting,
    /// Todo pacote IP decodificavel (alto volume).
    All,
}

const DNS_PORT: u16 = 53;

pub fn to_timestamp(t: SystemTime) -> Timestamp {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Timestamp {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        },
        Err(_) => Timestamp {
            seconds: 0,
            nanos: 0,
        },
    }
}

fn dns_meta(i: DnsInfo) -> MetadadosL7 {
    MetadadosL7::Dns(MetadadosDns {
        dominio_consultado: i.domain,
        tipo_registro: u32::from(i.qtype),
        respostas_ip: i.answers.iter().map(ToString::to_string).collect(),
        codigo_resposta: u32::from(i.rcode),
        eh_resposta: i.is_response,
    })
}

/// DNS sobre TCP: mensagem prefixada por 2 bytes de tamanho; so a primeira mensagem do segmento.
fn dns_over_tcp(payload: &[u8]) -> Option<DnsInfo> {
    let len = usize::from(u16::from_be_bytes([*payload.first()?, *payload.get(1)?]));
    let body = payload.get(2..)?;
    dns::parse_dns(&body[..len.min(body.len())]).ok()
}

/// Monta o evento para `pkt`, ou `None` se a politica o descarta.
/// `wire_len` e o tamanho original do pacote na rede (nao o capturado).
pub fn build_event(
    pkt: &Packet<'_>,
    ts: SystemTime,
    wire_len: u64,
    policy: EmitPolicy,
) -> Option<EventoFluxoRede> {
    let all = policy == EmitPolicy::All;
    let mut ev = EventoFluxoRede {
        ip_origem: pkt.src_ip.to_string(),
        ip_destino: pkt.dst_ip.to_string(),
        tamanho_bytes: wire_len,
        timestamp_captura: Some(to_timestamp(ts)),
        ..Default::default()
    };

    match &pkt.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            flags,
            payload,
        } => {
            ev.protocolo = ProtocoloTransporte::ProtoTcp as i32;
            ev.porta_origem = u32::from(*src_port);
            ev.porta_destino = u32::from(*dst_port);
            ev.flags_tcp = u32::from(*flags);
            if *src_port == DNS_PORT || *dst_port == DNS_PORT {
                ev.metadados_l7 = dns_over_tcp(payload).map(dns_meta);
            }
            if ev.metadados_l7.is_none()
                && let Some(ch) = tls::parse_client_hello(payload)
            {
                ev.metadados_l7 = Some(MetadadosL7::Tls(MetadadosTls {
                    sni_hostname: ch.sni.unwrap_or_default(),
                    versao_tls: ch.version.to_string(),
                }));
            }
            let interesting = ev.metadados_l7.is_some() || flags & (tcp::SYN | tcp::RST) != 0;
            (all || interesting).then_some(ev)
        }
        Transport::Udp {
            src_port,
            dst_port,
            payload,
        } => {
            ev.protocolo = ProtocoloTransporte::ProtoUdp as i32;
            ev.porta_origem = u32::from(*src_port);
            ev.porta_destino = u32::from(*dst_port);
            if *src_port == DNS_PORT || *dst_port == DNS_PORT {
                ev.metadados_l7 = dns::parse_dns(payload).ok().map(dns_meta);
            }
            (all || ev.metadados_l7.is_some()).then_some(ev)
        }
        Transport::Icmp { icmp_type, code } => {
            ev.protocolo = ProtocoloTransporte::ProtoIcmp as i32;
            ev.icmp_tipo = u32::from(*icmp_type);
            ev.icmp_codigo = u32::from(*code);
            Some(ev)
        }
        Transport::Other { .. } => {
            ev.protocolo = ProtocoloTransporte::ProtoDesconhecido as i32;
            all.then_some(ev)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{LinkType, decode_frame, testutil::*};
    use std::time::Duration;

    fn ev(frame: &[u8], policy: EmitPolicy) -> Option<EventoFluxoRede> {
        let pkt = decode_frame(LinkType::Ethernet, frame).unwrap();
        let ts = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123);
        build_event(&pkt, ts, frame.len() as u64, policy)
    }

    #[test]
    fn dns_query_event() {
        let f = eth_v4(17, &udp(50000, 53, &dns_query("Example.com", 28)));
        let e = ev(&f, EmitPolicy::Interesting).unwrap();
        assert_eq!(
            (e.ip_origem.as_str(), e.porta_destino, e.protocolo),
            ("10.0.0.1", 53, ProtocoloTransporte::ProtoUdp as i32)
        );
        assert_eq!(e.tamanho_bytes, f.len() as u64);
        assert_eq!(
            e.timestamp_captura,
            Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123
            })
        );
        let Some(MetadadosL7::Dns(d)) = e.metadados_l7 else {
            panic!("sem dns")
        };
        assert_eq!(
            (
                d.dominio_consultado.as_str(),
                d.tipo_registro,
                d.eh_resposta,
                d.codigo_resposta
            ),
            ("example.com", 28, false, 0)
        );
    }

    #[test]
    fn dns_response_event_has_answers_and_rcode() {
        let ips = ["1.2.3.4".parse().unwrap(), "::1".parse().unwrap()];
        let f = eth_v4(17, &udp(53, 50000, &dns_response("a.com", 1, 0, &ips)));
        let Some(MetadadosL7::Dns(d)) = ev(&f, EmitPolicy::Interesting).unwrap().metadados_l7
        else {
            panic!()
        };
        assert!(d.eh_resposta);
        assert_eq!(d.respostas_ip, vec!["1.2.3.4", "::1"]);
        let f = eth_v4(17, &udp(53, 50000, &dns_response("nx.com", 1, 3, &[])));
        let Some(MetadadosL7::Dns(d)) = ev(&f, EmitPolicy::Interesting).unwrap().metadados_l7
        else {
            panic!()
        };
        assert_eq!(d.codigo_resposta, 3);
    }

    #[test]
    fn dns_over_tcp_event() {
        let q = dns_query("tcp.example", 1);
        let mut payload = (q.len() as u16).to_be_bytes().to_vec();
        payload.extend(&q);
        let f = eth_v4(6, &tcp(40000, 53, tcp::PSH | tcp::ACK, &payload));
        let Some(MetadadosL7::Dns(d)) = ev(&f, EmitPolicy::Interesting).unwrap().metadados_l7
        else {
            panic!()
        };
        assert_eq!(d.dominio_consultado, "tcp.example");
    }

    #[test]
    fn tls_client_hello_event() {
        let f = eth_v4(
            6,
            &tcp(
                40000,
                443,
                tcp::PSH | tcp::ACK,
                &client_hello(Some("secure.example"), &[0x0304]),
            ),
        );
        let e = ev(&f, EmitPolicy::Interesting).unwrap();
        assert_eq!(e.flags_tcp, u32::from(tcp::PSH | tcp::ACK));
        let Some(MetadadosL7::Tls(t)) = e.metadados_l7 else {
            panic!()
        };
        assert_eq!(
            (t.sni_hostname.as_str(), t.versao_tls.as_str()),
            ("secure.example", "TLS1.3")
        );
    }

    #[test]
    fn tcp_policy_filtering() {
        let syn = eth_v4(6, &tcp(1, 80, tcp::SYN, &[]));
        let synack = eth_v4(6, &tcp(80, 1, tcp::SYN | tcp::ACK, &[]));
        let rst = eth_v4(6, &tcp(80, 1, tcp::RST | tcp::ACK, &[]));
        let data = eth_v4(6, &tcp(1, 80, tcp::PSH | tcp::ACK, b"GET /"));
        for f in [&syn, &synack, &rst] {
            assert!(ev(f, EmitPolicy::Interesting).is_some());
        }
        assert!(ev(&data, EmitPolicy::Interesting).is_none());
        assert!(ev(&data, EmitPolicy::All).is_some());
    }

    #[test]
    fn udp_icmp_and_other() {
        let plain = eth_v4(17, &udp(1000, 2000, b"x"));
        assert!(ev(&plain, EmitPolicy::Interesting).is_none());
        assert!(ev(&plain, EmitPolicy::All).is_some());
        let garbage_dns = eth_v4(17, &udp(1000, 53, b"not dns at all"));
        assert!(ev(&garbage_dns, EmitPolicy::Interesting).is_none());

        let icmp = eth_v4(1, &[3, 3, 0, 0]);
        let e = ev(&icmp, EmitPolicy::Interesting).unwrap();
        assert_eq!(
            (e.protocolo, e.icmp_tipo, e.icmp_codigo),
            (ProtocoloTransporte::ProtoIcmp as i32, 3, 3)
        );

        let gre = eth_v4(47, &[0; 8]);
        assert!(ev(&gre, EmitPolicy::Interesting).is_none());
        assert_eq!(
            ev(&gre, EmitPolicy::All).unwrap().protocolo,
            ProtocoloTransporte::ProtoDesconhecido as i32
        );
    }

    #[test]
    fn ipv6_addresses_are_compressed() {
        let f = eth(0x86dd, &v6(58, &[128, 0, 0, 0]));
        let e = ev(&f, EmitPolicy::Interesting).unwrap();
        assert_eq!(
            (e.ip_origem.as_str(), e.ip_destino.as_str()),
            ("fe80::1", "fe80::2")
        );
    }
}
