//! Saida legivel dos eventos (`--print`): uma linha de texto ou um objeto JSON por evento.
//! Dominios e SNI vem da rede (hostil): o texto troca caracteres de controle por `?` para nao
//! mexer no terminal de quem le, e o JSON usa o escape do serde_json.
use psychoscope_proto::v1::{
    EventoFluxoRede, ProtocoloTransporte,
    evento_fluxo_rede::{MetadadosDns, MetadadosL7, MetadadosTls},
};
use serde_json::{Map, Value, json};

const TCP_FLAGS: [(u32, &str); 6] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
];

fn protocol(ev: &EventoFluxoRede) -> &'static str {
    match ProtocoloTransporte::try_from(ev.protocolo) {
        Ok(ProtocoloTransporte::ProtoTcp) => "TCP",
        Ok(ProtocoloTransporte::ProtoUdp) => "UDP",
        Ok(ProtocoloTransporte::ProtoIcmp) => "ICMP",
        _ => "IP",
    }
}

fn tcp_flags(bits: u32) -> Vec<&'static str> {
    TCP_FLAGS
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// Instante em RFC 3339 (UTC, milissegundos), a partir de segundos e nanos da epoca Unix.
pub fn rfc3339(secs: i64, nanos: i32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // dias desde 1970-01-01 -> data civil (algoritmo de Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60,
        (nanos.clamp(0, 999_999_999)) / 1_000_000
    )
}

fn timestamp(ev: &EventoFluxoRede) -> String {
    ev.timestamp_captura
        .as_ref()
        .map_or_else(|| "-".to_string(), |t| rfc3339(t.seconds, t.nanos))
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn endpoint(ip: &str, port: u32, with_port: bool) -> String {
    match (with_port, ip.contains(':')) {
        (false, _) => clean(ip),
        (true, true) => format!("[{}]:{port}", clean(ip)), // IPv6
        (true, false) => format!("{}:{port}", clean(ip)),
    }
}

fn dns_text(d: &MetadadosDns) -> String {
    let kind = if d.eh_resposta {
        "resposta"
    } else {
        "consulta"
    };
    let mut s = format!(
        "DNS {kind} {} tipo {}",
        clean(&d.dominio_consultado),
        d.tipo_registro
    );
    if d.eh_resposta {
        s += &format!(" rcode {}", d.codigo_resposta);
        if !d.respostas_ip.is_empty() {
            s += &format!(
                " -> {}",
                d.respostas_ip
                    .iter()
                    .map(|i| clean(i))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    s
}

fn tls_text(t: &MetadadosTls) -> String {
    let sni = if t.sni_hostname.is_empty() {
        "(sem SNI)".to_string()
    } else {
        clean(&t.sni_hostname)
    };
    format!("TLS ClientHello SNI {sni} versao {}", clean(&t.versao_tls))
}

/// Uma linha de texto: `2026-10-23T22:59:05.123Z UDP 192.168.0.8:51000 -> 192.168.0.1:53 74B DNS ...`.
pub fn render_text(ev: &EventoFluxoRede) -> String {
    let proto = protocol(ev);
    let ports = matches!(proto, "TCP" | "UDP");
    let mut s = format!(
        "{} {proto} {} -> {} {}B",
        timestamp(ev),
        endpoint(&ev.ip_origem, ev.porta_origem, ports),
        endpoint(&ev.ip_destino, ev.porta_destino, ports),
        ev.tamanho_bytes
    );
    if proto == "TCP" {
        let flags = tcp_flags(ev.flags_tcp);
        if !flags.is_empty() {
            s += &format!(" [{}]", flags.join(","));
        }
    }
    if proto == "ICMP" {
        s += &format!(" tipo {} codigo {}", ev.icmp_tipo, ev.icmp_codigo);
    }
    match &ev.metadados_l7 {
        Some(MetadadosL7::Dns(d)) => s += &format!(" {}", dns_text(d)),
        Some(MetadadosL7::Tls(t)) => s += &format!(" {}", tls_text(t)),
        None => {}
    }
    s
}

/// Um objeto JSON (uma linha) com os nomes de campo do contrato.
pub fn render_json(ev: &EventoFluxoRede) -> String {
    let mut o = Map::new();
    o.insert("timestamp_captura".into(), json!(timestamp(ev)));
    o.insert("protocolo".into(), json!(protocol(ev)));
    o.insert("ip_origem".into(), json!(ev.ip_origem));
    o.insert("porta_origem".into(), json!(ev.porta_origem));
    o.insert("ip_destino".into(), json!(ev.ip_destino));
    o.insert("porta_destino".into(), json!(ev.porta_destino));
    o.insert("tamanho_bytes".into(), json!(ev.tamanho_bytes));
    if protocol(ev) == "TCP" {
        o.insert("flags_tcp".into(), json!(tcp_flags(ev.flags_tcp)));
    }
    if protocol(ev) == "ICMP" {
        o.insert("icmp_tipo".into(), json!(ev.icmp_tipo));
        o.insert("icmp_codigo".into(), json!(ev.icmp_codigo));
    }
    match &ev.metadados_l7 {
        Some(MetadadosL7::Dns(d)) => {
            o.insert(
                "dns".into(),
                json!({
                    "dominio_consultado": d.dominio_consultado,
                    "tipo_registro": d.tipo_registro,
                    "eh_resposta": d.eh_resposta,
                    "codigo_resposta": d.codigo_resposta,
                    "respostas_ip": d.respostas_ip,
                }),
            );
        }
        Some(MetadadosL7::Tls(t)) => {
            o.insert(
                "tls".into(),
                json!({"sni_hostname": t.sni_hostname, "versao_tls": t.versao_tls}),
            );
        }
        None => {}
    }
    Value::Object(o).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::Timestamp;

    fn base() -> EventoFluxoRede {
        EventoFluxoRede {
            ip_origem: "192.168.0.8".into(),
            porta_origem: 51000,
            ip_destino: "192.168.0.1".into(),
            porta_destino: 53,
            protocolo: ProtocoloTransporte::ProtoUdp as i32,
            tamanho_bytes: 74,
            timestamp_captura: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_789,
            }),
            ..Default::default()
        }
    }

    fn dns(domain: &str, response: bool) -> EventoFluxoRede {
        EventoFluxoRede {
            metadados_l7: Some(MetadadosL7::Dns(MetadadosDns {
                dominio_consultado: domain.into(),
                tipo_registro: 1,
                respostas_ip: if response {
                    vec!["93.184.216.34".into()]
                } else {
                    vec![]
                },
                codigo_resposta: 0,
                eh_resposta: response,
            })),
            ..base()
        }
    }

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339(1_700_000_000, 123_456_789),
            "2023-11-14T22:13:20.123Z"
        );
        assert_eq!(rfc3339(951_782_400, 0), "2000-02-29T00:00:00.000Z"); // bissexto
        assert_eq!(rfc3339(-1, 999_000_000), "1969-12-31T23:59:59.999Z");
        assert_eq!(
            rfc3339(0, -5),
            "1970-01-01T00:00:00.000Z",
            "nanos invalidos nao quebram"
        );
    }

    #[test]
    fn text_lines_for_each_kind_of_event() {
        assert_eq!(
            render_text(&dns("www.example.com", false)),
            "2023-11-14T22:13:20.123Z UDP 192.168.0.8:51000 -> 192.168.0.1:53 74B DNS consulta www.example.com tipo 1"
        );
        assert!(
            render_text(&dns("a.com", true))
                .ends_with("DNS resposta a.com tipo 1 rcode 0 -> 93.184.216.34")
        );
        let syn = EventoFluxoRede {
            protocolo: ProtocoloTransporte::ProtoTcp as i32,
            flags_tcp: 0x12,
            ip_origem: "fe80::1".into(),
            ..base()
        };
        let t = render_text(&syn);
        assert!(
            t.contains("TCP [fe80::1]:51000 -> 192.168.0.1:53") && t.ends_with("[SYN,ACK]"),
            "{t}"
        );
        let icmp = EventoFluxoRede {
            protocolo: ProtocoloTransporte::ProtoIcmp as i32,
            icmp_tipo: 8,
            ..base()
        };
        assert!(
            render_text(&icmp).ends_with("ICMP 192.168.0.8 -> 192.168.0.1 74B tipo 8 codigo 0")
        );
        let tls = EventoFluxoRede {
            metadados_l7: Some(MetadadosL7::Tls(MetadadosTls {
                sni_hostname: String::new(),
                versao_tls: "TLS1.3".into(),
            })),
            ..base()
        };
        assert!(render_text(&tls).ends_with("TLS ClientHello SNI (sem SNI) versao TLS1.3"));
        assert!(
            render_text(&EventoFluxoRede::default()).starts_with("- IP "),
            "evento vazio nao quebra"
        );
    }

    #[test]
    fn hostile_strings_cannot_reach_the_terminal_or_break_the_json() {
        let ev = dns("evil\x1b[2J\r\nname", false);
        let t = render_text(&ev);
        assert!(
            !t.contains('\x1b') && !t.contains('\n') && !t.contains('\r'),
            "{t:?}"
        );
        let j = render_json(&ev);
        assert!(!j.contains('\n') && j.contains("\\u001b"), "{j}");
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["dns"]["dominio_consultado"], "evil\x1b[2J\r\nname");
    }

    #[test]
    fn json_uses_the_contract_field_names() {
        let v: Value = serde_json::from_str(&render_json(&dns("a.com", true))).unwrap();
        assert_eq!(v["ip_origem"], "192.168.0.8");
        assert_eq!(v["porta_destino"], 53);
        assert_eq!(v["protocolo"], "UDP");
        assert_eq!(v["timestamp_captura"], "2023-11-14T22:13:20.123Z");
        assert_eq!(v["dns"]["respostas_ip"][0], "93.184.216.34");
        assert!(v.get("flags_tcp").is_none() && v.get("icmp_tipo").is_none());
        let syn = EventoFluxoRede {
            protocolo: ProtocoloTransporte::ProtoTcp as i32,
            flags_tcp: 0x02,
            ..base()
        };
        let v: Value = serde_json::from_str(&render_json(&syn)).unwrap();
        assert_eq!(v["flags_tcp"], json!(["SYN"]));
    }
}
