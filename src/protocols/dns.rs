//! DNS (RFC 1035): primeira pergunta, codigo de resposta e enderecos A/AAAA das respostas.
//! Seguro contra ponteiros de compressao ciclicos e rotulos malformados.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::DecodeError;
use super::reader::Reader;

const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_JUMPS: usize = 16;
const MAX_QUESTIONS: u16 = 16;
const MAX_ANSWERS: u16 = 64;

#[derive(Debug, PartialEq, Eq)]
pub struct DnsInfo {
    pub domain: String,
    pub qtype: u16,
    pub answers: Vec<IpAddr>,
    pub rcode: u8,
    pub is_response: bool,
}

/// Le um nome em `msg` a partir de `start`. Devolve o nome (minusculo, sem ponto final;
/// "." para a raiz) e a posicao logo apos o nome no fluxo original.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut next_after: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    let end = next_after.unwrap_or(pos + 1);
                    if name.is_empty() {
                        name.push('.');
                    }
                    return Some((name, end));
                }
                let l = usize::from(len);
                let label = msg.get(pos + 1..pos + 1 + l)?;
                if !name.is_empty() {
                    name.push('.');
                }
                if name.len() + l > MAX_NAME_LEN {
                    return None;
                }
                for &b in label {
                    name.push(if (0x21..=0x7e).contains(&b) {
                        char::from(b.to_ascii_lowercase())
                    } else {
                        '?'
                    });
                }
                pos += 1 + l;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(lo);
                if next_after.is_none() {
                    next_after = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || target >= msg.len() {
                    return None;
                }
                pos = target;
            }
            _ => return None, // tipos de rotulo 0x40/0x80 sao invalidos/obsoletos
        }
    }
}

pub fn parse_dns(msg: &[u8]) -> Result<DnsInfo, DecodeError> {
    let header = parse_header(msg)?;
    let (domain, qtype, pos) = parse_questions(msg, header.questions)?;
    // Respostas: melhor esforco; truncamento por snaplen devolve o que ja foi lido.
    let answers = if header.is_response {
        parse_answers(msg, pos, header.answers)
    } else {
        Vec::new()
    };
    Ok(DnsInfo {
        domain,
        qtype,
        answers,
        rcode: header.rcode,
        is_response: header.is_response,
    })
}

struct Header {
    is_response: bool,
    rcode: u8,
    questions: u16,
    answers: u16,
}

/// Cabecalho de 12 bytes: exige 1 a MAX_QUESTIONS perguntas.
fn parse_header(msg: &[u8]) -> Result<Header, DecodeError> {
    let mut r = Reader::new(msg);
    r.skip(2).ok_or(DecodeError::Truncated)?; // id
    let flags = r.u16().ok_or(DecodeError::Truncated)?;
    let questions = r.u16().ok_or(DecodeError::Truncated)?;
    let answers = r.u16().ok_or(DecodeError::Truncated)?;
    r.skip(4).ok_or(DecodeError::Truncated)?; // ns + ar
    if questions == 0 || questions > MAX_QUESTIONS {
        return Err(DecodeError::Malformed);
    }
    Ok(Header {
        is_response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        questions,
        answers,
    })
}

/// Percorre as perguntas; devolve nome e tipo da primeira e a posicao logo depois da ultima.
fn parse_questions(msg: &[u8], count: u16) -> Result<(String, u16, usize), DecodeError> {
    let mut pos = 12;
    let mut first = (String::new(), 0);
    for i in 0..count {
        let (name, after) = read_name(msg, pos).ok_or(DecodeError::Malformed)?;
        let mut q = Reader::new(msg.get(after..).ok_or(DecodeError::Truncated)?);
        let qtype = q.u16().ok_or(DecodeError::Truncated)?;
        q.skip(2).ok_or(DecodeError::Truncated)?; // classe
        pos = after + 4;
        if i == 0 {
            first = (name, qtype);
        }
    }
    Ok((first.0, first.1, pos))
}

/// Enderecos A/AAAA das respostas, ate MAX_ANSWERS; para ao primeiro registro ilegivel.
fn parse_answers(msg: &[u8], mut pos: usize, count: u16) -> Vec<IpAddr> {
    let mut answers = Vec::new();
    for _ in 0..count.min(MAX_ANSWERS) {
        let Some((_, after)) = read_name(msg, pos) else {
            break;
        };
        let mut a = Reader::new(msg.get(after..).unwrap_or(&[]));
        let (Some(t), Some(_class), Some(_ttl), Some(rdlen)) = (a.u16(), a.u16(), a.u32(), a.u16())
        else {
            break;
        };
        let Some(rdata) = a.take(usize::from(rdlen)) else {
            break;
        };
        pos = after + 10 + usize::from(rdlen);
        if let Some(ip) = address_from_rdata(t, rdata) {
            answers.push(ip);
        }
    }
    answers
}

/// A (tipo 1, 4 bytes) ou AAAA (tipo 28, 16 bytes); outros tipos nao interessam.
fn address_from_rdata(rtype: u16, rdata: &[u8]) -> Option<IpAddr> {
    match (rtype, rdata.len()) {
        (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
            rdata[0], rdata[1], rdata[2], rdata[3],
        ))),
        (28, 16) => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|o| IpAddr::V6(Ipv6Addr::from(o))),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn enc_name(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in name.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v
    }

    pub fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(enc_name(name));
        m.extend(qtype.to_be_bytes());
        m.extend([0, 1]);
        m
    }

    /// Resposta com ponteiro de compressao para a pergunta (0xC00C).
    pub fn response(name: &str, qtype: u16, rcode: u8, ips: &[IpAddr]) -> Vec<u8> {
        let mut m = vec![
            0x12,
            0x34,
            0x81,
            0x80 | rcode,
            0,
            1,
            0,
            ips.len() as u8,
            0,
            0,
            0,
            0,
        ];
        m.extend(enc_name(name));
        m.extend(qtype.to_be_bytes());
        m.extend([0, 1]);
        for ip in ips {
            m.extend([0xc0, 0x0c]);
            match ip {
                IpAddr::V4(a) => {
                    m.extend([0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    m.extend(a.octets());
                }
                IpAddr::V6(a) => {
                    m.extend([0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                    m.extend(a.octets());
                }
            }
        }
        m
    }

    #[test]
    fn query_parses() {
        let i = parse_dns(&query("Example.COM", 1)).unwrap();
        assert_eq!(
            i,
            DnsInfo {
                domain: "example.com".into(),
                qtype: 1,
                answers: vec![],
                rcode: 0,
                is_response: false
            }
        );
    }

    #[test]
    fn response_with_compression_and_both_families() {
        let ips: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "2606:2800:220:1::1".parse().unwrap(),
        ];
        let i = parse_dns(&response("example.com", 1, 0, &ips)).unwrap();
        assert!(i.is_response);
        assert_eq!(i.answers, ips);
        assert_eq!(i.domain, "example.com");
    }

    #[test]
    fn nxdomain_rcode() {
        let i = parse_dns(&response("nope.invalid", 1, 3, &[])).unwrap();
        assert_eq!((i.rcode, i.is_response, i.answers.len()), (3, true, 0));
    }

    #[test]
    fn root_name() {
        assert_eq!(parse_dns(&query("", 2)).unwrap().domain, ".");
    }

    #[test]
    fn rejects_malformed() {
        assert!(matches!(parse_dns(&[0; 11]), Err(DecodeError::Truncated)));
        let mut q = query("a.com", 1);
        q[4..6].copy_from_slice(&0u16.to_be_bytes()); // qdcount 0
        assert!(matches!(parse_dns(&q), Err(DecodeError::Malformed)));
        q[4..6].copy_from_slice(&1000u16.to_be_bytes());
        assert!(matches!(parse_dns(&q), Err(DecodeError::Malformed)));

        // ponteiro apontando para si mesmo (ciclo)
        let mut m = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xc0, 12, 0, 1, 0, 1]);
        assert!(matches!(parse_dns(&m), Err(DecodeError::Malformed)));
        // ponteiro para fora da mensagem
        let mut m = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xc3, 0xff, 0, 1, 0, 1]);
        assert!(matches!(parse_dns(&m), Err(DecodeError::Malformed)));
        // tipo de rotulo invalido (0x40)
        let mut m = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0x41, b'a', 0, 0, 1, 0, 1]);
        assert!(matches!(parse_dns(&m), Err(DecodeError::Malformed)));
        // rotulo maior que o buffer
        let mut m = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([30, b'a']);
        assert!(matches!(parse_dns(&m), Err(DecodeError::Malformed)));
        // pergunta sem qtype/qclass
        let mut m = query("a.com", 1);
        m.truncate(m.len() - 3);
        assert!(matches!(parse_dns(&m), Err(DecodeError::Truncated)));
    }

    #[test]
    fn name_too_long_is_rejected() {
        let label = "a".repeat(63);
        let name = format!("{label}.{label}.{label}.{label}.{label}");
        assert!(matches!(
            parse_dns(&query(&name, 1)),
            Err(DecodeError::Malformed)
        ));
    }

    #[test]
    fn truncated_answers_keep_what_was_read() {
        let ips: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()];
        let mut m = response("a.com", 1, 0, &ips);
        m.truncate(m.len() - 3); // corta o segundo rdata
        let i = parse_dns(&m).unwrap();
        assert_eq!(i.answers, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn non_printable_bytes_are_sanitized() {
        let mut m = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([3, 0x01, b'A', 0xff, 0, 0, 1, 0, 1]);
        assert_eq!(parse_dns(&m).unwrap().domain, "?a?");
    }
}
