//! Camada 3: IPv4 e IPv6 (com cabecalhos de extensao comuns).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::DecodeError;
use super::reader::Reader;

pub struct IpHeader<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Protocolo de camada 4 (IPv4 `protocol` / IPv6 `next header` final).
    pub proto: u8,
    /// Carga util da camada 4 (vazia em fragmentos nao-iniciais).
    pub payload: &'a [u8],
    /// true quando este e um fragmento com offset > 0 (sem cabecalho L4).
    pub non_first_fragment: bool,
}

pub fn parse_ipv4(buf: &[u8]) -> Result<IpHeader<'_>, DecodeError> {
    let mut r = Reader::new(buf);
    let vihl = r.u8().ok_or(DecodeError::Truncated)?;
    if vihl >> 4 != 4 {
        return Err(DecodeError::Malformed);
    }
    let ihl = usize::from(vihl & 0x0f) * 4;
    if ihl < 20 {
        return Err(DecodeError::Malformed);
    }
    r.skip(1).ok_or(DecodeError::Truncated)?; // TOS
    let total_len = usize::from(r.u16().ok_or(DecodeError::Truncated)?);
    r.skip(2).ok_or(DecodeError::Truncated)?; // identificacao
    let frag = r.u16().ok_or(DecodeError::Truncated)?;
    r.skip(1).ok_or(DecodeError::Truncated)?; // TTL
    let proto = r.u8().ok_or(DecodeError::Truncated)?;
    r.skip(2).ok_or(DecodeError::Truncated)?; // checksum
    let src = r.take(4).ok_or(DecodeError::Truncated)?;
    let dst = r.take(4).ok_or(DecodeError::Truncated)?;
    if buf.len() < ihl || total_len < ihl {
        return Err(DecodeError::Truncated);
    }
    // total_len maior que o capturado = snaplen truncou; usa o que existe.
    let end = total_len.min(buf.len());
    let non_first_fragment = frag & 0x1fff != 0;
    Ok(IpHeader {
        src: IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
        dst: IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
        proto,
        payload: if non_first_fragment {
            &[]
        } else {
            &buf[ihl..end]
        },
        non_first_fragment,
    })
}

const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_AUTH: u8 = 51;
const EXT_DEST_OPTS: u8 = 60;
const MAX_EXT_HEADERS: usize = 8;

pub fn parse_ipv6(buf: &[u8]) -> Result<IpHeader<'_>, DecodeError> {
    let mut r = Reader::new(buf);
    let first = r.u32().ok_or(DecodeError::Truncated)?;
    if first >> 28 != 6 {
        return Err(DecodeError::Malformed);
    }
    let payload_len = usize::from(r.u16().ok_or(DecodeError::Truncated)?);
    let next = r.u8().ok_or(DecodeError::Truncated)?;
    r.skip(1).ok_or(DecodeError::Truncated)?; // hop limit
    let src = take_addr(&mut r)?;
    let dst = take_addr(&mut r)?;

    let body = r.rest();
    let mut br = Reader::new(&body[..payload_len.min(body.len())]);
    let (proto, non_first_fragment) = skip_extension_headers(&mut br, next)?;
    Ok(IpHeader {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        proto,
        payload: if non_first_fragment { &[] } else { br.rest() },
        non_first_fragment,
    })
}

fn take_addr(r: &mut Reader<'_>) -> Result<[u8; 16], DecodeError> {
    let bytes = r.take(16).ok_or(DecodeError::Truncated)?;
    Ok(<[u8; 16]>::try_from(bytes).expect("take(16) devolve 16 bytes"))
}

/// Pula os cabecalhos de extensao conhecidos (ate MAX_EXT_HEADERS) e devolve o protocolo
/// final e se este e um fragmento nao inicial (sem cabecalho L4).
fn skip_extension_headers(br: &mut Reader<'_>, mut next: u8) -> Result<(u8, bool), DecodeError> {
    for _ in 0..MAX_EXT_HEADERS {
        match next {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTS | EXT_AUTH => {
                let nh = br.u8().ok_or(DecodeError::Truncated)?;
                let len = usize::from(br.u8().ok_or(DecodeError::Truncated)?);
                let total = if next == EXT_AUTH {
                    (len + 2) * 4
                } else {
                    (len + 1) * 8
                };
                br.skip(total - 2).ok_or(DecodeError::Truncated)?;
                next = nh;
            }
            EXT_FRAGMENT => {
                let nh = br.u8().ok_or(DecodeError::Truncated)?;
                br.skip(1).ok_or(DecodeError::Truncated)?;
                let off = br.u16().ok_or(DecodeError::Truncated)?;
                br.skip(4).ok_or(DecodeError::Truncated)?; // identificacao
                next = nh;
                if off >> 3 != 0 {
                    return Ok((next, true));
                }
            }
            _ => break,
        }
    }
    Ok((next, false))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn v4(proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0,
            0,
            64,
            proto,
            0,
            0,
        ];
        p.extend([10, 0, 0, 1]);
        p.extend([10, 0, 0, 2]);
        p.extend(payload);
        p
    }

    #[test]
    fn ipv4_basic() {
        let p = v4(6, &[1, 2, 3, 4]);
        let h = parse_ipv4(&p).unwrap();
        assert_eq!(h.src.to_string(), "10.0.0.1");
        assert_eq!(h.dst.to_string(), "10.0.0.2");
        assert_eq!((h.proto, h.payload), (6, &[1u8, 2, 3, 4][..]));
    }

    #[test]
    fn ipv4_options_trailer_and_snaplen() {
        // IHL=6 (4 bytes de opcoes)
        let mut p = v4(17, &[0; 4]);
        p[0] = 0x46;
        p.splice(20..20, [0, 0, 0, 0]);
        let total = (p.len()) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        assert_eq!(parse_ipv4(&p).unwrap().payload.len(), 4);

        // padding Ethernet apos total_len e ignorado
        let mut p = v4(17, &[1, 2]);
        p.extend([0xee; 10]);
        assert_eq!(parse_ipv4(&p).unwrap().payload, &[1, 2]);

        // snaplen truncou: total_len > capturado
        let mut p = v4(17, &[0; 100]);
        p.truncate(30);
        assert_eq!(parse_ipv4(&p).unwrap().payload.len(), 10);
    }

    #[test]
    fn ipv4_invalid() {
        assert!(matches!(parse_ipv4(&[]), Err(DecodeError::Truncated)));
        let mut p = v4(6, &[]);
        p[0] = 0x65;
        assert!(matches!(parse_ipv4(&p), Err(DecodeError::Malformed)));
        p[0] = 0x44; // IHL 4 < 5
        assert!(matches!(parse_ipv4(&p), Err(DecodeError::Malformed)));
        let mut p = v4(6, &[]);
        p[2..4].copy_from_slice(&10u16.to_be_bytes()); // total_len < IHL
        assert!(matches!(parse_ipv4(&p), Err(DecodeError::Truncated)));
    }

    #[test]
    fn ipv4_fragments() {
        let mut p = v4(17, &[1, 2, 3, 4]);
        p[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF, offset 0: primeiro fragmento
        let h = parse_ipv4(&p).unwrap();
        assert!(!h.non_first_fragment && h.payload.len() == 4);
        p[6..8].copy_from_slice(&0x0010u16.to_be_bytes()); // offset 16
        let h = parse_ipv4(&p).unwrap();
        assert!(h.non_first_fragment && h.payload.is_empty());
    }

    pub fn v6(next: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x60,
            0,
            0,
            0,
            (body.len() >> 8) as u8,
            body.len() as u8,
            next,
            64,
        ];
        p.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend(body);
        p
    }

    #[test]
    fn ipv6_with_extension_headers() {
        let pkt = v6(6, &[9, 9]);
        let h = parse_ipv6(&pkt).unwrap();
        assert_eq!(h.src.to_string(), "fe80::1");
        assert_eq!((h.proto, h.payload), (6, &[9u8, 9][..]));

        // hop-by-hop (8 bytes) -> destination options (8) -> UDP
        let mut body = vec![60, 0, 0, 0, 0, 0, 0, 0];
        body.extend([17, 0, 0, 0, 0, 0, 0, 0]);
        body.extend([7, 7, 7]);
        let pkt = v6(0, &body);
        let h = parse_ipv6(&pkt).unwrap();
        assert_eq!((h.proto, h.payload), (17, &[7u8, 7, 7][..]));

        // fragmento nao-inicial
        let body = [17, 0, 0x00, 0x08, 0, 0, 0, 1, 5, 5];
        let pkt = v6(44, &body);
        let h = parse_ipv6(&pkt).unwrap();
        assert!(h.non_first_fragment && h.payload.is_empty());
    }

    #[test]
    fn ipv6_invalid_and_loop_bounded() {
        assert!(matches!(
            parse_ipv6(&[0x40; 40]),
            Err(DecodeError::Malformed)
        ));
        assert!(matches!(
            parse_ipv6(&[0x60; 10]),
            Err(DecodeError::Truncated)
        ));
        // cabecalho de extensao anunciando mais bytes do que existem
        let body = [60, 200, 0, 0];
        assert!(matches!(
            parse_ipv6(&v6(0, &body)),
            Err(DecodeError::Truncated)
        ));
        // cadeia longa de extensoes termina (limite de 8) sem panico
        let body: Vec<u8> = (0..64).flat_map(|_| [0u8, 0, 0, 0, 0, 0, 0, 0]).collect();
        let _ = parse_ipv6(&v6(0, &body));
    }
}
