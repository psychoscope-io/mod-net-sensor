//! Camada 4: UDP.
use super::DecodeError;
use super::reader::Reader;

pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(buf: &[u8]) -> Result<UdpDatagram<'_>, DecodeError> {
    let mut r = Reader::new(buf);
    let src_port = r.u16().ok_or(DecodeError::Truncated)?;
    let dst_port = r.u16().ok_or(DecodeError::Truncated)?;
    let len = usize::from(r.u16().ok_or(DecodeError::Truncated)?);
    r.skip(2).ok_or(DecodeError::Truncated)?; // checksum
    if len < 8 {
        return Err(DecodeError::Malformed);
    }
    let body = r.rest();
    Ok(UdpDatagram {
        src_port,
        dst_port,
        payload: &body[..(len - 8).min(body.len())],
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut p = Vec::new();
        p.extend(sp.to_be_bytes());
        p.extend(dp.to_be_bytes());
        p.extend(len.to_be_bytes());
        p.extend([0, 0]);
        p.extend(payload);
        p
    }

    #[test]
    fn parses() {
        let pkt = udp(5353, 53, b"abc");
        let d = parse_udp(&pkt).unwrap();
        assert_eq!((d.src_port, d.dst_port, d.payload), (5353, 53, &b"abc"[..]));
    }

    #[test]
    fn length_field_limits_payload_and_errors() {
        let mut p = udp(1, 2, b"abcdef");
        p[4..6].copy_from_slice(&10u16.to_be_bytes()); // so 2 bytes de payload validos
        assert_eq!(parse_udp(&p).unwrap().payload, b"ab");
        p[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert!(matches!(parse_udp(&p), Err(DecodeError::Malformed)));
        p[4..6].copy_from_slice(&500u16.to_be_bytes()); // snaplen truncou
        assert_eq!(parse_udp(&p).unwrap().payload, b"abcdef");
        assert!(matches!(parse_udp(&[0; 7]), Err(DecodeError::Truncated)));
    }
}
