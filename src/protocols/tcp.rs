//! Camada 4: TCP.
use super::DecodeError;
use super::reader::Reader;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    /// Numero de sequencia do primeiro byte do payload (SYN consome um numero extra, nao tratado aqui).
    pub seq: u32,
    /// Bitmask FIN/SYN/RST/PSH/ACK/URG (contrato do `flags_tcp`).
    pub flags: u8,
    pub payload: &'a [u8],
}

pub fn parse_tcp(buf: &[u8]) -> Result<TcpSegment<'_>, DecodeError> {
    let mut r = Reader::new(buf);
    let src_port = r.u16().ok_or(DecodeError::Truncated)?;
    let dst_port = r.u16().ok_or(DecodeError::Truncated)?;
    let seq = r.u32().ok_or(DecodeError::Truncated)?;
    r.skip(4).ok_or(DecodeError::Truncated)?; // ack
    let off_flags = r.u16().ok_or(DecodeError::Truncated)?;
    let hdr_len = usize::from(off_flags >> 12) * 4;
    if hdr_len < 20 {
        return Err(DecodeError::Malformed);
    }
    if hdr_len > buf.len() {
        return Err(DecodeError::Truncated);
    }
    Ok(TcpSegment {
        src_port,
        dst_port,
        seq,
        flags: (off_flags & 0x3f) as u8,
        payload: &buf[hdr_len..],
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn tcp(sp: u16, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        tcp_seq(sp, dp, 0, flags, payload)
    }

    pub fn tcp_seq(sp: u16, dp: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend(sp.to_be_bytes());
        p.extend(dp.to_be_bytes());
        p.extend(seq.to_be_bytes());
        p.extend([0; 4]);
        p.extend([0x50, flags]);
        p.extend([0xff, 0xff, 0, 0, 0, 0]);
        p.extend(payload);
        p
    }

    #[test]
    fn parses_ports_flags_payload() {
        let pkt = tcp(40000, 443, SYN | ACK, b"hi");
        let s = parse_tcp(&pkt).unwrap();
        assert_eq!(
            (s.src_port, s.dst_port, s.flags, s.payload),
            (40000, 443, SYN | ACK, &b"hi"[..])
        );
    }

    #[test]
    fn exposes_sequence_number_and_ignores_ack_number() {
        let mut p = tcp_seq(1, 2, 0xdead_beef, ACK, b"x");
        assert_eq!(parse_tcp(&p).unwrap().seq, 0xdead_beef);
        p[8..12].copy_from_slice(&[0xff; 4]); // ack nao influencia
        assert_eq!(parse_tcp(&p).unwrap().seq, 0xdead_beef);
        assert_eq!(parse_tcp(&tcp(1, 2, 0, &[])).unwrap().seq, 0);
        // truncado dentro do campo seq
        assert!(matches!(parse_tcp(&p[..6]), Err(DecodeError::Truncated)));
    }

    #[test]
    fn ece_cwr_bits_are_not_exposed() {
        let mut p = tcp(1, 2, 0, &[]);
        p[13] = 0xc2; // CWR|ECE|SYN
        assert_eq!(parse_tcp(&p).unwrap().flags, SYN);
    }

    #[test]
    fn options_are_skipped_and_errors_reported() {
        let mut p = tcp(1, 2, SYN, &[]);
        p[12] = 0x60; // 24 bytes
        p.extend([1, 1, 1, 1]);
        p.extend(b"x");
        assert_eq!(parse_tcp(&p).unwrap().payload, b"x");
        let mut short = [0u8; 19];
        short[12] = 0x50;
        assert!(matches!(parse_tcp(&short), Err(DecodeError::Truncated)));
        assert!(matches!(parse_tcp(&[0; 5]), Err(DecodeError::Truncated)));
        let mut bad = tcp(1, 2, 0, &[]);
        bad[12] = 0x40; // offset 16 < 20
        assert!(matches!(parse_tcp(&bad), Err(DecodeError::Malformed)));
        let mut big = tcp(1, 2, 0, &[]);
        big[12] = 0xf0; // 60 bytes > capturado
        assert!(matches!(parse_tcp(&big), Err(DecodeError::Truncated)));
    }
}
