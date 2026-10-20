//! Camada 4: ICMP (v4) e ICMPv6 — apenas tipo e codigo.
use super::DecodeError;
use super::reader::Reader;

pub fn parse_icmp(buf: &[u8]) -> Result<(u8, u8), DecodeError> {
    let mut r = Reader::new(buf);
    let typ = r.u8().ok_or(DecodeError::Truncated)?;
    let code = r.u8().ok_or(DecodeError::Truncated)?;
    Ok((typ, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_and_code() {
        assert_eq!(parse_icmp(&[3, 3, 0, 0]).unwrap(), (3, 3));
        assert!(matches!(parse_icmp(&[8]), Err(DecodeError::Truncated)));
    }
}
