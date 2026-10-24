//! Camada 2: Ethernet II (com ate 2 tags VLAN 802.1Q/802.1ad) e Linux cooked (SLL v1 e v2).
use super::DecodeError;
use super::reader::Reader;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88a8, 0x9100];
const MAX_VLAN_TAGS: usize = 2;

/// Devolve `(ethertype, payload)` de um frame Ethernet II.
pub fn parse_ethernet(frame: &[u8]) -> Result<(u16, &[u8]), DecodeError> {
    let mut r = Reader::new(frame);
    r.skip(12).ok_or(DecodeError::Truncated)?; // MAC destino + origem
    let mut ethertype = r.u16().ok_or(DecodeError::Truncated)?;
    let mut tags = 0;
    while VLAN_TPIDS.contains(&ethertype) {
        if tags == MAX_VLAN_TAGS {
            return Err(DecodeError::Unsupported);
        }
        r.skip(2).ok_or(DecodeError::Truncated)?; // TCI
        ethertype = r.u16().ok_or(DecodeError::Truncated)?;
        tags += 1;
    }
    Ok((ethertype, r.rest()))
}

/// Devolve `(ethertype, payload)` de um frame Linux cooked capture v1 (DLT_LINUX_SLL).
pub fn parse_linux_sll(frame: &[u8]) -> Result<(u16, &[u8]), DecodeError> {
    let mut r = Reader::new(frame);
    r.skip(14).ok_or(DecodeError::Truncated)?; // tipo, ARPHRD, tam. endereco, endereco(8)
    let ethertype = r.u16().ok_or(DecodeError::Truncated)?;
    Ok((ethertype, r.rest()))
}

/// Devolve `(ethertype, payload)` de um frame Linux cooked capture v2 (DLT_LINUX_SLL2), o
/// formato que o libpcap recente usa por padrao em `-i any`. O protocolo vem primeiro, e o
/// cabecalho tem 20 bytes: protocolo(2), reservado(2), indice da interface(4), ARPHRD(2),
/// tipo do pacote(1), tam. endereco(1) e endereco(8).
pub fn parse_linux_sll2(frame: &[u8]) -> Result<(u16, &[u8]), DecodeError> {
    let mut r = Reader::new(frame);
    let ethertype = r.u16().ok_or(DecodeError::Truncated)?;
    r.skip(18).ok_or(DecodeError::Truncated)?;
    Ok((ethertype, r.rest()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0xaa; 6];
        f.extend([0xbb; 6]);
        f.extend(ethertype);
        f.extend(payload);
        f
    }

    #[test]
    fn plain_and_vlan() {
        let f = eth(&[0x08, 0x00], &[1, 2, 3]);
        assert_eq!(
            parse_ethernet(&f).unwrap(),
            (ETHERTYPE_IPV4, &[1u8, 2, 3][..])
        );

        let f = eth(&[0x81, 0x00], &[0x00, 0x64, 0x86, 0xdd, 9]);
        assert_eq!(parse_ethernet(&f).unwrap(), (ETHERTYPE_IPV6, &[9u8][..]));

        // QinQ (2 tags) ok, 3 tags recusado
        let f = eth(&[0x88, 0xa8], &[0, 1, 0x81, 0x00, 0, 2, 0x08, 0x00, 7]);
        assert_eq!(parse_ethernet(&f).unwrap().0, ETHERTYPE_IPV4);
        let f = eth(
            &[0x88, 0xa8],
            &[0, 1, 0x81, 0x00, 0, 2, 0x81, 0x00, 0, 3, 0x08, 0x00],
        );
        assert!(matches!(parse_ethernet(&f), Err(DecodeError::Unsupported)));
    }

    #[test]
    fn truncated() {
        assert!(matches!(
            parse_ethernet(&[0; 13]),
            Err(DecodeError::Truncated)
        ));
        let f = eth(&[0x81, 0x00], &[0x00]);
        assert!(matches!(parse_ethernet(&f), Err(DecodeError::Truncated)));
        assert!(matches!(
            parse_linux_sll(&[0; 15]),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn sll() {
        let mut f = vec![0; 14];
        f.extend([0x08, 0x00, 5, 6]);
        assert_eq!(
            parse_linux_sll(&f).unwrap(),
            (ETHERTYPE_IPV4, &[5u8, 6][..])
        );
    }

    #[test]
    fn sll2() {
        let mut f = vec![0x86, 0xdd];
        f.extend([0; 18]);
        f.extend([7, 8]);
        assert_eq!(
            parse_linux_sll2(&f).unwrap(),
            (ETHERTYPE_IPV6, &[7u8, 8][..])
        );
        // sem payload e valido (cabecalho completo); truncar o cabecalho nao
        assert_eq!(parse_linux_sll2(&f[..20]).unwrap().1, &[] as &[u8]);
        assert!(matches!(
            parse_linux_sll2(&f[..19]),
            Err(DecodeError::Truncated)
        ));
        assert!(matches!(parse_linux_sll2(&[]), Err(DecodeError::Truncated)));
    }
}
