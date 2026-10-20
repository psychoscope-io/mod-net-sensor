//! TLS ClientHello: SNI e versao. Apenas ClientHello contido em um unico registro/segmento;
//! mensagens fragmentadas em varios registros nao sao reconstruidas.
use super::reader::Reader;

const CONTENT_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub sni: Option<String>,
    pub version: &'static str,
}

fn version_name(v: u16) -> &'static str {
    match v {
        0x0304 => "TLS1.3",
        0x0303 => "TLS1.2",
        0x0302 => "TLS1.1",
        0x0301 => "TLS1.0",
        0x0300 => "SSL3.0",
        _ => "DESCONHECIDA",
    }
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn valid_hostname(h: &[u8]) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Devolve `Some` somente se `payload` comeca com um registro de handshake contendo um ClientHello.
pub fn parse_client_hello(payload: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(payload);
    if r.u8()? != CONTENT_HANDSHAKE || r.u8()? != 3 {
        return None;
    }
    let _record_minor = r.u8()?;
    let record_len = usize::from(r.u16()?);
    // O registro pode ter sido truncado pelo snaplen: limita ao que foi capturado.
    let rest = r.rest();
    let mut h = Reader::new(&rest[..record_len.min(rest.len())]);

    if h.u8()? != HS_CLIENT_HELLO {
        return None;
    }
    h.u24()?; // tamanho do handshake
    let legacy = h.u16()?;
    if legacy >> 8 != 3 {
        return None;
    }
    let mut version = version_name(legacy);
    h.skip(32)?; // random
    let sid = usize::from(h.u8()?);
    h.skip(sid)?;
    let cs = usize::from(h.u16()?);
    h.skip(cs)?;
    let comp = usize::from(h.u8()?);
    h.skip(comp)?;

    let mut out = ClientHello { sni: None, version };
    let Some(ext_total) = h.u16() else {
        return Some(out);
    };
    let ext_buf = h.rest();
    let mut e = Reader::new(&ext_buf[..usize::from(ext_total).min(ext_buf.len())]);

    // Extensoes: melhor esforco ate o fim dos dados capturados.
    while let (Some(t), Some(l)) = (e.u16(), e.u16()) {
        let Some(body) = e.take(usize::from(l)) else {
            break;
        };
        let mut b = Reader::new(body);
        match t {
            EXT_SERVER_NAME => {
                let _ = (|| -> Option<()> {
                    b.u16()?; // tamanho da lista
                    while let (Some(nt), Some(nl)) = (b.u8(), b.u16()) {
                        let name = b.take(usize::from(nl))?;
                        if nt == 0 {
                            if valid_hostname(name) {
                                out.sni = Some(String::from_utf8_lossy(name).to_ascii_lowercase());
                            }
                            return Some(());
                        }
                    }
                    Some(())
                })();
            }
            EXT_SUPPORTED_VERSIONS => {
                let _ = (|| -> Option<()> {
                    let n = usize::from(b.u8()?);
                    let list = b.take(n)?;
                    let best = list
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_be_bytes(*c))
                        .filter(|v| !is_grease(*v))
                        .max()?;
                    version = version_name(best);
                    Some(())
                })();
            }
            _ => {}
        }
    }
    out.version = version;
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend((body.len() as u16).to_be_bytes());
        v.extend(body);
        v
    }

    pub fn client_hello(sni: Option<&str>, versions: &[u16]) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(s) = sni {
            let mut b = Vec::new();
            b.extend(((s.len() + 3) as u16).to_be_bytes());
            b.push(0);
            b.extend((s.len() as u16).to_be_bytes());
            b.extend(s.as_bytes());
            exts.extend(ext(EXT_SERVER_NAME, &b));
        }
        if !versions.is_empty() {
            let mut b = vec![(versions.len() * 2) as u8];
            for v in versions {
                b.extend(v.to_be_bytes());
            }
            exts.extend(ext(EXT_SUPPORTED_VERSIONS, &b));
        }
        let mut ch = vec![0x03, 0x03];
        ch.extend([7u8; 32]);
        ch.push(0); // session id
        ch.extend([0, 4, 0x13, 0x01, 0x13, 0x02]);
        ch.extend([1, 0]);
        ch.extend((exts.len() as u16).to_be_bytes());
        ch.extend(&exts);
        let mut hs = vec![HS_CLIENT_HELLO];
        hs.extend(&(ch.len() as u32).to_be_bytes()[1..]);
        hs.extend(&ch);
        let mut rec = vec![CONTENT_HANDSHAKE, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        rec
    }

    #[test]
    fn sni_and_tls13_via_supported_versions_ignoring_grease() {
        let p = client_hello(Some("WWW.Example.com"), &[0x0a0a, 0x0304, 0x0303]);
        assert_eq!(
            parse_client_hello(&p),
            Some(ClientHello {
                sni: Some("www.example.com".into()),
                version: "TLS1.3"
            })
        );
    }

    #[test]
    fn tls12_without_sni_or_versions() {
        let p = client_hello(None, &[]);
        assert_eq!(
            parse_client_hello(&p),
            Some(ClientHello {
                sni: None,
                version: "TLS1.2"
            })
        );
    }

    #[test]
    fn invalid_sni_is_dropped_but_hello_kept() {
        let p = client_hello(Some("bad host!"), &[]);
        assert_eq!(parse_client_hello(&p).unwrap().sni, None);
        let long = "a".repeat(254);
        assert_eq!(
            parse_client_hello(&client_hello(Some(&long), &[]))
                .unwrap()
                .sni,
            None
        );
    }

    #[test]
    fn rejects_non_client_hello() {
        assert_eq!(parse_client_hello(&[]), None);
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), None);
        let mut p = client_hello(Some("a.com"), &[]);
        p[5] = 2; // ServerHello
        assert_eq!(parse_client_hello(&p), None);
        let mut p = client_hello(Some("a.com"), &[]);
        p[1] = 4; // major version != 3
        assert_eq!(parse_client_hello(&p), None);
    }

    #[test]
    fn snaplen_truncation_returns_what_is_available() {
        let p = client_hello(Some("example.com"), &[0x0304]);
        // corta no meio da extensao SNI: ainda e um ClientHello, sem SNI
        let cut = p.len() - 20;
        let r = parse_client_hello(&p[..cut]);
        assert!(r.is_some());
        // corta dentro do campo random: nao e um ClientHello utilizavel
        assert!(parse_client_hello(&p[..40]).is_none());
        // corta logo antes das extensoes: ClientHello valido, sem SNI
        assert_eq!(parse_client_hello(&p[..52]).map(|c| c.sni), Some(None));
        // qualquer prefixo nunca entra em panico
        for n in 0..p.len() {
            let _ = parse_client_hello(&p[..n]);
        }
    }
}
