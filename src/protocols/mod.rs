//! DECODE: parsers puros e testaveis (sem I/O, sem estado, sem `unsafe`).
//!
//! `decode_frame` percorre L2 -> L3 -> L4 e devolve um `Packet` que empresta o frame.
//! Toda leitura e checada contra limites: entrada arbitraria nunca causa panico.
use std::net::IpAddr;

pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod reader;
pub mod tcp;
pub mod tls;
pub mod udp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("pacote truncado")]
    Truncated,
    #[error("pacote malformado")]
    Malformed,
    #[error("protocolo nao suportado")]
    Unsupported,
}

/// Tipo de enlace do pcap (DLT_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    LinuxSll,
    /// IP puro (DLT_RAW = 12/101): versao decidida pelo primeiro nibble.
    Raw,
}

impl LinkType {
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            1 => Some(Self::Ethernet),
            113 => Some(Self::LinuxSll),
            12 | 101 => Some(Self::Raw),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Transport<'a> {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &'a [u8],
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    /// ICMP (v4) ou ICMPv6.
    Icmp { icmp_type: u8, code: u8 },
    /// Outro protocolo de camada 4 (ou fragmento sem cabecalho L4).
    Other { proto: u8 },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub transport: Transport<'a>,
}

pub fn decode_frame(link: LinkType, frame: &[u8]) -> Result<Packet<'_>, DecodeError> {
    let (ethertype, l3) = match link {
        LinkType::Ethernet => ethernet::parse_ethernet(frame)?,
        LinkType::LinuxSll => ethernet::parse_linux_sll(frame)?,
        LinkType::Raw => match frame.first().map(|b| b >> 4) {
            Some(4) => (ethernet::ETHERTYPE_IPV4, frame),
            Some(6) => (ethernet::ETHERTYPE_IPV6, frame),
            Some(_) => return Err(DecodeError::Malformed),
            None => return Err(DecodeError::Truncated),
        },
    };
    let (hdr, v6) = match ethertype {
        ethernet::ETHERTYPE_IPV4 => (ip::parse_ipv4(l3)?, false),
        ethernet::ETHERTYPE_IPV6 => (ip::parse_ipv6(l3)?, true),
        _ => return Err(DecodeError::Unsupported),
    };

    let transport = if hdr.non_first_fragment {
        Transport::Other { proto: hdr.proto }
    } else {
        match (hdr.proto, v6) {
            (6, _) => {
                let s = tcp::parse_tcp(hdr.payload)?;
                Transport::Tcp {
                    src_port: s.src_port,
                    dst_port: s.dst_port,
                    flags: s.flags,
                    payload: s.payload,
                }
            }
            (17, _) => {
                let d = udp::parse_udp(hdr.payload)?;
                Transport::Udp {
                    src_port: d.src_port,
                    dst_port: d.dst_port,
                    payload: d.payload,
                }
            }
            (1, false) | (58, true) => {
                let (icmp_type, code) = icmp::parse_icmp(hdr.payload)?;
                Transport::Icmp { icmp_type, code }
            }
            (proto, _) => Transport::Other { proto },
        }
    };
    Ok(Packet {
        src_ip: hdr.src,
        dst_ip: hdr.dst,
        transport,
    })
}

/// Construtores de pacotes sinteticos compartilhados pelos testes.
#[cfg(test)]
pub(crate) mod testutil {
    pub use super::dns::tests::{query as dns_query, response as dns_response};
    pub use super::ip::tests::{v4, v6};
    pub use super::tcp::tests::tcp;
    pub use super::tls::tests::client_hello;
    pub use super::udp::tests::udp;

    pub fn eth(ethertype: u16, l3: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        f.extend(ethertype.to_be_bytes());
        f.extend(l3);
        f
    }

    pub fn eth_v4(proto: u8, l4: &[u8]) -> Vec<u8> {
        eth(0x0800, &v4(proto, l4))
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn udp_dns_over_ethernet() {
        let f = eth_v4(17, &udp(40000, 53, &dns_query("a.com", 1)));
        let p = decode_frame(LinkType::Ethernet, &f).unwrap();
        assert_eq!(p.src_ip.to_string(), "10.0.0.1");
        assert!(matches!(p.transport, Transport::Udp { dst_port: 53, .. }));
    }

    #[test]
    fn tcp_ipv6_and_icmp_variants() {
        let f = eth(0x86dd, &v6(6, &tcp(1, 2, tcp::SYN, &[])));
        assert!(matches!(
            decode_frame(LinkType::Ethernet, &f).unwrap().transport,
            Transport::Tcp {
                flags: tcp::SYN,
                ..
            }
        ));
        let f = eth_v4(1, &[3, 3, 0, 0]);
        assert_eq!(
            decode_frame(LinkType::Ethernet, &f).unwrap().transport,
            Transport::Icmp {
                icmp_type: 3,
                code: 3
            }
        );
        let f = eth(0x86dd, &v6(58, &[128, 0, 0, 0]));
        assert_eq!(
            decode_frame(LinkType::Ethernet, &f).unwrap().transport,
            Transport::Icmp {
                icmp_type: 128,
                code: 0
            }
        );
        // ICMPv4 em IPv6 (proto 1) nao e ICMP
        let f = eth(0x86dd, &v6(1, &[3, 3, 0, 0]));
        assert_eq!(
            decode_frame(LinkType::Ethernet, &f).unwrap().transport,
            Transport::Other { proto: 1 }
        );
    }

    #[test]
    fn other_link_types_and_unsupported() {
        let ip = v4(6, &tcp(1, 2, 0, &[]));
        assert!(decode_frame(LinkType::Raw, &ip).is_ok());
        let mut sll = vec![0; 14];
        sll.extend([0x08, 0x00]);
        sll.extend(&ip);
        assert!(decode_frame(LinkType::LinuxSll, &sll).is_ok());
        assert_eq!(
            decode_frame(LinkType::Ethernet, &eth(0x0806, &[0; 28])),
            Err(DecodeError::Unsupported)
        );
        assert_eq!(
            decode_frame(LinkType::Raw, &[]),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            decode_frame(LinkType::Raw, &[0x10]),
            Err(DecodeError::Malformed)
        );
        assert_eq!(LinkType::from_dlt(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_dlt(9999), None);
    }

    #[test]
    fn fragments_do_not_expose_l4() {
        let mut ip = v4(17, &udp(1, 2, b"x"));
        ip[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        let f = eth(0x0800, &ip);
        assert_eq!(
            decode_frame(LinkType::Ethernet, &f).unwrap().transport,
            Transport::Other { proto: 17 }
        );
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20_000))]

            #[test]
            fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..400)) {
                for link in [LinkType::Ethernet, LinkType::LinuxSll, LinkType::Raw] {
                    let _ = decode_frame(link, &data);
                }
                let _ = dns::parse_dns(&data);
                let _ = tls::parse_client_hello(&data);
            }

            #[test]
            fn mutated_valid_packets_never_panic(
                pos in 0usize..200, val in any::<u8>(), cut in 0usize..200, which in 0u8..3,
            ) {
                let mut f = match which {
                    0 => eth_v4(17, &udp(1, 53, &dns_response("example.com", 1, 0, &["1.2.3.4".parse().unwrap()]))),
                    1 => eth_v4(6, &tcp(1, 443, tcp::ACK, &client_hello(Some("example.com"), &[0x0304]))),
                    _ => eth(0x86dd, &v6(6, &tcp(1, 2, tcp::SYN, &[]))),
                };
                if let Some(b) = f.get_mut(pos) { *b = val; }
                f.truncate(f.len().saturating_sub(cut));
                let _ = decode_frame(LinkType::Ethernet, &f);
            }
        }
    }
}
