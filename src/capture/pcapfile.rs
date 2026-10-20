//! Escritor minimo de arquivos pcap classicos (microssegundos, little-endian),
//! usado para gerar fixtures de teste e de replay.
use std::io::{self, Write};

pub const LINKTYPE_ETHERNET: u32 = 1;

pub struct PcapPacket<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// Bytes gravados (capturados).
    pub data: &'a [u8],
    /// Tamanho original na rede; `None` = igual a `data.len()`.
    pub wire_len: Option<u32>,
}

pub fn write_pcap<W: Write>(
    w: &mut W,
    linktype: u32,
    snaplen: u32,
    packets: &[PcapPacket<'_>],
) -> io::Result<()> {
    w.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?; // versao 2.4
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&snaplen.to_le_bytes())?;
    w.write_all(&linktype.to_le_bytes())?;
    for p in packets {
        let caplen = p.data.len() as u32;
        w.write_all(&p.ts_sec.to_le_bytes())?;
        w.write_all(&p.ts_usec.to_le_bytes())?;
        w.write_all(&caplen.to_le_bytes())?;
        w.write_all(&p.wire_len.unwrap_or(caplen).to_le_bytes())?;
        w.write_all(p.data)?;
    }
    Ok(())
}
