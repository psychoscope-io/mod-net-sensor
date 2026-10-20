//! Cursor de leitura com checagem de limites: nenhum metodo entra em panico,
//! todos devolvem `None` quando faltam bytes.

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_bounds() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.u16(), Some(0x0203));
        assert_eq!(r.u24(), Some(0x040506));
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.u16(), None);
        assert_eq!(r.remaining(), 1, "leitura falha nao consome");
        assert_eq!(r.rest(), &[7]);
        assert_eq!(
            r.take(usize::MAX),
            None,
            "overflow de posicao nao pode entrar em panico"
        );
        assert_eq!(r.skip(2), None);
        assert_eq!(r.u8(), Some(7));
        assert_eq!(r.u8(), None);
    }
}
