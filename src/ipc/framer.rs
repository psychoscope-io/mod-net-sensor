//! Framing length-prefixed do IPC do Psychoscope.
//!
//! Formato: `[ uint32 big-endian: N ][ N bytes: payload protobuf ]`, com
//! `1 <= N <= MAX_FRAME_SIZE`. O tamanho declarado e validado **antes** de
//! qualquer alocacao do payload.

use prost::Message;
use psychoscope_proto::v1::MensagemIpc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use psychoscope_proto::MAX_FRAME_SIZE;

/// Tamanho do prefixo de tamanho em bytes.
pub const HEADER_SIZE: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame vazio (tamanho 0)")]
    Empty,
    #[error("frame excede o tamanho maximo: declarado={declared} max={max}")]
    TooLarge { declared: u32, max: u32 },
    #[error("stream encerrado no meio de um frame")]
    Truncated,
    #[error("decodificacao protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Le um frame completo. `Ok(None)` indica EOF limpo na fronteira de um frame.
///
/// `max == 0` significa `MAX_FRAME_SIZE`; valores acima de `MAX_FRAME_SIZE` sao
/// reduzidos a ele. `Empty`/`TooLarge` sao violacoes de protocolo: o payload nao
/// e lido e a conexao deve ser encerrada pelo chamador.
///
/// Nao e cancel-safe: use dentro de uma task de leitura dedicada, nao em `select!`.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: u32,
) -> Result<Option<Vec<u8>>, FrameError> {
    let max = if max == 0 || max > MAX_FRAME_SIZE {
        MAX_FRAME_SIZE
    } else {
        max
    };

    let mut hdr = [0u8; HEADER_SIZE];
    let mut filled = 0;
    while filled < HEADER_SIZE {
        let n = r.read(&mut hdr[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        filled += n;
    }

    let declared = u32::from_be_bytes(hdr);
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > max {
        return Err(FrameError::TooLarge { declared, max });
    }

    let mut payload = vec![0u8; declared as usize];
    match r.read_exact(&mut payload).await {
        Ok(_) => Ok(Some(payload)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(FrameError::Truncated),
        Err(e) => Err(e.into()),
    }
}

/// Escreve header + payload em um unico `write_all`, evitando intercalacao parcial.
/// Escritas concorrentes na mesma conexao devem ser serializadas pelo chamador.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    let declared = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    if declared > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge {
            declared,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&declared.to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Serializa `msg` e o envia como um frame.
pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &MensagemIpc,
) -> Result<(), FrameError> {
    write_frame(w, &msg.encode_to_vec()).await
}

/// Le um frame e o decodifica como `MensagemIpc`. `Ok(None)` = EOF limpo.
pub async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    max: u32,
) -> Result<Option<MensagemIpc>, FrameError> {
    match read_frame(r, max).await? {
        Some(bytes) => Ok(Some(MensagemIpc::decode(bytes.as_slice())?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Cursor;

    #[derive(Deserialize)]
    struct Fill {
        byte: String,
        count: usize,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        header: String,
        payload: Option<String>,
        payload_fill: Option<Fill>,
        expect: String,
    }
    #[derive(Deserialize)]
    struct Vectors {
        max_frame_size: u32,
        cases: Vec<Case>,
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex invalido: {s}");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Vectors {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/framing_vectors.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Reader que entrega no maximo 1 byte por `poll_read`.
    struct OneByte<R>(R);
    impl<R: AsyncRead + Unpin> AsyncRead for OneByte<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let mut one = [0u8; 1];
            let mut rb = tokio::io::ReadBuf::new(&mut one);
            match std::pin::Pin::new(&mut self.0).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => {
                    buf.put_slice(rb.filled());
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    fn check(expect: &str, got: Result<Option<Vec<u8>>, FrameError>, want: &[u8], name: &str) {
        match (expect, got) {
            ("ok", Ok(Some(p))) => assert_eq!(p, want, "{name}: payload"),
            ("eof", Ok(None)) => {}
            ("empty", Err(FrameError::Empty)) => {}
            ("too_large", Err(FrameError::TooLarge { .. })) => {}
            ("truncated", Err(FrameError::Truncated)) => {}
            (e, g) => panic!("{name}: expect={e} mas obteve {g:?}"),
        }
    }

    #[test]
    fn golden_vectors() {
        let v = vectors();
        assert_eq!(v.max_frame_size, MAX_FRAME_SIZE);
        rt().block_on(async {
            for c in &v.cases {
                let hdr = unhex(&c.header);
                let payload = match (&c.payload, &c.payload_fill) {
                    (_, Some(f)) => vec![unhex(&f.byte)[0]; f.count],
                    (Some(p), None) => unhex(p),
                    (None, None) => vec![],
                };
                let stream = [hdr.clone(), payload.clone()].concat();

                let got = read_frame(&mut Cursor::new(stream.clone()), 0).await;
                check(&c.expect, got, &payload, &c.name);

                let got = read_frame(&mut OneByte(Cursor::new(stream.clone())), 0).await;
                check(&c.expect, got, &payload, &format!("{}/one_byte", c.name));

                if c.expect == "ok" {
                    let mut out = Vec::new();
                    write_frame(&mut out, &payload).await.unwrap();
                    assert_eq!(out, stream, "{}: bytes escritos != vetor canonico", c.name);
                }
            }
        });
    }

    #[test]
    fn oversized_rejected_before_reading_payload() {
        rt().block_on(async {
            let mut data = vec![0x00, 0x10, 0x00, 0x01];
            data.extend(vec![0u8; 4096]);
            let mut cur = Cursor::new(data);
            let err = read_frame(&mut cur, 0).await.unwrap_err();
            assert!(matches!(err, FrameError::TooLarge { .. }));
            assert_eq!(
                cur.position(),
                HEADER_SIZE as u64,
                "so o header deve ser consumido"
            );
        });
    }

    #[test]
    fn custom_max_honored_and_clamped() {
        rt().block_on(async {
            let frame = [&[0u8, 0, 0, 8][..], &[0u8; 8][..]].concat();
            assert!(matches!(
                read_frame(&mut Cursor::new(frame.clone()), 7).await,
                Err(FrameError::TooLarge { .. })
            ));
            assert!(
                read_frame(&mut Cursor::new(frame), 8)
                    .await
                    .unwrap()
                    .is_some()
            );
            let huge = vec![0x00, 0x10, 0x00, 0x01];
            assert!(matches!(
                read_frame(&mut Cursor::new(huge), 1 << 30).await,
                Err(FrameError::TooLarge { .. })
            ));
        });
    }

    #[test]
    fn write_rejects_invalid() {
        rt().block_on(async {
            let mut out = Vec::new();
            assert!(matches!(
                write_frame(&mut out, &[]).await,
                Err(FrameError::Empty)
            ));
            let big = vec![0u8; MAX_FRAME_SIZE as usize + 1];
            assert!(matches!(
                write_frame(&mut out, &big).await,
                Err(FrameError::TooLarge { .. })
            ));
            assert!(out.is_empty());
        });
    }

    #[test]
    fn message_roundtrip_over_duplex() {
        use psychoscope_proto::v1::{HelloModulo, mensagem_ipc::Payload};
        rt().block_on(async {
            let msg = MensagemIpc {
                id_mensagem: "m1".into(),
                timestamp: None,
                payload: Some(Payload::Hello(HelloModulo {
                    id_modulo: "mod-net-sensor".into(),
                    versao_protocolo: 1,
                    versao_modulo: "0.1.0".into(),
                    pid: 42,
                })),
            };
            let (mut a, mut b) = tokio::io::duplex(64);
            let m2 = msg.clone();
            let w = tokio::spawn(async move { write_message(&mut a, &m2).await });
            let got = read_message(&mut b, 0).await.unwrap().unwrap();
            w.await.unwrap().unwrap();
            assert_eq!(got, msg);
        });
    }

    #[test]
    fn garbage_payload_is_decode_error() {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_frame(&mut buf, &[0xff, 0xff, 0xff]).await.unwrap();
            let err = read_message(&mut Cursor::new(buf), 0).await.unwrap_err();
            assert!(matches!(err, FrameError::Decode(_)));
        });
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn roundtrip(payload in proptest::collection::vec(any::<u8>(), 1..8192)) {
                rt().block_on(async {
                    let mut buf = Vec::new();
                    write_frame(&mut buf, &payload).await.unwrap();
                    prop_assert_eq!(buf.len(), HEADER_SIZE + payload.len());
                    let got = read_frame(&mut Cursor::new(buf), 0).await.unwrap().unwrap();
                    prop_assert_eq!(got, payload);
                    Ok(())
                })?;
            }

            #[test]
            fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
                rt().block_on(async {
                    let _ = read_frame(&mut Cursor::new(data), 0).await;
                });
            }
        }
    }
}
