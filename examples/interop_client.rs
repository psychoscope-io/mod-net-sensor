//! Cliente de interoperabilidade Rust <-> Go.
//!
//! Uso: cargo run --example interop_client -- <socket> <happy|oversize> <dump-sent> <dump-recv>
use std::collections::HashMap;

use mod_net_sensor::ipc::framer::{read_frame, write_frame};
use prost::Message;
use prost_types::Timestamp;
use psychoscope_proto::v1::{
    EventoFluxoRede, EventoTelemetria, HelloModulo, MensagemIpc, ProtocoloTransporte,
    RespostaComando, comando_controle::TipoAcao, evento_fluxo_rede,
    evento_fluxo_rede::MetadadosDns, evento_telemetria, mensagem_ipc::Payload,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

fn ts() -> Option<Timestamp> {
    Some(Timestamp {
        seconds: 1_700_000_000,
        nanos: 123,
    })
}

fn msg(id: &str, payload: Payload) -> MensagemIpc {
    MensagemIpc {
        id_mensagem: id.into(),
        timestamp: ts(),
        payload: Some(payload),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (sock, scenario, dump_sent, dump_recv) = (&args[1], &args[2], &args[3], &args[4]);
    let mut conn = UnixStream::connect(sock).await?;
    let (mut sent, mut recv) = (String::new(), String::new());

    let result = run(&mut conn, scenario, &mut sent, &mut recv).await;
    std::fs::write(dump_sent, sent)?;
    std::fs::write(dump_recv, recv)?;
    result?;
    println!("ipc-interop (rust) OK: {scenario}");
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<String>() + "\n"
}

async fn run(
    conn: &mut UnixStream,
    scenario: &str,
    sent: &mut String,
    recv: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    if scenario == "oversize" {
        // Header declarando 1 MiB + 1; o Go deve rejeitar e fechar sem ler payload.
        conn.write_all(&[0x00, 0x10, 0x00, 0x01]).await?;
        conn.flush().await?;
        let mut sink = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(conn, &mut sink).await?;
        assert_eq!(n, 0, "o Go deveria ter fechado a conexao");
        return Ok(());
    }

    // 1. Hello
    let hello = msg(
        "m-hello",
        Payload::Hello(HelloModulo {
            id_modulo: "mod-net-sensor".into(),
            versao_protocolo: 1,
            versao_modulo: "0.1.0".into(),
            pid: 4242,
        }),
    );
    let b = hello.encode_to_vec();
    sent.push_str(&hex(&b));
    write_frame(conn, &b).await?;

    // 2. HelloResposta
    let b = read_frame(conn, 0)
        .await?
        .ok_or("EOF antes do HelloResposta")?;
    recv.push_str(&hex(&b));
    let m = MensagemIpc::decode(b.as_slice())?;
    match m.payload {
        Some(Payload::HelloResposta(r))
            if m.id_mensagem == "m-hello-ack"
                && r.aceito
                && r.versao_core == "0.1.0"
                && r.intervalo_status_seg == 5
                && m.timestamp == ts() => {}
        other => return Err(format!("hello_resposta inesperada: {other:?}").into()),
    }

    // 3. Telemetria
    let evt = msg(
        "m-evt",
        Payload::Telemetria(EventoTelemetria {
            id_modulo: "mod-net-sensor".into(),
            dado: Some(evento_telemetria::Dado::Rede(EventoFluxoRede {
                ip_origem: "10.0.0.1".into(),
                porta_origem: 51514,
                ip_destino: "1.1.1.1".into(),
                porta_destino: 53,
                protocolo: ProtocoloTransporte::ProtoUdp as i32,
                tamanho_bytes: 74,
                metadados_l7: Some(evento_fluxo_rede::MetadadosL7::Dns(MetadadosDns {
                    dominio_consultado: "example.com".into(),
                    tipo_registro: 1,
                    respostas_ip: vec!["93.184.216.34".into(), "2606:2800:220:1::".into()],
                    codigo_resposta: 0,
                })),
                flags_tcp: 0x12,
                icmp_tipo: 0,
                icmp_codigo: 0,
                timestamp_captura: ts(),
            })),
        }),
    );
    let b = evt.encode_to_vec();
    sent.push_str(&hex(&b));
    write_frame(conn, &b).await?;

    // 4. Comando PAUSAR
    let b = read_frame(conn, 0).await?.ok_or("EOF antes do comando")?;
    recv.push_str(&hex(&b));
    let m = MensagemIpc::decode(b.as_slice())?;
    let expected_params = HashMap::from([("motivo".to_string(), "teste".to_string())]);
    match m.payload {
        Some(Payload::Comando(c))
            if m.id_mensagem == "m-cmd"
                && c.id_comando == "cmd-1"
                && c.acao == TipoAcao::Pausar as i32
                && c.parametros == expected_params => {}
        other => return Err(format!("comando inesperado: {other:?}").into()),
    }

    // 5. Resposta ACK
    let ack = msg(
        "m-ack",
        Payload::Resposta(RespostaComando {
            id_comando_referencia: "cmd-1".into(),
            sucesso: true,
            mensagem_erro: String::new(),
        }),
    );
    let b = ack.encode_to_vec();
    sent.push_str(&hex(&b));
    write_frame(conn, &b).await?;

    // 6. O Go fecha a conexao: EOF limpo na fronteira de frame.
    assert!(read_frame(conn, 0).await?.is_none(), "esperado EOF limpo");
    Ok(())
}
