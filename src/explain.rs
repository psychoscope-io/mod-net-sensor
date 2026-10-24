//! Traduz erros de captura e de socket em mensagens que dizem o que fazer. Funcoes puras: o
//! contexto (interfaces existentes, caminho do binario) vem por parametro.
use std::io::ErrorKind;
use std::path::Path;

/// O que se sabe sobre a captura que falhou.
pub struct CaptureContext<'a> {
    pub interface: Option<&'a str>,
    pub pcap_file: Option<&'a Path>,
    /// Interfaces existentes, separadas por virgula (vazio se nao foi possivel listar).
    pub available: &'a str,
    /// Caminho do binario, para o comando de `setcap`.
    pub exe: &'a str,
}

/// Dica para um erro do libpcap (texto do erro), ou `None` se nao for um caso conhecido.
pub fn capture_hint(error: &str, ctx: &CaptureContext<'_>) -> Option<String> {
    let e = error.to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| e.contains(n));
    if let Some(path) = ctx.pcap_file {
        let p = path.display();
        return if has(&["no such file"]) {
            Some(format!(
                "o arquivo {p} nao existe: confira o caminho de --pcap-file"
            ))
        } else if has(&["permission denied"]) {
            Some(format!("sem permissao para ler {p}"))
        } else if has(&[
            "unknown file format",
            "bad dump file format",
            "truncated dump file",
            "appears to be damaged",
        ]) {
            Some(format!("{p} nao e um arquivo pcap/pcapng valido"))
        } else {
            bpf_hint(&e)
        };
    }
    let name = ctx.interface.unwrap_or("<interface>");
    // sem permissao o libpcap reclama de permissao mesmo para uma interface que nao existe:
    // se a lista mostra que o nome esta errado, esse e o problema a corrigir primeiro
    if interface_is_missing(ctx) {
        Some(missing_interface_hint(name, ctx.available))
    } else if has(&["operation not permitted", "permission denied"]) {
        Some(format!(
            "a captura exige CAP_NET_RAW e CAP_NET_ADMIN: uma vez, como administrador, rode `sudo setcap cap_net_raw,cap_net_admin=eip {}` (ou execute o sensor como root)",
            shell_quote(ctx.exe)
        ))
    } else if has(&["no such device", "no such file"]) {
        Some(missing_interface_hint(name, ctx.available))
    } else if has(&["not up"]) {
        Some(format!(
            "a interface '{name}' esta desativada: ative com `sudo ip link set {name} up`"
        ))
    } else {
        bpf_hint(&e)
    }
}

/// O nome nao consta na lista de interfaces (so vale quando a lista foi obtida).
fn interface_is_missing(ctx: &CaptureContext<'_>) -> bool {
    match ctx.interface {
        Some(name) if !ctx.available.is_empty() => !ctx.available.split(", ").any(|n| n == name),
        _ => false,
    }
}

fn missing_interface_hint(name: &str, available: &str) -> String {
    let list = if available.is_empty() {
        "veja as interfaces com --list-interfaces".to_string()
    } else {
        format!("interfaces disponiveis: {available} (detalhes com --list-interfaces)")
    };
    format!("a interface '{name}' nao existe; {list}")
}

/// Texto seguro para colar num shell: entre aspas simples se tiver espaco ou metacaractere.
fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | ',' | ':' | '=')
        });
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// O erro e de filtro BPF (sintaxe ou expressao), e nao de fonte ou permissao.
fn is_bpf_error(error: &str) -> bool {
    let e = error.to_lowercase();
    ["can't parse filter", "syntax error", "filter expression"]
        .iter()
        .any(|n| e.contains(n))
}

fn bpf_hint(lowercase_error: &str) -> Option<String> {
    is_bpf_error(lowercase_error).then(|| "o filtro de --bpf e invalido: a sintaxe esta em `man pcap-filter` (exemplo: \"udp port 53 or tcp port 443\")".to_string())
}

/// Dica para a falha ao conectar no socket do Core.
pub fn socket_hint(kind: ErrorKind, socket: &Path) -> Option<String> {
    let p = socket.display();
    match kind {
        ErrorKind::NotFound => Some(format!(
            "o Core nao esta escutando em {p}: inicie o psychoscope, ou use --print para ver os eventos sem ele"
        )),
        ErrorKind::ConnectionRefused => Some(format!(
            "{p} existe, mas o Core nao aceita conexoes (processo parado?): inicie o psychoscope ou use --print"
        )),
        ErrorKind::PermissionDenied => Some(format!(
            "sem permissao para abrir {p}: o usuario do sensor precisa de acesso ao socket (modo e grupo do socket do Core)"
        )),
        ErrorKind::InvalidInput => Some(
            "caminho do socket longo demais (o limite do sistema e ~107 bytes): use --socket com um caminho mais curto"
                .to_string(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live<'a>(name: &'a str, available: &'a str) -> CaptureContext<'a> {
        CaptureContext {
            interface: Some(name),
            pcap_file: None,
            available,
            exe: "/usr/local/bin/mod-net-sensor",
        }
    }

    #[test]
    fn permission_errors_name_the_command_with_the_real_binary() {
        for msg in [
            "socket: Operation not permitted",
            "eth0: You don't have permission to capture on that device (socket: Operation not permitted)",
        ] {
            let h = capture_hint(msg, &live("eth0", "")).unwrap();
            assert!(
                h.contains("setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/mod-net-sensor"),
                "{h}"
            );
        }
    }

    #[test]
    fn missing_or_down_interface_lists_what_exists() {
        let h = capture_hint(
            "nope: No such device exists (SIOCGIFHWADDR: No such device)",
            &live("nope", "eth0, lo"),
        )
        .unwrap();
        assert!(
            h.contains("'nope' nao existe")
                && h.contains("eth0, lo")
                && h.contains("--list-interfaces"),
            "{h}"
        );
        let h = capture_hint("x: That device is not up", &live("x", "")).unwrap();
        assert!(h.contains("ip link set x up"), "{h}");
        // sem lista, ainda manda para o comando que lista
        assert!(
            capture_hint("No such device exists", &live("x", ""))
                .unwrap()
                .contains("--list-interfaces")
        );
    }

    #[test]
    fn file_errors_do_not_suggest_setcap() {
        let f = Path::new("/tmp/x.pcap");
        let ctx = CaptureContext {
            interface: None,
            pcap_file: Some(f),
            available: "",
            exe: "m",
        };
        assert!(
            capture_hint("/tmp/x.pcap: No such file or directory", &ctx)
                .unwrap()
                .contains("nao existe")
        );
        assert!(
            capture_hint("/tmp/x.pcap: Permission denied", &ctx)
                .unwrap()
                .contains("sem permissao para ler")
        );
        assert!(
            capture_hint("/tmp/x.pcap: unknown file format", &ctx)
                .unwrap()
                .contains("nao e um arquivo pcap")
        );
        assert!(
            !capture_hint("/tmp/x.pcap: Permission denied", &ctx)
                .unwrap()
                .contains("setcap")
        );
    }

    #[test]
    fn bpf_errors_and_unknown_errors() {
        let h = capture_hint(
            "can't parse filter expression: syntax error",
            &live("lo", ""),
        )
        .unwrap();
        assert!(h.contains("pcap-filter"), "{h}");
        assert_eq!(capture_hint("algo inesperado", &live("lo", "")), None);
    }

    #[test]
    fn socket_errors_say_what_to_do() {
        let p = Path::new("/var/run/psychoscope/core.sock");
        assert!(
            socket_hint(ErrorKind::NotFound, p)
                .unwrap()
                .contains("--print")
        );
        assert!(
            socket_hint(ErrorKind::ConnectionRefused, p)
                .unwrap()
                .contains("nao aceita")
        );
        assert!(
            socket_hint(ErrorKind::PermissionDenied, p)
                .unwrap()
                .contains("sem permissao")
        );
        assert!(
            socket_hint(ErrorKind::InvalidInput, p)
                .unwrap()
                .contains("longo demais")
        );
        assert_eq!(socket_hint(ErrorKind::TimedOut, p), None);
    }

    #[test]
    fn a_wrong_interface_name_beats_the_permission_hint() {
        // sem privilegio o libpcap diz "Operation not permitted" ate para um nome que nao existe
        let h = capture_hint(
            "socket: Operation not permitted",
            &live("eth0", "lo, wlp2s0"),
        )
        .unwrap();
        assert!(
            h.contains("'eth0' nao existe") && h.contains("lo, wlp2s0") && !h.contains("setcap"),
            "{h}"
        );
        // nome certo na lista: a permissao e o problema
        assert!(
            capture_hint("socket: Operation not permitted", &live("lo", "lo, wlp2s0"))
                .unwrap()
                .contains("setcap")
        );
        // lista desconhecida: nao da para afirmar que o nome esta errado
        assert!(
            capture_hint("socket: Operation not permitted", &live("eth0", ""))
                .unwrap()
                .contains("setcap")
        );
    }

    #[test]
    fn the_setcap_path_is_safe_to_paste() {
        assert_eq!(
            shell_quote("/usr/local/bin/mod-net-sensor"),
            "/usr/local/bin/mod-net-sensor"
        );
        assert_eq!(
            shell_quote("/home/ana maria/mod net"),
            "'/home/ana maria/mod net'"
        );
        assert_eq!(shell_quote("/tmp/it's"), "'/tmp/it'\\''s'");
        assert_eq!(shell_quote("/tmp/$(rm -rf x)"), "'/tmp/$(rm -rf x)'");
        let ctx = CaptureContext {
            interface: Some("lo"),
            pcap_file: None,
            available: "lo",
            exe: "/opt/meu sensor/bin",
        };
        assert!(
            capture_hint("Operation not permitted", &ctx)
                .unwrap()
                .contains("eip '/opt/meu sensor/bin'")
        );
    }
}
