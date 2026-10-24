//! Resumo de execucao: a linha periodica de `-v` e o relatorio final. Funcoes puras sobre um
//! `Snapshot` dos contadores; quem monta o `Snapshot` e o `main`.
use std::path::PathBuf;
use std::time::Duration;

/// Perdas (dado que o sensor devia ter processado e nao processou), com o nome para exibir.
const LOSSES: [(&str, &str); 5] = [
    ("perda.kernel", "kernel"),
    ("perda.interface", "interface"),
    ("perda.fila_captura", "fila de captura"),
    ("perda.fila_eventos", "fila de eventos"),
    ("perda.ipc", "envio ao Core"),
];

/// Descartes sem perda: trafego que o sensor viu e decidiu nao transformar em evento.
const IGNORED: [(&str, &str); 5] = [
    ("politica.filtrados", "pacotes fora da politica de emissao"),
    ("decode.nao_suportado", "quadros de protocolo nao suportado"),
    ("decode.malformado", "quadros malformados"),
    ("ip.fragmento", "fragmentos IP"),
    (
        "remontagem.descartados",
        "ClientHellos fragmentados descartados",
    ),
];

/// Fotografia dos contadores num instante.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub elapsed: Duration,
    pub captured: u64,
    pub bytes: u64,
    /// Chaves de `StatusModulo.contadores` (sem `perda.ipc`, que vem de `ipc_dropped`).
    pub counters: Vec<(&'static str, u64)>,
    /// Eventos entregues (ao Core) ou impressos.
    pub delivered: u64,
    /// Eventos perdidos no envio ao Core (reconexao ou falha de escrita).
    pub ipc_dropped: u64,
}

/// Para onde os eventos foram.
#[derive(Debug, Clone)]
pub enum Destination {
    Core { socket: PathBuf, sessions: u64 },
    Print,
}

impl Snapshot {
    fn counter(&self, key: &str) -> u64 {
        if key == "perda.ipc" {
            return self.ipc_dropped;
        }
        self.counters
            .iter()
            .find(|(k, _)| *k == key)
            .map_or(0, |(_, v)| *v)
    }

    fn losses(&self) -> Vec<(&'static str, u64)> {
        LOSSES
            .iter()
            .map(|(k, n)| (*n, self.counter(k)))
            .filter(|(_, v)| *v > 0)
            .collect()
    }

    fn total_losses(&self) -> u64 {
        self.losses().iter().map(|(_, v)| v).sum()
    }
}

fn per_second(n: u64, d: Duration) -> f64 {
    if d.as_secs_f64() <= 0.0 {
        0.0
    } else {
        n as f64 / d.as_secs_f64()
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn pairs(list: &[(&str, u64)]) -> String {
    list.iter()
        .map(|(n, v)| format!("{n} {v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Uma linha com a taxa do ultimo intervalo (`-v`).
pub fn periodic_line(prev: &Snapshot, now: &Snapshot) -> String {
    let dt = now.elapsed.saturating_sub(prev.elapsed);
    let losses = now.total_losses();
    format!(
        "{:.0}s | {:.0} pacotes/s | {:.0} eventos/s ({} no total) | perdas: {}",
        now.elapsed.as_secs_f64(),
        per_second(now.captured.saturating_sub(prev.captured), dt),
        per_second(now.delivered.saturating_sub(prev.delivered), dt),
        now.delivered,
        if losses == 0 {
            "nenhuma".to_string()
        } else {
            format!("{losses} ({})", pairs(&now.losses()))
        },
    )
}

/// Relatorio de encerramento, com o aviso de eventos que nao chegaram a lugar nenhum.
pub fn final_report(s: &Snapshot, dest: &Destination) -> String {
    let mut out = format!(
        "resumo ({:.1}s)\n  pacotes: {} capturados ({:.0}/s), {}\n",
        s.elapsed.as_secs_f64(),
        s.captured,
        per_second(s.captured, s.elapsed),
        human_bytes(s.bytes)
    );
    out += &match dest {
        Destination::Core { .. } => format!("  eventos: {} entregues ao Core\n", s.delivered),
        Destination::Print => format!("  eventos: {} impressos\n", s.delivered),
    };
    out += &match s.losses().as_slice() {
        [] => "  perdas: nenhuma\n".to_string(),
        l => format!("  perdas: {} no total ({})\n", s.total_losses(), pairs(l)),
    };
    let ignored: Vec<_> = IGNORED
        .iter()
        .map(|(k, n)| (*n, s.counter(k)))
        .filter(|(_, v)| *v > 0)
        .collect();
    if !ignored.is_empty() {
        out += &format!("  vistos e ignorados: {}\n", pairs(&ignored));
    }
    if let Destination::Core {
        socket,
        sessions: 0,
    } = dest
    {
        out += &format!(
            "  AVISO: nenhum evento chegou ao Core: ele nao estava conectado em {}. Use --print para ver os eventos sem o Core.\n",
            socket.display()
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(secs: u64, captured: u64, delivered: u64) -> Snapshot {
        Snapshot {
            elapsed: Duration::from_secs(secs),
            captured,
            delivered,
            ..Default::default()
        }
    }

    #[test]
    fn periodic_line_shows_rates_of_the_last_interval_and_losses() {
        let prev = snap(10, 1_000, 100);
        let mut now = snap(20, 3_000, 160);
        assert_eq!(
            periodic_line(&prev, &now),
            "20s | 200 pacotes/s | 6 eventos/s (160 no total) | perdas: nenhuma"
        );
        now.counters = vec![("perda.kernel", 5), ("perda.fila_captura", 0)];
        now.ipc_dropped = 2;
        let l = periodic_line(&prev, &now);
        assert!(l.ends_with("perdas: 7 (kernel 5, envio ao Core 2)"), "{l}");
        // dois instantes iguais nao dividem por zero
        assert!(periodic_line(&now, &now).contains("0 pacotes/s"));
    }

    #[test]
    fn final_report_separates_losses_from_ignored_traffic() {
        let mut s = snap(12, 334, 330);
        s.bytes = 41_200;
        s.counters = vec![
            ("decode.nao_suportado", 1),
            ("politica.filtrados", 3),
            ("perda.kernel", 0),
        ];
        let dest = Destination::Core {
            socket: "/run/core.sock".into(),
            sessions: 1,
        };
        let r = final_report(&s, &dest);
        for want in [
            "resumo (12.0s)",
            "334 capturados (28/s), 40.2 KiB",
            "330 entregues ao Core",
            "perdas: nenhuma",
            "vistos e ignorados: pacotes fora da politica de emissao 3, quadros de protocolo nao suportado 1",
        ] {
            assert!(r.contains(want), "faltou {want:?}:\n{r}");
        }
        assert!(!r.contains("AVISO"));

        s.counters.push(("perda.fila_captura", 4));
        let r = final_report(&s, &Destination::Print);
        assert!(
            r.contains("330 impressos") && r.contains("perdas: 4 no total (fila de captura 4)"),
            "{r}"
        );
    }

    #[test]
    fn warns_when_the_core_never_connected() {
        let s = snap(2, 330, 0);
        let r = final_report(
            &s,
            &Destination::Core {
                socket: "/run/core.sock".into(),
                sessions: 0,
            },
        );
        assert!(
            r.contains("AVISO: nenhum evento chegou ao Core")
                && r.contains("/run/core.sock")
                && r.contains("--print"),
            "{r}"
        );
        let r = final_report(&s, &Destination::Print);
        assert!(!r.contains("AVISO"), "com --print o Core nao e esperado");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_bytes(900), "900 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 << 20), "5.0 MiB");
    }
}
