//! Interfaces de rede capturaveis: `--list-interfaces` e a lista usada nas mensagens de erro.
use pcap::Device;

/// Uma interface como o libpcap a enxerga.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub wireless: bool,
    pub addresses: Vec<String>,
}

/// Lista as interfaces que o libpcap oferece (pode exigir permissao em alguns sistemas).
pub fn list() -> Result<Vec<Interface>, pcap::Error> {
    Ok(Device::list()?.into_iter().map(Interface::from).collect())
}

impl From<Device> for Interface {
    fn from(d: Device) -> Self {
        Self {
            name: d.name,
            description: d.desc,
            up: d.flags.is_up(),
            running: d.flags.is_running(),
            loopback: d.flags.is_loopback(),
            wireless: d.flags.is_wireless(),
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
        }
    }
}

impl Interface {
    fn state(&self) -> &'static str {
        match (self.up, self.running) {
            (false, _) => "desativada",
            (true, false) => "sem link",
            (true, true) => "ativa",
        }
    }

    fn kind(&self) -> &'static str {
        if self.loopback {
            "loopback"
        } else if self.wireless {
            "sem fio"
        } else {
            "-"
        }
    }
}

/// Nomes separados por virgula, para mensagens de erro ("eth0, lo, wlan0").
pub fn names(list: &[Interface]) -> String {
    list.iter()
        .map(|i| i.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Quantos enderecos aparecem por interface (as de container acumulam muitos IPv6).
const MAX_ADDRESSES_SHOWN: usize = 3;

impl Interface {
    /// Ordem de exibicao: primeiro o que um host costuma querer capturar (ativa, com IPv4),
    /// depois o loopback, as demais ativas e, por fim, as inativas.
    fn rank(&self) -> u8 {
        let ipv4 = self.addresses.iter().any(|a| !a.contains(':'));
        match (self.up && self.running, self.loopback, ipv4) {
            (true, false, true) => 0,
            (true, true, _) => 1,
            (true, _, _) => 2,
            _ => 3,
        }
    }

    /// IPv4 antes de IPv6, no maximo `MAX_ADDRESSES_SHOWN`, com "(+N)" para o resto.
    fn addresses_text(&self) -> String {
        if self.addresses.is_empty() {
            return "-".to_string();
        }
        let mut sorted: Vec<&str> = self.addresses.iter().map(String::as_str).collect();
        sorted.sort_by_key(|a| a.contains(':'));
        let shown = sorted
            .iter()
            .take(MAX_ADDRESSES_SHOWN)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        match sorted.len().saturating_sub(MAX_ADDRESSES_SHOWN) {
            0 => shown,
            more => format!("{shown} (+{more})"),
        }
    }
}

/// Tabela para `--list-interfaces`. Nomes e descricoes vem do sistema: caracteres de controle
/// viram `?` para nao mexer no terminal.
pub fn render(list: &[Interface]) -> String {
    if list.is_empty() {
        return "nenhuma interface encontrada (o libpcap nao listou nenhuma; veja as permissoes)\n"
            .to_string();
    }
    let width = list
        .iter()
        .map(|i| i.name.chars().count())
        .max()
        .unwrap_or(0)
        .max("INTERFACE".len());
    let mut out = format!(
        "{:<width$}  {:<10}  {:<8}  ENDERECOS\n",
        "INTERFACE", "ESTADO", "TIPO"
    );
    let mut sorted: Vec<&Interface> = list.iter().collect();
    sorted.sort_by_key(|i| i.rank()); // estavel: dentro de cada grupo vale a ordem do sistema
    for i in sorted {
        out += &format!(
            "{:<width$}  {:<10}  {:<8}  {}\n",
            clean(&i.name),
            i.state(),
            i.kind(),
            i.addresses_text()
        );
        if let Some(d) = &i.description {
            out += &format!("{:<width$}  {}\n", "", clean(d));
        }
    }
    out += "\nuse: mod-net-sensor -i <INTERFACE>\n";
    out
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, up: bool, running: bool) -> Interface {
        Interface {
            name: name.to_string(),
            description: None,
            up,
            running,
            loopback: false,
            wireless: false,
            addresses: vec![],
        }
    }

    #[test]
    fn table_has_state_kind_and_addresses() {
        let lo = Interface {
            loopback: true,
            addresses: vec!["127.0.0.1".into(), "::1".into()],
            ..iface("lo", true, true)
        };
        let wifi = Interface {
            wireless: true,
            addresses: vec!["192.168.0.8".into()],
            description: Some("Wi-Fi".into()),
            ..iface("wlp2s0", true, true)
        };
        let out = render(&[
            lo,
            wifi,
            iface("eth0", false, false),
            iface("eth1", true, false),
        ]);
        for want in [
            "INTERFACE",
            "ESTADO",
            "ENDERECOS",
            "lo      ",
            "loopback",
            "127.0.0.1, ::1",
            "wlp2s0",
            "sem fio",
            "192.168.0.8",
            "Wi-Fi",
            "desativada",
            "sem link",
            "use: mod-net-sensor -i <INTERFACE>",
        ] {
            assert!(out.contains(want), "faltou {want:?}:\n{out}");
        }
        assert_eq!(
            names(&[iface("a", true, true), iface("b", true, true)]),
            "a, b"
        );
    }

    #[test]
    fn hostile_names_and_empty_lists_are_safe() {
        let mut i = iface("e\x1b[31mth0", true, true);
        i.description = Some("x\ny".into());
        let out = render(&[i]);
        assert!(!out.contains('\x1b') && !out.contains("x\ny"), "{out:?}");
        assert!(render(&[]).contains("nenhuma interface"));
    }

    #[test]
    fn useful_interfaces_come_first_and_long_address_lists_are_trimmed() {
        let veth = Interface {
            addresses: vec!["fe80::1".into()],
            ..iface("veth1", true, true)
        };
        let down = iface("eth9", false, false);
        let lo = Interface {
            loopback: true,
            addresses: vec!["127.0.0.1".into()],
            ..iface("lo", true, true)
        };
        let many = Interface {
            addresses: vec![
                "fe80::1".into(),
                "2001::1".into(),
                "192.168.0.8".into(),
                "2001::2".into(),
                "2001::3".into(),
            ],
            ..iface("wlp2s0", true, true)
        };
        let out = render(&[veth, down, lo, many]);
        let pos = |n: &str| out.find(n).unwrap_or_else(|| panic!("sem {n}:\n{out}"));
        assert!(
            pos("wlp2s0") < pos("lo ") && pos("lo ") < pos("veth1") && pos("veth1") < pos("eth9"),
            "{out}"
        );
        assert!(
            out.contains("192.168.0.8, fe80::1, 2001::1 (+2)"),
            "IPv4 primeiro e o resto resumido:\n{out}"
        );
    }
}
