//! Uso de memoria e CPU do proprio processo, lido de /proc (Linux).
use std::time::Instant;

fn sysconf(name: libc::c_int) -> Option<f64> {
    // SAFETY: sysconf e thread-safe e so le configuracao do sistema.
    let v = unsafe { libc::sysconf(name) };
    (v > 0).then_some(v as f64)
}

/// Memoria residente (RSS) em MiB, ou 0.0 se indisponivel.
pub fn rss_mb() -> f64 {
    let pages = std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<f64>().ok())
        });
    match (pages, sysconf(libc::_SC_PAGESIZE)) {
        (Some(p), Some(sz)) => p * sz / (1024.0 * 1024.0),
        _ => 0.0,
    }
}

/// Soma utime+stime em ticks, lida de /proc/self/stat (campos 14 e 15).
fn cpu_ticks() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    // O campo `comm` (2o) pode conter espacos e parenteses: parte-se apos o ultimo ')'.
    let after = &s[s.rfind(')')? + 1..];
    let f: Vec<&str> = after.split_whitespace().collect();
    // apos ')' o 1o campo e o estado (3o do arquivo): utime e f[11], stime f[12].
    Some(f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?)
}

/// Medidor de CPU: cada chamada a `sample` devolve o uso (% de um nucleo) desde a anterior.
pub struct CpuMeter {
    last_ticks: Option<f64>,
    last_at: Instant,
    clk_tck: f64,
}

impl CpuMeter {
    pub fn new() -> Self {
        Self {
            last_ticks: cpu_ticks(),
            last_at: Instant::now(),
            clk_tck: sysconf(libc::_SC_CLK_TCK).unwrap_or(100.0),
        }
    }

    pub fn sample(&mut self) -> f64 {
        let now = Instant::now();
        let ticks = cpu_ticks();
        let pct = match (self.last_ticks, ticks) {
            (Some(a), Some(b)) => {
                let wall = now.duration_since(self.last_at).as_secs_f64();
                if wall > 0.0 {
                    ((b - a) / self.clk_tck / wall * 100.0).max(0.0)
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };
        self.last_ticks = ticks;
        self.last_at = now;
        pct
    }
}

impl Default for CpuMeter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_is_plausible() {
        let m = rss_mb();
        assert!(m > 1.0 && m < 100_000.0, "rss={m}");
    }

    #[test]
    fn cpu_meter_sees_busy_loop() {
        let mut m = CpuMeter::new();
        let t = Instant::now();
        let mut x = 0u64;
        while t.elapsed().as_millis() < 300 {
            x = x.wrapping_add(std::hint::black_box(1));
        }
        std::hint::black_box(x);
        let pct = m.sample();
        assert!(pct > 20.0, "cpu%={pct}");
    }
}
