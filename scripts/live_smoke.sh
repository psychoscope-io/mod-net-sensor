#!/usr/bin/env bash
# Captura AO VIVO sem privilegios reais: roda dentro de um user+net namespace
# (`unshare -Urn`), onde o usuario tem CAP_NET_RAW sobre a interface `lo` do namespace.
# Daemon Go + sensor Rust (gerenciado) + trafego gerado em lo: DNS, SYN/RST e TLS ClientHello.
# Requer ../psychoscope-core, unshare e ip.
set -euo pipefail
if [ "${1:-}" != "--inner" ]; then
  exec timeout -s KILL 300 unshare -Urn bash "$0" --inner
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$HERE/scripts/lib/build.sh"
psy_env "$HERE"
CORE="$(psy_find_core "$HERE")" || exit 1
TMP="$(mktemp -d)"
DPID=""
cleanup() {
  if [ -n "$DPID" ]; then kill -KILL "$DPID" 2>/dev/null || true; fi
  pkill -KILL -f "$TMP" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FALHOU: $*" >&2; cat "$TMP/daemon.log" >&2 || true; exit 1; }

ip link set lo up
psy_build_core "$CORE" "$TMP"
(cd "$HERE" && cargo build -q)

cat > "$TMP/cfg.json" <<JSON
{ "status_interval": "1s",
  "modules": [{ "id": "mod-net-sensor", "path": "$HERE/target/debug/mod-net-sensor",
                "args": ["-i", "lo"], "connect_timeout": "10s", "stop_grace": "5s" }],
  "storage": { "path": "$TMP/state/alerts.db" }, "overrides_path": "$TMP/state/overrides.json", "engine_state_path": "$TMP/state/engine-state.json" }
JSON
CLI="$TMP/psychoscope-cli --ctl-socket $TMP/run/ctl.sock"
"$TMP/psychoscope" --config "$TMP/cfg.json" --socket "$TMP/run/core.sock" --ctl-socket "$TMP/run/ctl.sock" --log-level debug 2> "$TMP/daemon.log" &
DPID=$!

wait_for() { local what="$1"; shift; for _ in $(seq 100); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done; fail "timeout esperando: $what"; }
wait_for "modulo CONECTADO" bash -c "$CLI list | grep -q CONECTADO"
echo "ok: sensor ao vivo conectado (captura em lo)"

python3 - <<'PY'
import socket, ssl, threading, time
time.sleep(0.5)
# DNS para uma porta sem servidor: gera consulta + ICMP port-unreachable
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"
s.sendto(q, ("127.0.0.1", 53))
# SYN para porta fechada: SYN + RST
try: socket.create_connection(("127.0.0.1", 9), timeout=1)
except OSError: pass
# TLS ClientHello com SNI (servidor TCP que apenas le e fecha)
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
port = srv.getsockname()[1]
threading.Thread(target=lambda: (lambda c: (c.recv(4096), c.close()))(srv.accept()[0]), daemon=True).start()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try: ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=2), server_hostname="live.example.com")
except Exception: pass
PY

# esperado >= 5: DNS, ICMP, SYN, RST, ClientHello (+ SYN/SYN-ACK do handshake TCP)
got() { $CLI list | awk 'NR==2{print $5}'; }
for _ in $(seq 60); do [ "$(got)" -ge 5 ] 2>/dev/null && break; sleep 0.25; done
$CLI list
[ "$(got)" -ge 5 ] || fail "eventos esperados >= 5, obtido $(got)"
PK=$($CLI list | awk 'NR==2{print $6}'); [ "$PK" -ge 5 ] || fail "pacotes capturados insuficientes: $PK"
echo "ok: $(got) eventos de trafego real em lo"

PID=$($CLI list | awk 'NR==2{print $3}')
$CLI cmd mod-net-sensor reconfigure bpf="udp port 53" | grep -q ok || fail "reconfigure bpf ao vivo"
echo "ok: RECONFIGURAR (BPF) aplicado ao vivo"
$CLI cmd mod-net-sensor reconfigure bpf="isto nao e bpf ((" 2> "$TMP/nack.txt" && fail "BPF invalido deveria ser NACK"
echo "ok: BPF invalido recusado (NACK): $(cat "$TMP/nack.txt")"

# Configuracao ao vivo: neste namespace o usuario e root, entao a escrita e permitida.
$CLI config set detection.scan.vertical_ports=40 | grep -q "detection.scan.vertical_ports: 15 -> 40" || fail "config set"
$CLI config detection.scan.vertical_ports | grep -q "ajuste" || fail "o campo deve aparecer com origem ajuste"
[ "$(stat -c %a "$TMP/state/overrides.json")" = 600 ] || fail "o arquivo de ajustes deve ter modo 0600"
grep -q "configuracao alterada" "$TMP/daemon.log" || fail "a mudanca deve ir para o log de auditoria"
grep -q "motor reconfigurado" "$TMP/daemon.log" || fail "o motor deve ter sido reconfigurado ao vivo"
if $CLI config set detection.scan.window=10m 2> "$TMP/cfgbad.txt"; then fail "janela maior que detection.window deveria ser recusada"; fi
grep -q "detection.window" "$TMP/cfgbad.txt" || fail "erro de validacao: $(cat "$TMP/cfgbad.txt")"
$CLI config reset detection.scan.vertical_ports | grep -q "detection.scan.vertical_ports: 40 -> 15" || fail "config reset"
[ ! -e "$TMP/state/overrides.json" ] || fail "sem ajustes o arquivo e removido"
echo "ok: configuracao ao vivo (ajuste, auditoria, motor reconfigurado, validacao e restauracao)"

# Tela de configuracoes da TUI num pty real (como root do namespace): edita, grava, restaura e sai.
python3 "$CORE/scripts/tui_config_pty.py" "$TMP/psychoscope-cli" "$TMP/run/ctl.sock" "$TMP/state/overrides.json" > "$TMP/tui_config.txt" 2>&1 \
  || { cat "$TMP/tui_config.txt" >&2; fail "tela de configuracoes da TUI"; }
tail -1 "$TMP/tui_config.txt" | grep -q "TUI CONFIG OK" || fail "tela de configuracoes da TUI: $(tail -3 "$TMP/tui_config.txt")"
echo "ok: tela de configuracoes da TUI num pty real (edicao, rascunho, gravacao, restauracao e saida)"

START=$(date +%s)
kill -TERM "$DPID"; wait "$DPID"; RC=$?; DPID=""
[ "$RC" = 0 ] || fail "daemon saiu com $RC"
kill -0 "$PID" 2>/dev/null && fail "sensor ainda vivo apos o shutdown do daemon"
echo "ok: shutdown gracioso em $(( $(date +%s) - START ))s"
echo "LIVE SMOKE OK"
