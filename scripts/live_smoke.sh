#!/usr/bin/env bash
# Captura AO VIVO sem privilegios reais: roda dentro de um user+net namespace
# (`unshare -Urn`), onde o usuario tem CAP_NET_RAW sobre a interface `lo` do namespace.
# Daemon Go + sensor Rust (gerenciado) + trafego gerado em lo: DNS, SYN/RST e TLS ClientHello.
# Requer ../psychoscope-core, unshare e ip.
set -euo pipefail
if [ "${1:-}" != "--inner" ]; then
  exec timeout -s KILL 120 unshare -Urn bash "$0" --inner
fi

export PATH="$HOME/.local/go/bin:$PATH"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# Layout de desenvolvimento (repos irmaos): resolve psychoscope-proto a partir do checkout local.
[ -f "$HERE/../psychoscope-proto/scripts/local-deps.sh" ] && source "$HERE/../psychoscope-proto/scripts/local-deps.sh"
CORE="$HERE/../psychoscope-core"
TMP="$(mktemp -d)"
DPID=""
cleanup() { [ -n "$DPID" ] && kill -KILL "$DPID" 2>/dev/null || true; pkill -KILL -f "$TMP" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
fail() { echo "FALHOU: $*" >&2; cat "$TMP/daemon.log" >&2 || true; exit 1; }

ip link set lo up
(cd "$CORE" && go build -o "$TMP/psychoscope" ./cmd/psychoscope && go build -o "$TMP/psychoscope-cli" ./cmd/psychoscope-cli)
(cd "$HERE" && cargo build -q)

cat > "$TMP/cfg.json" <<JSON
{ "status_interval": "1s",
  "modules": [{ "id": "mod-net-sensor", "path": "$HERE/target/debug/mod-net-sensor",
                "args": ["-i", "lo"], "connect_timeout": "10s", "stop_grace": "5s" }] }
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

START=$(date +%s)
kill -TERM "$DPID"; wait "$DPID"; RC=$?; DPID=""
[ "$RC" = 0 ] || fail "daemon saiu com $RC"
kill -0 "$PID" 2>/dev/null && fail "sensor ainda vivo apos o shutdown do daemon"
echo "ok: shutdown gracioso em $(( $(date +%s) - START ))s"
echo "LIVE SMOKE OK"
