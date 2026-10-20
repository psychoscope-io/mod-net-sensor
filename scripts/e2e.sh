#!/usr/bin/env bash
# E2E real: daemon Go (supervisor) lanca o sensor Rust, que reproduz um pcap sintetico e
# envia a telemetria pelo socket Unix. Valida handshake com SO_PEERCRED, contagem de
# eventos, comandos (pausar/retomar/reconfigurar/encerrar) e desligamento gracioso.
# Requer ../psychoscope-core. Nao exige privilegios (usa --pcap-file).
set -euo pipefail
export PATH="$HOME/.local/go/bin:$PATH"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$HERE/../psychoscope-core"
TMP="$(mktemp -d)"
DPID=""
cleanup() { [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
fail() { echo "FALHOU: $*" >&2; echo "--- log do daemon ---" >&2; cat "$TMP/daemon.log" >&2 || true; exit 1; }

EXPECTED=$(python3 "$HERE/scripts/gen_pcap.py" "$TMP/t.pcap")
(cd "$CORE" && go build -o "$TMP/psychoscope" ./cmd/psychoscope && go build -o "$TMP/psychoscope-cli" ./cmd/psychoscope-cli)
(cd "$HERE" && cargo build -q)
SENSOR="$HERE/target/debug/mod-net-sensor"

cat > "$TMP/cfg.json" <<JSON
{
  "status_interval": "1s",
  "modules": [{
    "id": "mod-net-sensor",
    "path": "$SENSOR",
    "args": ["--pcap-file", "$TMP/t.pcap"],
    "connect_timeout": "10s",
    "stop_grace": "5s"
  }]
}
JSON
CLI="$TMP/psychoscope-cli --ctl-socket $TMP/run/ctl.sock"
"$TMP/psychoscope" --config "$TMP/cfg.json" --socket "$TMP/run/core.sock" --ctl-socket "$TMP/run/ctl.sock" --log-level debug 2> "$TMP/daemon.log" &
DPID=$!

col() { $CLI list | awk -v c="$1" 'NR==1{for(i=1;i<=NF;i++) if($i==c) idx=i} NR==2{print $idx}'; }
wait_for() { # descricao, comando...
  local what="$1"; shift
  for _ in $(seq 100); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 0.1; done
  fail "timeout esperando: $what"
}

wait_for "ctl.sock" test -S "$TMP/run/ctl.sock"
wait_for "modulo CONECTADO" bash -c "$CLI list | grep -q CONECTADO"
echo "ok: modulo conectado (handshake + SO_PEERCRED)"

# O StatusModulo chega a cada 1s; esperamos o total de eventos do pcap.
wait_for "EVENTOS=$EXPECTED" bash -c "[ \"\$($(declare -f col); CLI='$CLI'; col EVENTOS)\" = '$EXPECTED' ]"
echo "ok: $EXPECTED eventos recebidos pelo Core"
grep -q "telemetria recebida" "$TMP/daemon.log" || fail "core nao registrou telemetria"
$CLI list

$CLI cmd mod-net-sensor pause   | grep -q ok || fail "pause"
wait_for "estado PAUSADO" bash -c "$CLI list | grep -q PAUSADO"
$CLI cmd mod-net-sensor resume  | grep -q ok || fail "resume"
wait_for "estado CONECTADO" bash -c "$CLI list | grep -q CONECTADO"
echo "ok: pausar/retomar"

if $CLI cmd mod-net-sensor reconfigure bpf=udp 2> "$TMP/nack.txt"; then fail "reconfigure apos o fim do replay deveria ser NACK"; fi
grep -q "encerrada" "$TMP/nack.txt" || fail "mensagem de NACK inesperada: $(cat "$TMP/nack.txt")"
if $CLI cmd mod-net-sensor reconfigure foo=bar 2> "$TMP/nack2.txt"; then fail "parametro desconhecido deveria ser NACK"; fi
grep -q "desconhecido" "$TMP/nack2.txt" || fail "NACK de parametro: $(cat "$TMP/nack2.txt")"
echo "ok: NACK propagado ao CLI ($(cat "$TMP/nack.txt"))"

PID=$($CLI list | awk 'NR==2{print $3}')
$CLI cmd mod-net-sensor stop | grep -q ok || fail "stop"
wait_for "estado ENCERRADO" bash -c "$CLI list | grep -q ENCERRADO"
kill -0 "$PID" 2>/dev/null && fail "processo do sensor ainda vivo apos ENCERRAR"
echo "ok: ENCERRAR graceful (processo $PID terminou, sem restart)"

kill -TERM "$DPID"; wait "$DPID"; RC=$?; DPID=""
[ "$RC" = 0 ] || fail "daemon saiu com $RC"
echo "E2E OK"
