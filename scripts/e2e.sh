#!/usr/bin/env bash
# E2E real: daemon Go (supervisor) lanca o sensor Rust, que reproduz um pcap sintetico e
# envia a telemetria pelo socket Unix. Valida handshake com SO_PEERCRED, contagem de
# eventos, deteccao (conjunto EXATO de 10 alertas, sem extras), metricas, persistencia (o historico volta apos
# reiniciar o daemon), TUI, comandos (pausar/retomar/reconfigurar/encerrar) e desligamento gracioso.
# Requer ../psychoscope-core. Nao exige privilegios (usa --pcap-file).
set -euo pipefail
export PATH="$HOME/.local/go/bin:$PATH"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# Layout de desenvolvimento (repos irmaos): resolve psychoscope-proto a partir do checkout local.
[ -f "$HERE/../psychoscope-proto/scripts/local-deps.sh" ] && source "$HERE/../psychoscope-proto/scripts/local-deps.sh"
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
  }],
  "storage": { "path": "$TMP/state/alerts.db" }
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

# Deteccao: o pcap malicioso deve gerar EXATAMENTE estes 10 alertas (nenhum falso positivo
# no trafego benigno e nenhum extra).
EXPECTED_ALERTS=10
alerts_now() { timeout 2 $CLI alerts > "$TMP/alerts.txt" 2>/dev/null || true; wc -l < "$TMP/alerts.txt"; }
for _ in $(seq 40); do [ "$(alerts_now)" -ge $EXPECTED_ALERTS ] && break; sleep 0.2; done
cat "$TMP/alerts.txt"
[ "$(wc -l < "$TMP/alerts.txt")" = $EXPECTED_ALERTS ] || fail "esperado exatamente $EXPECTED_ALERTS alertas, obtido $(wc -l < "$TMP/alerts.txt")"
awk '{sub(/:$/,"",$4); print $4}' "$TMP/alerts.txt" | sort | uniq -c | awk '{print $2"="$1}' | tr '\n' ' ' > "$TMP/by_rule.txt"
WANT="net.beacon=1 net.bruteforce.auth=1 net.dns.nxdomain_burst=1 net.dns.rate=1 net.dns.tunnel=1 net.icmp.sweep=1 net.scan.syn=1 net.tls.suspicious=3 "
[ "$(cat "$TMP/by_rule.txt")" = "$WANT" ] || fail "alertas por regra: [$(cat "$TMP/by_rule.txt")] esperado [$WANT]"
for needle in "10.0.0.77" "exfil.example" "10.0.0.99" "10.0.0.55" "10.0.0.44" "10.0.0.60" \
              "SNI igual a um IP (93.184.216.34)" "oferece no maximo TLS1.0" "SNI igual a um IP (198.51.100.77)"; do
  grep -qF "$needle" "$TMP/alerts.txt" || fail "alerta com '$needle' ausente"
done
echo "ok: 10 alertas exatos (scan, NXDOMAIN, tunel DNS, forca bruta, ICMP sweep, beacon, pico DNS e 3x TLS - um deles so existe se o ClientHello fragmentado foi remontado)"

# Metricas via ctl.sock
$CLI metrics > "$TMP/metrics.txt"
grep -q "^psychoscope_engine_alerts_total  *10$" "$TMP/metrics.txt" || fail "metrica de alertas: $(grep alerts_total "$TMP/metrics.txt")"
grep -q "^psychoscope_module_up{module=mod-net-sensor}  *1$" "$TMP/metrics.txt" || fail "metrica module_up ausente"
grep -q "^psychoscope_engine_events_processed_total  *$EXPECTED$" "$TMP/metrics.txt" || fail "eventos processados no motor != $EXPECTED: $(grep events_processed "$TMP/metrics.txt")"
echo "ok: metricas ($EXPECTED eventos processados, 10 alertas)"

# TUI num pseudo-terminal real: deve mostrar o modulo conectado e os alertas.
python3 "$CORE/scripts/tui_pty.py" "$TMP/psychoscope-cli" "$TMP/run/ctl.sock" PSYCHOSCOPE mod-net-sensor CONECTADO "Alertas (10)" net.scan.syn net.dns.tunnel "ev/s" || fail "TUI"
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
echo "ok: shutdown gracioso do daemon"

# Persistencia: um daemon NOVO, sem modulos, ainda conhece os 10 alertas (SQLite).
cat > "$TMP/cfg2.json" <<JSON
{ "status_interval": "1s", "storage": { "path": "$TMP/state/alerts.db" } }
JSON
[ "$(stat -c %a "$TMP/state/alerts.db")" = 600 ] || fail "banco de alertas deve ter modo 0600"
"$TMP/psychoscope" --config "$TMP/cfg2.json" --socket "$TMP/run/core.sock" --ctl-socket "$TMP/run/ctl.sock" --log-level debug 2> "$TMP/daemon2.log" &
DPID=$!
wait_for "ctl.sock apos reinicio" bash -c "$CLI list"
$CLI alerts --history -n 100 > "$TMP/hist.txt"
tail -1 "$TMP/hist.txt" | grep -qx -- "-- 10 de 10 alertas --" || fail "historico apos reinicio: $(tail -1 "$TMP/hist.txt")"
$CLI alerts --history --min-severity alta | tail -1 | grep -qx -- "-- 2 de 2 alertas --" || fail "filtro de severidade no historico"
$CLI alerts --history --rule net.tls.suspicious | tail -1 | grep -qx -- "-- 3 de 3 alertas --" || fail "filtro de regra no historico"
# o timestamp do alerta e o instante da deteccao (nao o do pcap, de 2023): todos entram em --since 1h
$CLI alerts --history --since 1h | tail -1 | grep -qx -- "-- 10 de 10 alertas --" || fail "filtro --since 1h"
python3 "$CORE/scripts/tui_pty.py" "$TMP/psychoscope-cli" "$TMP/run/ctl.sock" PSYCHOSCOPE "Alertas (10)" net.beacon net.bruteforce.auth || fail "TUI apos reinicio"
echo "ok: 10 alertas recuperados do SQLite apos reiniciar o daemon (CLI e TUI)"
kill -TERM "$DPID"; wait "$DPID"; DPID=""
echo "E2E OK"
