#!/usr/bin/env bash
# Vazao ponta a ponta com trafego VARIADO e com tempestade de alertas, por reproducao de pcap:
# o daemon Go sobe com o sensor lendo um pcap grande (sem perdas dentro do sensor, com
# contrapressao pelo socket IPC), e o script mede quanto tempo o Core leva para processar todos os
# eventos, quantos alertas gravou no SQLite e quantos perdeu, e o CPU e a memoria dos dois.
# Cenarios (scripts/gen_traffic_pcap.py): `variado` (DNS, handshakes TCP e ClientHellos de 5000
# origens), `tempestade-scan` e `tempestade-nxdomain` (um alerta por origem/cliente distinto).
#
#   scripts/bench_replay.sh
#   BENCH_N=300000 BENCH_STORM=10000 scripts/bench_replay.sh
#   BENCH_QUEUE=65536 scripts/bench_replay.sh      # outro tamanho da fila do motor
#   BENCH_LOG_LEVEL=info scripts/bench_replay.sh   # com o log de cada alerta, como no servico
#
# Sem privilegios (nao captura de interface). Requer ../psychoscope-core e python3.
set -euo pipefail
export LC_ALL=C

N="${BENCH_N:-500000}"          # eventos do cenario `variado`
STORM="${BENCH_STORM:-20000}"   # origens/clientes de cada tempestade (= alertas esperados)
QUEUE="${BENCH_QUEUE:-4096}"    # detection.queue_size (fila de entrada do motor)
LOGLEVEL="${BENCH_LOG_LEVEL:-error}"  # info reproduz o servico (um log por alerta, sincrono no motor)
case "$QUEUE" in "" | *[!0-9]*) echo "BENCH_QUEUE deve ser um numero inteiro (recebi: $QUEUE)" >&2; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$HERE/scripts/lib/build.sh"
psy_env "$HERE"
CORE="$(psy_find_core "$HERE")" || exit 1
TMP="$(mktemp -d)"
DPID=""
cleanup() {
  if [ -n "$DPID" ]; then kill -TERM "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true; fi
  pkill -KILL -f "$TMP" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FALHOU: $*" >&2; tail -20 "$TMP/daemon.log" >&2 || true; exit 1; }

psy_build_core "$CORE" "$TMP"
(cd "$HERE" && cargo build --release -q)
clk="$(getconf CLK_TCK)"
ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }
rss_mib() { awk '/VmHWM/ {printf "%.0f", $2 / 1024}' "/proc/$1/status"; }

echo "| Cenário | Eventos | Tempo (s) | Eventos/s | Perdas no motor | Alertas gerados | Alertas gravados | Alertas perdidos | Banco (MiB) | CPU sensor | CPU Core | Memória sensor / Core (MiB) |"
echo "|---|---|---|---|---|---|---|---|---|---|---|---|"

run_scenario() { # nome modo n
  local name="$1" modo="$2" n="$3" dir="$TMP/$1"
  mkdir -p "$dir"
  local expected
  expected="$(python3 "$HERE/scripts/gen_traffic_pcap.py" "$dir/t.pcap" --modo "$modo" --n "$n")"
  cat > "$dir/cfg.json" <<JSON
{ "status_interval": "1s",
  "detection": { "queue_size": $QUEUE },
  "modules": [{ "id": "mod-net-sensor", "path": "$HERE/target/release/mod-net-sensor",
                "args": ["--pcap-file", "$dir/t.pcap"], "connect_timeout": "10s", "stop_grace": "5s" }],
  "storage": { "path": "$dir/alerts.db", "max_alerts": 1000000 },
  "overrides_path": "$dir/overrides.json", "engine_state_path": "$dir/engine-state.json" }
JSON
  local cli="$TMP/psychoscope-cli --ctl-socket $dir/ctl.sock"
  # o servico fica parado no inicio ate o pcap estar pronto: a contagem de tempo comeca na conexao do sensor
  "$TMP/psychoscope" --config "$dir/cfg.json" --socket "$dir/core.sock" --ctl-socket "$dir/ctl.sock" --log-level "$LOGLEVEL" 2> "$TMP/daemon.log" &
  DPID=$!
  local t0 s0 d0
  for _ in $(seq 400); do $cli list 2>/dev/null | grep -q CONECTADO && break; sleep 0.02; done
  t0=$(date +%s.%N)
  local spid
  spid="$($cli list | awk 'NR==2{print $3}')"
  s0=$(ticks "$spid"); d0=$(ticks "$DPID")
  local m done=0 t1
  while [ "$done" = 0 ]; do
    m="$($cli metrics)"
    local proc drop
    proc="$(awk '$1 ~ /^psychoscope_engine_events_processed_total/ {print $NF}' <<< "$m")"
    drop="$(awk '$1 ~ /^psychoscope_engine_events_dropped_total/ {print $NF}' <<< "$m")"
    if [ $((proc + drop)) -ge "$expected" ]; then done=1; fi
    t1=$(date +%s.%N)
    [ "$(awk -v a="$t0" -v b="$t1" 'BEGIN{print (b - a > 600)}')" = 1 ] && fail "$name: passou de 600 s"
    [ "$done" = 1 ] || sleep 0.1
  done
  local s1 d1
  s1=$(ticks "$spid"); d1=$(ticks "$DPID")
  sleep 3 # o gravador de alertas esvazia a fila (lotes de 64 ou 500 ms)
  m="$($cli metrics)"
  getm() { awk -v n="$1" '$1 ~ "^"n"({|$)" {print $NF; exit}' <<< "$m"; }
  local alerts written wdrop db
  alerts="$(getm psychoscope_engine_alerts_total)"; written="$(getm psychoscope_store_alerts_written_total)"
  wdrop="$(getm psychoscope_store_alerts_dropped_total)"; db="$(du -m "$dir/alerts.db" 2>/dev/null | awk '{print $1}')"
  awk -v name="$name" -v ev="$expected" -v el="$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b - a}')" -v ed="${drop:-0}" \
      -v al="${alerts:-0}" -v wr="${written:-0}" -v wd="${wdrop:-0}" -v db="${db:-0}" -v sc="$((s1 - s0))" -v dc="$((d1 - d0))" -v clk="$clk" \
      -v rs="$(rss_mib "$spid")" -v rd="$(rss_mib "$DPID")" 'BEGIN {
        printf "| %s | %d | %.1f | %d | %d | %d | %d | %d | %s | %.0f %% | %.0f %% | %s / %s |\n", name, ev, el, ev / el, ed, al, wr, wd, db, 100 * sc / clk / el, 100 * dc / clk / el, rs, rd }'
  kill -TERM "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true; DPID=""
}

run_scenario variado variado "$N"
run_scenario tempestade-scan tempestade-scan "$STORM"
run_scenario tempestade-nxdomain tempestade-nxdomain "$STORM"
echo
echo "Eventos/s é a vazão do sensor ao motor lendo o pcap sem limite de taxa; CPU em % de um núcleo."
