#!/usr/bin/env bash
# Medicao sob carga: daemon Go + sensor Rust (release) capturando AO VIVO em `lo` dentro de um
# user+net namespace (`unshare -Urn`, sem privilegios reais), com trafego sintetico em taxa
# crescente. Para cada degrau imprime uma linha de tabela markdown: pacotes enviados e capturados
# por segundo, perdas (fila do sensor, buffer do kernel e fila do motor), eventos por segundo e
# CPU e memoria do sensor e do Core. Os numeros vao para docs/DESEMPENHO.md.
#
#   scripts/bench_live.sh
#   BENCH_SECS=15 BENCH_RATES="20000 50000 100000" BENCH_PROCS=3 BENCH_MODES="dns" scripts/bench_live.sh
#   BENCH_IFACE=veth scripts/bench_live.sh      # captura numa veth (outro namespace de rede) em vez de lo
#
# Dois cenarios: "ruido" (UDP de dados, que a politica `interesting` descarta: custo de captura e
# decodificacao) e "dns" (consultas DNS, cada uma vira evento: custo de IPC e do motor com todas
# as regras). O gerador (Python) divide a mesma maquina com o sensor, entao a taxa maxima medida
# depende dele; rode com a maquina ociosa. Com BENCH_IFACE=veth o trafego atravessa um par veth entre
# dois namespaces de rede (driver e fila de recepcao do kernel, mais perto de uma placa que o lo, mas
# ainda virtual; uma interface fisica nao da para medir sem privilegios reais). Requer ../psychoscope-core, unshare, ip e python3.
set -euo pipefail
export LC_ALL=C # ponto decimal no awk e no printf, qualquer que seja o idioma do usuario
if [ "${1:-}" != "--inner" ]; then
  exec timeout -s KILL 1500 unshare -Urn bash "$0" --inner
fi

SECS="${BENCH_SECS:-15}"
RATES="${BENCH_RATES:-20000 50000 100000 200000}"
PROCS="${BENCH_PROCS:-3}"
MODES="${BENCH_MODES:-ruido dns}"
IFACE_KIND="${BENCH_IFACE:-lo}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$HERE/scripts/lib/build.sh"
psy_env "$HERE"
CORE="$(psy_find_core "$HERE")" || exit 1
TMP="$(mktemp -d)"
DPID=""
cleanup() {
  if [ -n "$DPID" ]; then kill -TERM "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true; fi
  if [ -n "${SINK:-}" ]; then kill "$SINK" 2>/dev/null || true; fi
  if [ -n "${PEER:-}" ]; then kill "$PEER" 2>/dev/null || true; fi
  pkill -KILL -f "$TMP" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FALHOU: $*" >&2; tail -20 "$TMP/daemon.log" >&2 || true; exit 1; }

ip link set lo up
IFACE=lo
TARGET=127.0.0.1
PEER=""
SINK=""
if [ "$IFACE_KIND" = veth ]; then
  # par veth: pv0 fica aqui (o sensor captura nela), pv1 vai para um namespace de rede filho onde rodam os geradores
  unshare -n sleep 3600 &
  PEER=$!
  sleep 0.3
  ip link add pv0 type veth peer name pv1
  ip link set pv1 netns "$PEER"
  ip addr add 10.77.0.1/24 dev pv0
  ip link set pv0 up
  nsenter -t "$PEER" -n sh -c 'ip link set lo up && ip addr add 10.77.0.2/24 dev pv1 && ip link set pv1 up'
  IFACE=pv0
  TARGET=10.77.0.1
fi
psy_build_core "$CORE" "$TMP"
(cd "$HERE" && cargo build --release -q)

cat > "$TMP/cfg.json" <<JSON
{ "status_interval": "1s",
  "modules": [{ "id": "mod-net-sensor", "path": "$HERE/target/release/mod-net-sensor",
                "args": ["-i", "$IFACE"], "connect_timeout": "10s", "stop_grace": "5s" }],
  "storage": { "path": "$TMP/state/alerts.db" }, "overrides_path": "$TMP/state/overrides.json", "engine_state_path": "$TMP/state/engine-state.json" }
JSON
CLI="$TMP/psychoscope-cli --ctl-socket $TMP/run/ctl.sock"
"$TMP/psychoscope" --config "$TMP/cfg.json" --socket "$TMP/run/core.sock" --ctl-socket "$TMP/run/ctl.sock" --log-level warn 2> "$TMP/daemon.log" &
DPID=$!
for _ in $(seq 100); do $CLI list 2>/dev/null | grep -q CONECTADO && break; sleep 0.1; done
$CLI list | grep -q CONECTADO || fail "o sensor nao conectou"
SPID="$($CLI list | awk 'NR==2{print $3}')"

# Gerador: PROCS processos, cada um com taxa alvo/PROCS, em UDP para uma porta com socket que
# nunca le (sem ICMP de volta). `ruido` manda dados na 9999; `dns` manda consultas na 53.
cat > "$TMP/gen.py" <<'PY'
import socket, struct, sys, time
mode, rate, secs, idx = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
import os
target = os.environ.get("BENCH_TARGET", "127.0.0.1")
port = 9999 if mode == "ruido" else 53
if os.environ.get("BENCH_RX", "1") == "1":
    # socket que nunca le: o kernel descarta sem devolver ICMP
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    try:
        rx.bind((target, port))
    except OSError:
        pass  # outro processo do gerador ja prendeu a porta
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 22)
def query(n):
    name = ("h%d.bench.example.com" % (n % 64)).split(".")
    q = struct.pack("!HHHHHH", n & 0xFFFF, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name) + b"\0" + struct.pack("!HH", 1, 1)
    return q
pkts = [b"x" * 100] if mode == "ruido" else [query(i) for i in range(64)]
dst, n, chunk, t0 = (target, port), 0, 100, time.perf_counter()
while True:
    now = time.perf_counter() - t0
    if now >= secs:
        break
    if n >= rate * now:
        time.sleep(0.0005)
        continue
    for _ in range(chunk):
        tx.sendto(pkts[n % len(pkts)], dst)
        n += 1
print(n / (time.perf_counter() - t0))
PY

if [ -n "$PEER" ]; then
  # sockets que nunca leem, no namespace do sensor (os geradores, no outro, so enviam)
  python3 -c "
import socket, time
socks = []
for p in (9999, 53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    s.bind(('$TARGET', p)); socks.append(s)
time.sleep(3600)" &
  SINK=$!
  sleep 0.3
fi
gen() { # modo taxa segundos indice
  if [ -n "$PEER" ]; then
    BENCH_TARGET="$TARGET" BENCH_RX=0 nsenter -t "$PEER" -n python3 "$TMP/gen.py" "$@"
  else
    BENCH_TARGET="$TARGET" python3 "$TMP/gen.py" "$@"
  fi
}
clk="$(getconf CLK_TCK)"
ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }
rss_mib() { awk '/VmHWM/ {printf "%.0f", $2 / 1024}' "/proc/$1/status"; }
# metric NOME [filtro]: valor da primeira serie de /metrics com esse nome
metric() { $CLI metrics | awk -v n="$1" '$1 ~ "^"n"({|$)" {print $NF; exit}'; }
counter() { $CLI metrics | awk -v c="counter=$1," 'index($0, c) {print $NF; exit}'; }

echo "Sensor e Core em release; interface $IFACE_KIND; $PROCS processos geradores; degraus de ${SECS} s."
echo
echo "| Cenário | Alvo (pkt/s) | Enviado (pkt/s) | Capturado (pkt/s) | Perdas fila de eventos | Perdas fila de captura | Perdas kernel | Eventos/s no motor | Perdas no motor | CPU sensor | CPU Core | Memória sensor / Core (MiB) |"
echo "|---|---|---|---|---|---|---|---|---|---|---|---|"

rss_now() { awk '/VmRSS/ {printf "%.0f", $2 / 1024}' "/proc/$1/status"; }

# Longa duracao (BENCH_SOAK=segundos, taxa BENCH_SOAK_RATE, padrao 50000): amostra a memoria e a CPU a cada
# 30 s para ver se algo cresce sem parar. Roda no lugar dos degraus.
if [ -n "${BENCH_SOAK:-}" ]; then
  rate="${BENCH_SOAK_RATE:-50000}"
  echo; echo "Longa duração: dns a ${rate} pkt/s por ${BENCH_SOAK} s."
  echo; echo "| Tempo (s) | Memória sensor (MiB) | Memória Core (MiB) | CPU sensor | CPU Core | Perdas acumuladas (fila de eventos) |"; echo "|---|---|---|---|---|---|"
  gens=()
  for i in $(seq "$PROCS"); do
    gen dns "$(awk -v r="$rate" -v p="$PROCS" 'BEGIN{print r/p}')" "$BENCH_SOAK" "$i" > "$TMP/gen.$i" &
    gens+=("$!")
  done
  s_prev=$(ticks "$SPID"); d_prev=$(ticks "$DPID"); t_prev=$(date +%s.%N)
  for ((t = 30; t <= BENCH_SOAK; t += 30)); do
    sleep 30
    now=$(date +%s.%N); s_now=$(ticks "$SPID"); d_now=$(ticks "$DPID")
    awk -v t="$t" -v rs="$(rss_now "$SPID")" -v rd="$(rss_now "$DPID")" -v el="$(awk -v a="$t_prev" -v b="$now" 'BEGIN{print b-a}')" \
        -v sc="$((s_now - s_prev))" -v dc="$((d_now - d_prev))" -v clk="$clk" -v fe="$(counter perda.fila_eventos)" \
        'BEGIN { printf "| %d | %s | %s | %.0f %% | %.0f %% | %s |\n", t, rs, rd, 100 * sc / clk / el, 100 * dc / clk / el, fe }'
    s_prev=$s_now; d_prev=$d_now; t_prev=$now
  done
  wait "${gens[@]}"
  exit 0
fi

for mode in $MODES; do
  for rate in $RATES; do
    cap0=$(metric psychoscope_module_packets_captured_total)
    fe0=$(counter perda.fila_eventos); fc0=$(counter perda.fila_captura); kd0=$(counter perda.kernel); ev0=$(metric psychoscope_engine_events_processed_total); ed0=$(metric psychoscope_engine_events_dropped_total)
    s0=$(ticks "$SPID"); d0=$(ticks "$DPID"); t0=$(date +%s.%N)
    gens=()
    for i in $(seq "$PROCS"); do
      gen "$mode" "$(awk -v r="$rate" -v p="$PROCS" 'BEGIN{print r/p}')" "$SECS" "$i" > "$TMP/gen.$i" &
      gens+=("$!")
    done
    wait "${gens[@]}"
    t1=$(date +%s.%N); s1=$(ticks "$SPID"); d1=$(ticks "$DPID")
    sleep 3 # deixa o sensor e o motor esvaziarem as filas e o status chegar
    cap1=$(metric psychoscope_module_packets_captured_total)
    fe1=$(counter perda.fila_eventos); fc1=$(counter perda.fila_captura); kd1=$(counter perda.kernel); ev1=$(metric psychoscope_engine_events_processed_total); ed1=$(metric psychoscope_engine_events_dropped_total)
    sent=$(cat "$TMP"/gen.* | awk '{s+=$1} END {printf "%.0f", s}')
    awk -v mode="$mode" -v rate="$rate" -v sent="$sent" -v el="$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}')" \
        -v cap="$((cap1 - cap0))" -v fe="$(( ${fe1:-0} - ${fe0:-0} ))" -v fc="$(( ${fc1:-0} - ${fc0:-0} ))" -v kd="$(( ${kd1:-0} - ${kd0:-0} ))" \
        -v ev="$((ev1 - ev0))" -v ed="$((ed1 - ed0))" -v sc="$((s1 - s0))" -v dc="$((d1 - d0))" -v clk="$clk" \
        -v rs="$(rss_mib "$SPID")" -v rd="$(rss_mib "$DPID")" 'BEGIN {
          printf "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %.0f %% | %.0f %% | %s / %s |\n", mode, rate, sent, cap / el, fe, fc, kd, ev / el, ed,
                 100 * sc / clk / el, 100 * dc / clk / el, rs, rd }'
  done
done
echo
echo "Perdas acumuladas por etapa (todo o teste):"
$CLI metrics | awk '/counter=perda\./ {n = $1; sub(/.*counter=/, "", n); sub(/,.*/, "", n); printf "- %s: %s\n", n, $NF}'
echo
echo "Percentuais de CPU são de um núcleo (100 % = um núcleo inteiro). Perdas e eventos são do degrau."
