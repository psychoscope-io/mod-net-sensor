#!/usr/bin/env bash
# Demo interativa: compila o Core e o sensor, sobe o daemon com um pcap sintetico malicioso
# (sem privilegios, sem tocar na sua rede) e abre a TUI para voce explorar os alertas.
# Requer go, cargo, python3 e libpcap-dev. Se ../psychoscope-core nao existir, o Core e clonado
# em ~/.cache/psychoscope-demo (ou use PSYCHOSCOPE_CORE=<caminho> para apontar um checkout).
set -euo pipefail
export PATH="$HOME/.local/go/bin:$PATH"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORE_REPO="https://github.com/psychoscope-io/psychoscope-core"

die() { echo "erro: $*" >&2; exit 1; }
for tool in go cargo python3; do
  command -v "$tool" >/dev/null || die "'$tool' nao encontrado no PATH; instale-o e tente de novo (veja o README)"
done

# Layout de desenvolvimento (repos irmaos): resolve psychoscope-proto a partir do checkout local.
# shellcheck source=/dev/null
[ -f "$HERE/../psychoscope-proto/scripts/local-deps.sh" ] && source "$HERE/../psychoscope-proto/scripts/local-deps.sh"

find_core() {
  if [ -n "${PSYCHOSCOPE_CORE:-}" ]; then echo "$PSYCHOSCOPE_CORE"; return; fi
  if [ -d "$HERE/../psychoscope-core" ]; then echo "$HERE/../psychoscope-core"; return; fi
  local cache="${XDG_CACHE_HOME:-$HOME/.cache}/psychoscope-demo/psychoscope-core"
  command -v git >/dev/null || die "'git' nao encontrado; instale-o ou defina PSYCHOSCOPE_CORE"
  if [ -d "$cache/.git" ]; then
    git -C "$cache" pull -q --ff-only >&2 || echo "aviso: nao foi possivel atualizar $cache; usando a copia existente" >&2
  else
    echo "clonando $CORE_REPO em $cache ..." >&2
    git clone -q --depth 1 "$CORE_REPO" "$cache" >&2
  fi
  echo "$cache"
}
CORE="$(find_core)"
[ -f "$CORE/go.mod" ] || die "'$CORE' nao parece o psychoscope-core (sem go.mod)"

TMP="$(mktemp -d)"
DPID=""
cleanup() {
  if [ -n "$DPID" ]; then kill "$DPID" 2>/dev/null && wait "$DPID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "compilando (a primeira vez demora alguns minutos) ..."
(cd "$CORE" && go build -o "$TMP/psychoscope" ./cmd/psychoscope && go build -o "$TMP/psychoscope-cli" ./cmd/psychoscope-cli)
(cd "$HERE" && cargo build -q --release) || die "falha ao compilar o sensor; confirme que libpcap-dev esta instalado"
EXPECTED=$(python3 "$HERE/scripts/gen_pcap.py" "$TMP/t.pcap")

cat > "$TMP/cfg.json" <<JSON
{
  "status_interval": "1s",
  "modules": [{
    "id": "mod-net-sensor",
    "path": "$HERE/target/release/mod-net-sensor",
    "args": ["--pcap-file", "$TMP/t.pcap"],
    "connect_timeout": "10s",
    "stop_grace": "5s"
  }],
  "storage": { "path": "$TMP/state/alerts.db" }
}
JSON
CLI="$TMP/psychoscope-cli --ctl-socket $TMP/run/ctl.sock"
"$TMP/psychoscope" --config "$TMP/cfg.json" --socket "$TMP/run/core.sock" --ctl-socket "$TMP/run/ctl.sock" 2> "$TMP/daemon.log" &
DPID=$!

# Espera o sensor conectar e o Core processar todo o pcap, para a TUI ja abrir com os alertas.
ready() {
  # shellcheck disable=SC2086 # CLI guarda o binario e suas flags
  $CLI list 2>/dev/null | awk -v want="$EXPECTED" 'NR==1{for(i=1;i<=NF;i++){if($i=="EVENTOS")e=i}} NR==2{ok=($e==want)} END{exit !ok}'
}
for _ in $(seq 150); do ready && break; sleep 0.2; done
ready || { cat "$TMP/daemon.log" >&2; die "o daemon nao processou o pcap a tempo (log acima)"; }

cat <<MSG

Pronto: $EXPECTED eventos do pcap sintetico processados. Abrindo a TUI.
  tab alterna os paineis | setas/j/k navegam | p pausa, r retoma, x encerra o modulo | q sai

Em OUTRO terminal, enquanto a TUI estiver aberta, voce pode usar a CLI:
  $CLI list
  $CLI alerts --history --min-severity alta
  $CLI metrics

O pcap e reproduzido uma unica vez. Ao sair da TUI, o daemon e o estado temporario sao removidos.
MSG
read -r -p "Enter para abrir a TUI... " _ || true
# shellcheck disable=SC2086
$CLI
