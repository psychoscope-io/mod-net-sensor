#!/usr/bin/env bash
# Interop Go <-> Rust sobre AF_UNIX real. Requer ../psychoscope-core ao lado deste repo.
set -euo pipefail
export PATH="$HOME/.local/go/bin:$PATH"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$HERE/../psychoscope-core"
TMP="$(mktemp -d)"; trap 'kill "${GO_PID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

(cd "$CORE" && go build -o "$TMP/ipc-interop" ./cmd/ipc-interop)
(cd "$HERE" && cargo build -q --example interop_client)
CLIENT="$HERE/target/debug/examples/interop_client"

for scenario in happy oversize; do
  SOCK="$TMP/$scenario.sock"
  "$TMP/ipc-interop" --socket "$SOCK" --scenario "$scenario" \
      --dump-sent "$TMP/go_sent.$scenario" --dump-recv "$TMP/go_recv.$scenario" > "$TMP/go.$scenario.log" 2>&1 &
  GO_PID=$!
  for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
  "$CLIENT" "$SOCK" "$scenario" "$TMP/rs_sent.$scenario" "$TMP/rs_recv.$scenario"
  wait "$GO_PID"; GO_PID=
  cat "$TMP/go.$scenario.log" | tail -1
done

# Bytes no fio identicos nos dois sentidos.
cmp "$TMP/go_sent.happy" "$TMP/rs_recv.happy" && echo "Go->Rust: bytes identicos"
cmp "$TMP/rs_sent.happy" "$TMP/go_recv.happy" && echo "Rust->Go: bytes identicos"
echo "INTEROP OK"
