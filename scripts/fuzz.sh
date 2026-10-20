#!/usr/bin/env bash
# Roda cada alvo do cargo-fuzz por N segundos (padrao 60): scripts/fuzz.sh [segundos] [alvo...]
# Exige nightly e cargo-fuzz (cargo install cargo-fuzz --locked) e libpcap-dev (ou LIBPCAP_LIBDIR).
# Falha (exit != 0) se algum alvo achar um crash; o artefato fica em fuzz/artifacts/<alvo>/.
set -euo pipefail

cd "$(dirname "$0")/.."

SECONDS_PER_TARGET="${1:-60}"
shift || true
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(decode_frame parse_dns parse_client_hello read_frame reassembler)
fi

case "$SECONDS_PER_TARGET" in
  '' | *[!0-9]*) echo "uso: $0 [segundos] [alvo...]" >&2; exit 2 ;;
esac

TOOLCHAIN="${FUZZ_TOOLCHAIN:-nightly}"
failed=()
for t in "${TARGETS[@]}"; do
  echo "==> fuzz $t (${SECONDS_PER_TARGET}s)"
  # max_len alto o bastante para o reassembler chegar ao limite de fluxos
  if ! cargo "+$TOOLCHAIN" fuzz run "$t" -- \
    -max_total_time="$SECONDS_PER_TARGET" -max_len=65536 -print_final_stats=1; then
    failed+=("$t")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "crashes em: ${failed[*]} (veja fuzz/artifacts/)" >&2
  exit 1
fi
echo "fuzz ok: ${TARGETS[*]}"
