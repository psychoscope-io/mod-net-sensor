#!/usr/bin/env bash
# Valida todas as mensagens de um intervalo de commits (sem merges).
#   scripts/check-commits.sh <intervalo>     ex.: origin/main..HEAD
set -euo pipefail
[ $# -eq 1 ] || { echo "uso: $0 <intervalo-git>" >&2; exit 2; }
dir="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
bad=0 total=0
while read -r sha; do
  total=$((total + 1))
  git log -1 --format=%B "$sha" > "$tmp"
  if ! "$dir/check-commit-msg.sh" "$tmp" 2> "$tmp.err"; then
    bad=$((bad + 1))
    echo "commit $(git log -1 --format='%h' "$sha"):" >&2
    cat "$tmp.err" >&2
  fi
  rm -f "$tmp.err"
done < <(git rev-list --reverse --no-merges "$1")
echo "$total commit(s) verificados, $bad fora do padrão"
[ "$bad" -eq 0 ]
