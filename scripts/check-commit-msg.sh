#!/usr/bin/env bash
# Valida uma mensagem de commit no padrão Conventional Commits 1.0.
#   scripts/check-commit-msg.sh <arquivo-da-mensagem>
# Regras: tipo(escopo)!: descrição | tipo ∈ feat fix docs style refactor perf test build ci chore revert |
#         cabeçalho com até 100 caracteres (o ideal é 72), descrição começa em minúscula e não termina
#         com ponto | linha em branco após o cabeçalho | sem trailers de IA.
# ALLOW_FIXUP=1 aceita "fixup!"/"squash!" (uso local, antes de reorganizar o histórico).
set -euo pipefail

TYPES='feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert'
MAX_HEADER=100

[ $# -eq 1 ] && [ -f "$1" ] || { echo "uso: $0 <arquivo-da-mensagem>" >&2; exit 2; }
msg="$(grep -v '^#' "$1" || true)"
header="$(printf '%s\n' "$msg" | head -n1)"

errors=()
fail() { errors+=("$1"); }

# Commits que o git gera sozinho
case "$header" in
  Merge\ *) exit 0 ;;
  Revert\ \"*) exit 0 ;;
  fixup!\ * | squash!\ *)
    [ "${ALLOW_FIXUP:-0}" = 1 ] && exit 0
    fail "fixup!/squash! devem ser incorporados antes de publicar (git rebase --autosquash)"
    ;;
esac

if [ ${#errors[@]} -eq 0 ]; then
  re="^(${TYPES})(\\([a-z0-9][a-z0-9._/,-]*\\))?!?: (.+)$"
  if [[ "$header" =~ $re ]]; then
    desc="${BASH_REMATCH[3]}"
    [[ "$desc" =~ ^[A-Z] ]] && fail "a descrição deve começar em minúscula: \"$desc\""
    [[ "$desc" =~ [.]$ ]] && fail "a descrição não termina com ponto"
    [[ "$desc" =~ ^[[:space:]] ]] && fail "a descrição não começa com espaço"
  else
    fail "o cabeçalho deve ser \"tipo(escopo): descrição\" com tipo em: ${TYPES//|/, }"
  fi
  [ ${#header} -le $MAX_HEADER ] || fail "cabeçalho com ${#header} caracteres (máximo $MAX_HEADER, ideal 72)"
fi

second="$(printf '%s\n' "$msg" | sed -n '2p')"
[ -z "$second" ] || fail "deve haver uma linha em branco entre o cabeçalho e o corpo"

if printf '%s\n' "$msg" | grep -qiE '^(co-authored-by|generated-by|assisted-by):.*(claude|anthropic|copilot|openai|chatgpt|gpt|cursor|gemini|codex)|generated with|🤖'; then
  fail "mensagens de commit não levam trailers ou marcas de IA"
fi

if [ ${#errors[@]} -gt 0 ]; then
  {
    echo "Mensagem de commit fora do padrão Conventional Commits:"
    echo "  > $header"
    for e in "${errors[@]}"; do echo "  - $e"; done
    echo "Exemplos: \"feat(ctl): consulta alertas persistidos\"  \"fix(ipc): rejeita PID forjado\"  \"docs: atualiza o README\""
  } >&2
  exit 1
fi
