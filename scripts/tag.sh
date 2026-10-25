#!/usr/bin/env bash
# Cria a tag anotada da proxima versao deste repositorio. So local: nunca faz push.
#
#   scripts/tag.sh [--bump patch|minor|major|X.Y.Z] [-m "descricao"] [--yes] [--skip-check] [--offline]
#
# - Sem argumentos e interativo: mostra a tag atual e os commits desde ela, sugere o tipo de versao
#   pelos Conventional Commits (fix sobe o Z, feat o Y, incompativel o X; antes da 1.0 o incompativel
#   sobe o Y), pede a descricao da tag e confirma.
# - Recusa versao que ja existe (local ou em origin), versao menor ou igual a maior ja criada,
#   arvore suja, branch diferente de main, branch atras de origin e nenhum commit desde a ultima tag.
# - Pre-voo (--skip-check pula): make check, o diretorio pessoal, o e-mail e segredos no codigo,
#   autor e committer dos commits novos (e-mail noreply do GitHub) e a tag do psychoscope-proto
#   no origin do proto.
# - Com Cargo.toml na raiz (sensor), atualiza a versao e o Cargo.lock e cria o commit
#   "chore(release): vX.Y.Z" antes da tag: o release.yml exige tag igual ao Cargo.toml.
# - Termina imprimindo o git push para voce rodar. Ordem de publicacao: proto, core, sensor, .github.
set -euo pipefail

BRANCH=main
BUMP=""
MSG=""
YES=0
SKIP_CHECK=0
OFFLINE=0

usage() { sed -n '2,/^set -euo/{/^set -euo/!p}' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "tag.sh: $*" >&2; exit 1; }
warn() { echo "aviso: $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --bump)       [ $# -ge 2 ] || die "--bump exige um valor"; BUMP="$2"; shift 2 ;;
    -m|--message) [ $# -ge 2 ] || die "$1 exige a descricao"; MSG="$2"; shift 2 ;;
    --yes)        YES=1; shift ;;
    --skip-check) SKIP_CHECK=1; shift ;;
    --offline)    OFFLINE=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) usage >&2; die "argumento desconhecido: $1" ;;
  esac
done

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || die "rode dentro de um repositorio git"
current_branch="$(git branch --show-current)"
[ "$current_branch" = "$BRANCH" ] || die "voce esta em '${current_branch:-HEAD solto}': as tags saem da $BRANCH (git switch $BRANCH)"
[ -z "$(git status --porcelain)" ] || die "ha alteracoes nao commitadas; faca commit ou stash antes de taguear"

has_origin=0
git remote get-url origin >/dev/null 2>&1 && has_origin=1
remote_tags=""
if [ "$OFFLINE" = 1 ] || [ "$has_origin" = 0 ]; then
  warn "sem consultar o origin: so as tags locais serao consideradas"
else
  git fetch -q origin "$BRANCH" || die "nao consegui consultar o origin (sem rede?); use --offline para ignorar"
  behind="$(git rev-list --count "HEAD..origin/$BRANCH")"
  [ "$behind" = 0 ] || die "a branch esta $behind commit(s) atras de origin/$BRANCH; rode git pull --ff-only"
  remote_tags="$(git ls-remote --tags --refs origin 'v*' | awk '{sub("refs/tags/", "", $2); print $2}')"
fi

# Maior versao entre as tags locais e as do origin.
highest="$({ git tag -l 'v*'; printf '%s\n' "$remote_tags"; } | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -uV | tail -n1 || true)"
cur="${highest#v}"
cur="${cur:-0.0.0}"

range=(HEAD)
if [ -n "$highest" ]; then
  if git rev-parse -q --verify "refs/tags/$highest" >/dev/null; then
    range=("$highest..HEAD")
    [ "$(git rev-list --count "$highest..HEAD")" != 0 ] || die "nenhum commit novo desde $highest; nao ha o que taguear"
  else
    range=()
    warn "$highest so existe no origin (rode git fetch --tags para ver os commits e a sugestao do tipo de versao)"
  fi
fi

bump() { # tipo versao
  local a b c
  IFS=. read -r a b c <<<"$2"
  case "$1" in
    patch) echo "$a.$b.$((c + 1))" ;;
    minor) echo "$a.$((b + 1)).0" ;;
    major) echo "$((a + 1)).0.0" ;;
  esac
}

# Tipo sugerido pelos Conventional Commits desde a ultima tag.
suggest_kind() {
  [ ${#range[@]} -gt 0 ] || { echo patch; return; }
  local breaking=0 feat=0
  if git log --format=%s "${range[@]}" | grep -qE '^[a-z]+(\([^)]*\))?!:' ||
    git log --format=%b "${range[@]}" | grep -qE '^BREAKING[ -]CHANGE'; then breaking=1; fi
  if git log --format=%s "${range[@]}" | grep -qE '^feat(\([^)]*\))?:'; then feat=1; fi
  if [ "$breaking" = 1 ]; then
    if [ "${cur%%.*}" -ge 1 ]; then echo major; else echo minor; fi
  elif [ "$feat" = 1 ]; then echo minor
  else echo patch
  fi
}

new=""
if [ -n "$BUMP" ]; then
  case "$BUMP" in
    patch|minor|major) new="$(bump "$BUMP" "$cur")" ;;
    *) new="${BUMP#v}" ;;
  esac
else
  kind="$(suggest_kind)"
  echo "Tag atual: ${highest:-nenhuma} (a maior entre as locais e as do origin)"
  if [ ${#range[@]} -gt 0 ]; then
    echo "Commits desde ${highest:-o inicio}:"
    git log --format='  %h %s' "${range[@]}" | head -n 20
  fi
  default=1
  tag_patch="v$(bump patch "$cur")"; tag_minor="v$(bump minor "$cur")"; tag_major="v$(bump major "$cur")"
  case "$kind" in minor) default=2 ;; major) default=3 ;; esac
  mark() { if [ "$default" = "$1" ]; then echo "  [sugerido]"; fi; }
  echo
  echo "Tipo de versao:"
  echo "  1) correcao (fix)         ${highest:-v0.0.0} -> $tag_patch$(mark 1)"
  echo "  2) funcionalidade (feat)  ${highest:-v0.0.0} -> $tag_minor$(mark 2)"
  echo "  3) incompativel           ${highest:-v0.0.0} -> $tag_major$(mark 3)"
  echo "  4) digitar a versao"
  read -r -p "Escolha [$default]: " choice || die "sem resposta (sem terminal? use --bump)"
  case "${choice:-$default}" in
    1) new="${tag_patch#v}" ;;
    2) new="${tag_minor#v}" ;;
    3) new="${tag_major#v}" ;;
    4) read -r -p "Versao (X.Y.Z): " new || die "sem resposta"; new="${new#v}" ;;
    *) die "opcao invalida: $choice" ;;
  esac
fi

[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "versao invalida: '$new' (use o formato X.Y.Z)"
if git tag -l "v$new" | grep -q . || printf '%s\n' "$remote_tags" | grep -qx "v$new"; then
  die "a tag v$new ja existe (local ou no origin); tags publicadas sao imutaveis"
fi
if [ -n "$highest" ] && [ "$(printf '%s\n%s\n' "$new" "$cur" | sort -V | tail -n1)" != "$new" ]; then
  die "v$new e menor ou igual a maior versao ja criada ($highest)"
fi

if [ -z "$MSG" ]; then
  read -r -p "Descricao da tag (uma linha): " MSG || die "sem descricao (use -m)"
fi
[ -n "$MSG" ] || die "a descricao da tag e obrigatoria"

preflight() {
  if [ -f Makefile ] && grep -q '^check:' Makefile; then
    echo "pre-voo: make check ..."
    make -s check || die "make check falhou; corrija antes de taguear"
  fi
  local hits=() email
  email="$(git config user.email || true)"
  [ -z "$HOME" ] || [ "$HOME" = / ] || hits+=(-e "$HOME")
  case "$email" in ""|*noreply*) ;; *) hits+=(-e "$email") ;; esac
  if [ ${#hits[@]} -gt 0 ] && git grep -nIF "${hits[@]}" -- . >&2; then
    die "o diretorio pessoal ou o e-mail apareceram acima; remova antes de publicar"
  fi
  if git grep -nIE 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}' -- . >&2; then
    die "possivel segredo no codigo (acima); remova antes de publicar"
  fi
  local bad
  bad="$(git log --format='%h %ae %ce' "${range[@]}" | awk '$2 !~ /@users\.noreply\.github\.com$|^noreply@github\.com$/ || $3 !~ /@users\.noreply\.github\.com$|^noreply@github\.com$/' || true)"
  [ -z "$bad" ] || die "autor ou committer sem e-mail noreply do GitHub nos commits abaixo:
$bad"
  if [ "$OFFLINE" = 0 ]; then
    local pin=""
    if [ -f go.mod ]; then pin="$(awk '/psychoscope-proto/ {print $2; exit}' go.mod)"; fi
    if [ -f Cargo.toml ]; then pin="$(sed -n 's/.*psychoscope-proto.*tag = "\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"; fi
    if [ -n "$pin" ] && ! git ls-remote --exit-code --tags https://github.com/psychoscope-io/psychoscope-proto "refs/tags/$pin" >/dev/null 2>&1; then
      warn "a tag $pin do psychoscope-proto nao foi encontrada no GitHub: publique o proto antes deste repositorio"
    fi
  fi
}
if [ "$SKIP_CHECK" = 0 ]; then preflight; else warn "pre-voo ignorado (--skip-check)"; fi

cargo_bump=0
if [ -f Cargo.toml ] && grep -q '^\[package\]' Cargo.toml; then
  cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
  [ "$cargo_version" = "$new" ] || cargo_bump=1
fi

echo
echo "Vai criar a tag anotada v$new (de ${highest:-nenhuma})"
echo "  descricao: $MSG"
echo "  commit:    $(git log -1 --format='%h %s')"
if [ "$cargo_bump" = 1 ]; then
  echo "  antes disso: commit \"chore(release): v$new\" ajustando a versao do Cargo.toml e do Cargo.lock ($cargo_version -> $new)"
fi
if [ "$YES" = 0 ]; then
  read -r -p "Confirmar? [s/N] " answer || die "sem resposta (use --yes)"
  case "$answer" in s|S|sim|SIM) ;; *) die "cancelado" ;; esac
fi

if [ "$cargo_bump" = 1 ]; then
  sed -i '0,/^version = ".*"/s//version = "'"$new"'"/' Cargo.toml
  cargo update --workspace --offline -q
  git add Cargo.toml Cargo.lock
  git commit -q -m "chore(release): v$new"
fi
git tag -a "v$new" -m "$MSG"

echo
echo "Tag v$new criada localmente em $(git log -1 --format='%h %s'). Nada foi enviado."
echo "Para publicar (dispara o release.yml), rode:"
echo "  git push origin $BRANCH v$new"
echo "Ordem entre repositorios: proto, core, sensor, .github."
