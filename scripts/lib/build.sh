#!/usr/bin/env bash
# Prologo compartilhado por demo.sh, e2e.sh e live_smoke.sh: ambiente, localizacao do Core e
# compilacao dos binarios do Core. Carregue com `source`; nada roda ao carregar.
# O argumento RAIZ e a raiz deste repositorio (o sensor), que os scripts ja calculam como HERE.

# psy_env RAIZ
# Poe o Go no PATH quando ele so existe em ~/.local/go e, no layout de repositorios irmaos,
# resolve o psychoscope-proto a partir do checkout local (veja local-deps.sh).
psy_env() {
  if ! command -v go >/dev/null && [ -d "$HOME/.local/go/bin" ]; then
    export PATH="$HOME/.local/go/bin:$PATH"
  fi
  local deps="$1/../psychoscope-proto/scripts/local-deps.sh"
  if [ -f "$deps" ]; then
    # shellcheck source=/dev/null
    source "$deps"
  fi
}

# psy_find_core RAIZ [clone]
# Imprime o caminho do psychoscope-core: PSYCHOSCOPE_CORE, o repositorio irmao ou, so com `clone`,
# uma copia em ~/.cache/psychoscope-demo (clonada ou atualizada). Devolve 1 com a mensagem de erro.
psy_find_core() {
  local here="$1" core="" cache
  if [ -n "${PSYCHOSCOPE_CORE:-}" ]; then
    core="$PSYCHOSCOPE_CORE"
  elif [ -d "$here/../psychoscope-core" ]; then
    core="$here/../psychoscope-core"
  elif [ "${2:-}" = clone ]; then
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/psychoscope-demo/psychoscope-core"
    command -v git >/dev/null || { echo "erro: 'git' nao encontrado; instale-o ou defina PSYCHOSCOPE_CORE" >&2; return 1; }
    if [ -d "$cache/.git" ]; then
      git -C "$cache" pull -q --ff-only >&2 || echo "aviso: nao foi possivel atualizar $cache; usando a copia existente" >&2
    else
      echo "clonando https://github.com/psychoscope-io/psychoscope-core em $cache ..." >&2
      git clone -q --depth 1 https://github.com/psychoscope-io/psychoscope-core "$cache" >&2
    fi
    core="$cache"
  else
    echo "erro: psychoscope-core nao encontrado em $here/../psychoscope-core (clone-o ao lado ou defina PSYCHOSCOPE_CORE)" >&2
    return 1
  fi
  [ -f "$core/go.mod" ] || { echo "erro: '$core' nao parece o psychoscope-core (sem go.mod)" >&2; return 1; }
  echo "$core"
}

# psy_build_core CORE DESTINO
# Compila o daemon e a CLI do Core em DESTINO (sem versao: serve aos testes; a receita de release
# e `make build` no core).
psy_build_core() {
  (cd "$1" && go build -o "$2/psychoscope" ./cmd/psychoscope && go build -o "$2/psychoscope-cli" ./cmd/psychoscope-cli)
}
