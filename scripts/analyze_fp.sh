#!/usr/bin/env bash
# Catalogo de casos: roda `psychoscope-cli analyze` sobre cada pcap de testdata/falsos-positivos/
# (o alerta e indevido) e de testdata/verdadeiros-positivos/ (o alerta TEM de disparar) e confere
# o resultado. Sem privilegios e sem o servico.
#   <nome>.pcap      pcap sintetico (so enderecos de documentacao; gerado por scripts/gen_fp_pcap.py)
#   <nome>.esperado  regras que disparam com os limiares PADRAO, uma por linha (linhas com #
#                    sao comentarios). Vazio ou ausente = nenhum alerta. Uma regra listada e um
#                    falso positivo conhecido: ou deliberadamente mantido (o sinal da regra nao
#                    o separa do ataque; a saida e o .ajuste) ou ainda nao corrigido. Quando a
#                    regra passar a distingui-lo, o teste falha e o arquivo deve ser esvaziado.
#   <nome>.ajuste    (opcional) argumentos do analyze, um por linha (por exemplo --set e o
#                    campo=valor), que PRECISAM silenciar todos os alertas: a documentacao
#                    de como resolver o falso positivo, verificada.
# Uso: analyze_fp.sh <psychoscope-cli> <mod-net-sensor>
set -euo pipefail
[ "$#" = 2 ] || { echo "uso: $0 <psychoscope-cli> <mod-net-sensor>" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$1"; SENSOR="$2"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP" XDG_STATE_HOME="$TMP/state" XDG_RUNTIME_DIR="$TMP/run" # nada do usuario entra na analise
fail() { echo "FALHOU (falsos positivos): $*" >&2; exit 1; }

shopt -s nullglob
casos=("$HERE"/testdata/falsos-positivos/*.pcap "$HERE"/testdata/verdadeiros-positivos/*.pcap)
[ "${#casos[@]}" -gt 0 ] || fail "nenhum pcap em testdata/falsos-positivos nem em testdata/verdadeiros-positivos"
for pcap in "${casos[@]}"; do
  base="${pcap%.pcap}"; nome="$(basename "$(dirname "$base")")/$(basename "$base")"
  "$CLI" analyze --sensor "$SENSOR" --json "$pcap" > "$TMP/out.json" || fail "$nome: analyze falhou"
  python3 -c 'import json,sys; sys.stdout.write("".join(r + "\n" for r in sorted(json.load(sys.stdin)["por_regra"])))' < "$TMP/out.json" > "$TMP/obtido.txt"
  : > "$TMP/esperado.txt"
  if [ -f "$base.esperado" ]; then grep -v -e '^$' -e '^#' "$base.esperado" | sort > "$TMP/esperado.txt" || true; fi
  diff -u "$TMP/esperado.txt" "$TMP/obtido.txt" > "$TMP/diff.txt" || fail "$nome: regras que disparam diferem do .esperado (- esperado, + obtido):
$(cat "$TMP/diff.txt")"
  if [ -f "$base.ajuste" ]; then
    mapfile -t ajuste < "$base.ajuste"
    "$CLI" analyze --sensor "$SENSOR" --fail-on-alert "${ajuste[@]}" "$pcap" > "$TMP/ajustado.txt" || fail "$nome: o ajuste documentado em $nome.ajuste nao silencia o alerta:
$(cat "$TMP/ajustado.txt")"
  fi
  echo "ok: $nome ($(wc -l < "$TMP/obtido.txt") regra(s) com limiares padrao; ajuste: ${ajuste[*]:-nenhum})"
  unset ajuste
done
echo "FALSOS POSITIVOS OK"
