---
name: adicionar-caso-de-falso-positivo
description: Transformar um falso positivo observado numa regra de detecção em um caso do catálogo (pcap sintético + .esperado + .ajuste) conferido pelo analyze. Use ao catalogar ou corrigir um falso positivo.
---
# Adicionar um caso ao catálogo de falsos positivos

O catálogo vive em `testdata/falsos-positivos/` e é conferido por `scripts/analyze_fp.sh` (chamado pelo `e2e.sh`). Modelo a copiar: `beacon-keepalive`.

1. **Reproduza o alerta** com `psychoscope-cli analyze --rule <regra> captura.pcap` (receita completa em `psychoscope-core/docs/FALSOS-POSITIVOS.md`).
2. **Nunca commite a captura real.** Recrie o padrão em `scripts/gen_fp_pcap.py`: uma função nova que devolve os pacotes (só endereços de documentação: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; nomes `example.com`; semente fixa) e uma linha em `__main__` que grava `testdata/falsos-positivos/<nome>.pcap`. Rode `python3 scripts/gen_fp_pcap.py` e commite o `.pcap` gerado.
3. **Escreva `<nome>.esperado`:** as regras que ainda disparam com os limiares PADRÃO, uma por linha (arquivo vazio = nenhum alerta). Regra listada = falso positivo conhecido e ainda não corrigido.
4. **Escreva `<nome>.ajuste`** (opcional, mas é o que torna o caso útil): os argumentos do `analyze`, um por linha, que silenciam o alerta (`--set` na linha de cima e `detection.<regra>.<campo>=valor` na de baixo). O script exige que o `analyze --fail-on-alert` com eles saia com 0.
5. **Se a correção muda a regra ou os limiares padrão**, esvazie o `.esperado` no mesmo commit: o teste falha de propósito quando o falso positivo some.
6. Rode `scripts/analyze_fp.sh <psychoscope-cli> <mod-net-sensor>` e `scripts/e2e.sh`; prove que morde (esvazie o `.esperado` ou estrague o `.ajuste` e veja falhar).
7. Atualize a seção "Falsos positivos" da regra em `psychoscope-core/docs/REGRAS.md` (de "esperado" para "observado", com o caso).
