---
name: adicionar-decoder-de-protocolo
description: Adicionar um decoder de protocolo (ou campo de evento) ao sensor de rede. Use ao suportar um novo protocolo L3/L4/L7 ou extrair um novo dado dos pacotes.
---
# Adicionar um decoder

1. **Contrato primeiro.** O dado cabe em um campo existente de `EventoFluxoRede`? Se não, é mudança aditiva no `psychoscope-proto` (skill `evoluir-contrato`), com tag antes de usar aqui.
2. **Parser** em `src/protocols/<proto>.rs` (veja `.claude/rules/protocolos.md`): pura, com `Reader`, erros em `DecodeError`. Encadeie em `decode_frame` (`src/protocols/mod.rs`).
3. **Evento:** mapeie em `src/event.rs` e decida se entra na política `interesting` (volume!) ou só em `all`.
4. **Testes:** unitários com helpers de `protocols::testutil`, caso truncado/malformado, `proptest`, e um alvo de fuzz novo + entrada no `scripts/fuzz.sh`.
5. **Integração:** inclua o tráfego em `scripts/gen_pcap.py` (atualize a contagem esperada de eventos e, se disparar regra, o conjunto exato de alertas do `e2e.sh`). Regras que usem o dado são trabalho do core (skill `adicionar-regra-de-deteccao` lá).
6. Documente no README (protocolos suportados e limitações) e rode a skill `verificar-sensor`.
