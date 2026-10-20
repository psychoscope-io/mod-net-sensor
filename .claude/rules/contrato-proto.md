<!-- Compartilhado: a fonte é psychoscope-io/.github (agents/). Não edite esta cópia; rode scripts/sync-agent-rules.sh. -->
# Contrato (psychoscope-proto)

- A fonte do contrato é o `psychoscope-proto`. **Nunca edite código gerado** (`gen/`, saída do prost); mude o `.proto` e regenere.
- **Só mudanças aditivas.** Nunca reutilize número ou nome de campo. Rode `buf lint`, `buf format` e `buf breaking` contra a última tag.
- **Tag publicada é imutável.** Mudança de contrato vira versão nova; os consumidores sobem depois (`go get` no core; `tag` e `Cargo.lock` no sensor).
- **Ordem:** proto (código, tag, push) → core → sensor. Enquanto a tag não existe no GitHub, use `source ../psychoscope-proto/scripts/local-deps.sh`.
- Semântica de compatibilidade: módulo compilado contra uma versão anterior do `ipc.proto` deve continuar funcionando; documente a versão no README do proto.
