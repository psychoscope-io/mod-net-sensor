---
paths:
  - "src/protocols/**"
  - "src/reassembly.rs"
---
# Regras dos decoders

- Funções **puras**: entrada `&[u8]`, saída `Result`/`Option`, sem I/O nem estado global. O estado (como a remontagem) mora em estrutura própria com limites.
- Valide tamanhos declarados contra o que existe *antes* de fatiar ou alocar; trate truncamento por `snaplen` como caso normal, devolvendo o que foi lido quando fizer sentido.
- Compressão e ponteiros (DNS) têm limite de saltos e de tamanho; cabeçalhos de extensão (IPv6) têm limite de profundidade.
- Todo parser novo traz: testes unitários com pacotes sintéticos (válido, truncado, malformado, adversarial), teste de propriedade "nunca entra em pânico com bytes arbitrários" (`proptest`) e um alvo em `fuzz/fuzz_targets/`.
- O valor do campo no evento segue o contrato (`flags_tcp` com 6 bits, IPs como texto).
