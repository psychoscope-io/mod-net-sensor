# Atalhos de desenvolvimento. `make check` e o que o CI e o hook pre-push executam.
.PHONY: fmt lint deny test check precommit hooks bench

fmt:
	cargo fmt

# Verificacoes rapidas, usadas pelo hook pre-commit.
precommit:
	cargo fmt --check

lint: precommit
	cargo clippy --locked --all-targets -- -D warnings
	git ls-files -z '*.sh' '.githooks/*' | xargs -0 shellcheck
	actionlint

deny:
	cargo deny check

test:
	cargo test --locked

check: lint deny test

# Benchmark do caminho quente (fora do `check`): gera um pcap de carga (~70 mil pacotes, a maioria
# descartada pela politica 'interesting') e mede decodificacao, montagem do evento e decode_loop.
bench:
	mkdir -p target
	python3 scripts/gen_pcap.py target/bench.pcap --repeat 30 --filler 2000 > /dev/null
	cargo bench --locked --bench hot_path

# Ativa os hooks versionados em .githooks (commit-msg, pre-commit, pre-push).
hooks:
	git config core.hooksPath .githooks
