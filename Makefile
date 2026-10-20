# Atalhos de desenvolvimento. `make check` e o que o CI e o hook pre-push executam.
.PHONY: fmt lint deny test check precommit hooks

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

# Ativa os hooks versionados em .githooks (commit-msg, pre-commit, pre-push).
hooks:
	git config core.hooksPath .githooks
