# Permaura developer shortcuts. Run `make help` for the list.

.DEFAULT_GOAL := help
.PHONY: help rust test gateway cli docs pre-push clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

rust: ## Build the whole Rust workspace
	cargo build

test: ## Run the Rust test suite (crypto, audit chain, policy decisions)
	cargo test

pre-push: ## Run the macOS check CI no longer does (see scripts/pre-push.sh)
	scripts/pre-push.sh

gateway: ## Start the REST /v1 + MCP gateway on 127.0.0.1:7376
	cargo run -p permaura-gateway -- start

cli: ## Run the `permaura` CLI (pass ARGS="...")
	cargo run -p permaura-gateway -- $(ARGS)

docs: ## List the documentation set
	@ls -1 docs

clean: ## Remove build artifacts
	cargo clean || true
	rm -rf node_modules
