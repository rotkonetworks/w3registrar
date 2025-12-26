.PHONY: build test check clean

build: ## Build release binary
	cargo build --release

test: ## Run tests
	cargo test

check: ## Run clippy and format check
	cargo clippy -- -D warnings
	cargo fmt --check

clean: ## Clean build artifacts
	cargo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
