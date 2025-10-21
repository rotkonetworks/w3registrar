.PHONY: help dev staging prod encrypt-all secrets-fetch install-age check-deps add-key generate-key list-keys

help: ## Show this help
	@echo ""
	@echo "w3reg deploy"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

install-age: ## Install age encryption tool
	@if command -v age >/dev/null 2>&1; then \
		echo "✅ age already installed"; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S --noconfirm age; \
		echo "✅ age installed"; \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get install -y age; \
		echo "✅ age installed"; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y age; \
		echo "✅ age installed"; \
	else \
		echo "❌ Unsupported package manager. Please install age manually."; \
		exit 1; \
	fi

check-deps: ## Check if all dependencies are installed
	@command -v age >/dev/null 2>&1 || (echo "❌ age not installed. Run: make install-age" && exit 1)
	@command -v gh >/dev/null 2>&1 || (echo "❌ gh CLI not installed" && exit 1)
	@echo "✅ All dependencies OK"

secrets-fetch: ## Fetch production configs from server
	@mkdir -p secrets
	@echo "📥 Fetching configs from www.rotko.net..."
	@scp root@www.rotko.net:/home/deploy/dapi-w3registrar/config.docker.toml secrets/dapi-config.toml
	@scp root@www.rotko.net:/home/deploy/sapi-w3registrar/config.docker.toml secrets/sapi-config.toml
	@scp root@www.rotko.net:/home/deploy/api-w3registrar/config.docker.toml secrets/api-config.toml
	@scp root@www.rotko.net:/home/deploy/dapi-w3registrar/ssl_cert.pem secrets/ssl_cert.pem
	@echo "✅ Configs fetched to secrets/"

encrypt-all: check-deps ## Encrypt all configs (dev, staging, prod)
	@./scripts/update-encrypted-configs.sh dev
	@./scripts/update-encrypted-configs.sh staging
	@./scripts/update-encrypted-configs.sh prod
	@echo "✅ All configs encrypted"

dev: check-deps ## Deploy to development (dapi.w3reg.org)
	@./scripts/deploy.sh dev

staging: check-deps ## Deploy to staging (sapi.w3reg.org)
	@./scripts/deploy.sh staging

prod: check-deps ## Deploy to production (api.w3reg.org) - requires confirmation
	@./scripts/deploy.sh prod

watch: ## Watch latest deployment
	@gh run watch

logs: ## Show latest deployment logs
	@gh run view --log

status: ## Check deployment status
	@gh run list --limit 5

# Key Management
generate-key: install-age ## Generate age key for new team member (usage: make generate-key NAME=alice)
	@./scripts/generate-key.sh $(NAME)

add-key: ## Add existing key to recipients (usage: make add-key KEY=age1... LABEL=name)
	@./scripts/add-key.sh "$(KEY)" "$(LABEL)"

add-ssh-key: ## Add SSH ed25519 key to recipients (usage: make add-ssh-key FILE=~/.ssh/id_ed25519.pub LABEL=name)
	@./scripts/add-key.sh "$(FILE)" "$(LABEL)"

list-keys: ## List all authorized recipients
	@echo "📋 Authorized keys (configs/recipients.txt):"
	@cat configs/recipients.txt
