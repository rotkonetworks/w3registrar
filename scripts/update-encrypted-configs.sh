#!/usr/bin/env bash
set -euo pipefail

# Script to update age-encrypted configs
# Usage: ./scripts/update-encrypted-configs.sh [dev|staging|prod]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$PROJECT_ROOT/configs"
SECRETS_DIR="$PROJECT_ROOT/secrets"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${GREEN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}$1${NC}"
}

# Check if age is installed
if ! command -v age &> /dev/null; then
    error "age is not installed. Install with: sudo apt-get install age"
fi

# Check environment argument
ENV="${1:-}"
if [[ ! "$ENV" =~ ^(dev|staging|prod)$ ]]; then
    error "Usage: $0 [dev|staging|prod]"
fi

# Map environment to config files
case "$ENV" in
    dev)
        SOURCE_CONFIG="$SECRETS_DIR/dapi-config.toml"
        ENCRYPTED_FILE="$CONFIG_DIR/config.development.age"
        ;;
    staging)
        SOURCE_CONFIG="$SECRETS_DIR/sapi-config.toml"
        ENCRYPTED_FILE="$CONFIG_DIR/config.staging.age"
        ;;
    prod)
        SOURCE_CONFIG="$SECRETS_DIR/api-config.toml"
        ENCRYPTED_FILE="$CONFIG_DIR/config.production.age"
        ;;
esac

# Check if source config exists
if [[ ! -f "$SOURCE_CONFIG" ]]; then
    error "Source config not found: $SOURCE_CONFIG"
fi

# Check if recipients file exists
RECIPIENTS_FILE="$CONFIG_DIR/recipients.txt"
if [[ ! -f "$RECIPIENTS_FILE" ]]; then
    error "Recipients file not found: $RECIPIENTS_FILE"
fi

info "Encrypting $SOURCE_CONFIG -> $ENCRYPTED_FILE"

# Encrypt the config
age -R "$RECIPIENTS_FILE" -o "$ENCRYPTED_FILE" "$SOURCE_CONFIG"

info "Successfully encrypted $ENV config"
info "Don't forget to commit and push: git add $ENCRYPTED_FILE && git commit -m 'Update $ENV config' && git push"
