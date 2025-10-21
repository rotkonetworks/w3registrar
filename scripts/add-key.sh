#!/usr/bin/env bash
set -euo pipefail

# Add an age/ed25519 public key to recipients
# Usage:
#   ./scripts/add-key.sh <public-key> <label>
#   ./scripts/add-key.sh age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p "alice-laptop"
#   ./scripts/add-key.sh ~/.ssh/id_ed25519.pub "bob-yubikey"

PUBLIC_KEY="${1:-}"
LABEL="${2:-new-key}"

if [[ -z "$PUBLIC_KEY" ]]; then
    echo "Usage: $0 <public-key-or-file> <label>"
    echo ""
    echo "Examples:"
    echo "  $0 age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p 'alice-laptop'"
    echo "  $0 ~/.ssh/id_ed25519.pub 'bob-yubikey'"
    echo "  $0 \"\$(ssh-keygen -y -f ~/.ssh/id_ed25519)\" 'charlie-key'"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RECIPIENTS_FILE="$PROJECT_ROOT/configs/recipients.txt"

# If it's a file, read it
if [[ -f "$PUBLIC_KEY" ]]; then
    PUBLIC_KEY_DATA="$(cat "$PUBLIC_KEY")"
    echo "📖 Reading key from file: $PUBLIC_KEY"
else
    PUBLIC_KEY_DATA="$PUBLIC_KEY"
fi

# Detect key type
if [[ "$PUBLIC_KEY_DATA" =~ ^age1 ]]; then
    KEY_TYPE="age"
    KEY_TO_ADD="$PUBLIC_KEY_DATA"
elif [[ "$PUBLIC_KEY_DATA" =~ ^ssh-(rsa|ed25519) ]]; then
    KEY_TYPE="ssh"
    KEY_TO_ADD="$PUBLIC_KEY_DATA"
else
    echo "❌ Invalid key format. Must be age1... or ssh-ed25519/ssh-rsa"
    exit 1
fi

# Check if key already exists
if grep -Fq "$KEY_TO_ADD" "$RECIPIENTS_FILE" 2>/dev/null; then
    echo "⚠️  Key already exists in $RECIPIENTS_FILE"
    exit 0
fi

# Add key with comment
echo "$KEY_TO_ADD # $LABEL (added $(date +%Y-%m-%d))" >> "$RECIPIENTS_FILE"

echo "✅ Added $KEY_TYPE key: $LABEL"
echo ""
echo "📋 Current recipients:"
cat "$RECIPIENTS_FILE"
echo ""
echo "🔄 Next steps:"
echo "   1. Re-encrypt all configs: make encrypt-all"
echo "   2. Commit: git add configs/recipients.txt configs/*.age && git commit -m 'Add key: $LABEL'"
echo "   3. Share AGE_PRIVATE_KEY with new recipient (securely!)"
