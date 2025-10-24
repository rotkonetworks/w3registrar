#!/usr/bin/env bash
set -euo pipefail

# Generate a new age key for team members
# Usage: ./scripts/generate-key.sh <name>

NAME="${1:-}"

if [[ -z "$NAME" ]]; then
    echo "Usage: $0 <name>"
    echo "Example: $0 alice"
    exit 1
fi

# Check if age is installed
if ! command -v age &> /dev/null; then
    echo "❌ age not installed. Run: make install-age"
    exit 1
fi

KEY_FILE="./secrets/${NAME}-age-key.txt"

if [[ -f "$KEY_FILE" ]]; then
    echo "⚠️  Key already exists: $KEY_FILE"
    read -p "Overwrite? (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        exit 0
    fi
fi

echo "🔑 Generating age key for: $NAME"
age-keygen -o "$KEY_FILE"

PUBLIC_KEY=$(age-keygen -y "$KEY_FILE")

echo ""
echo "✅ Generated key pair:"
echo "   Private key: $KEY_FILE (keep secret!)"
echo "   Public key:  $PUBLIC_KEY"
echo ""
echo "📋 Adding public key to recipients..."
./scripts/add-key.sh "$PUBLIC_KEY" "$NAME"

echo ""
echo "📤 Share with $NAME (use secure channel!):"
echo "---"
echo "Your age private key (save to ~/.config/age/key.txt):"
echo ""
cat "$KEY_FILE"
echo "---"
echo ""
echo "⚠️  SECURITY: Send via Signal, encrypted email, or password-protected archive"
echo ""
echo "🔄 After sharing, re-encrypt all configs:"
echo "   make encrypt-all"
