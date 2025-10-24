#!/usr/bin/env bash
set -euo pipefail

# One-command deploy script
# Usage: ./scripts/deploy.sh [dev|staging|prod]

ENV="${1:-dev}"

case "$ENV" in
    dev|staging|prod) ;;
    *) echo "Usage: $0 [dev|staging|prod]"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔒 Encrypting configs..."
"$SCRIPT_DIR/update-encrypted-configs.sh" "$ENV"

echo "📦 Committing encrypted config..."
git add configs/config.${ENV}*.age
git commit -m "Update $ENV config" || echo "No changes to commit"

echo "🚀 Pushing to GitHub..."
git push

echo "☁️  Triggering deployment..."
case "$ENV" in
    dev)
        gh workflow run deploy-dev-docker.yaml
        echo "✅ Dev deployment triggered: https://dapi.w3reg.org"
        ;;
    staging)
        gh workflow run deploy-staging-docker.yaml
        echo "✅ Staging deployment triggered: https://sapi.w3reg.org"
        ;;
    prod)
        echo "⚠️  Production deploy requires confirmation"
        read -p "Type DEPLOY to confirm: " confirm
        if [[ "$confirm" == "DEPLOY" ]]; then
            gh workflow run deploy-prod-docker.yaml -f confirm_deploy=DEPLOY
            echo "✅ Production deployment triggered: https://api.w3reg.org"
        else
            echo "❌ Deployment cancelled"
            exit 1
        fi
        ;;
esac

echo ""
echo "📊 Monitor deployment:"
echo "   gh run list --workflow=deploy-${ENV}-docker.yaml"
echo "   gh run watch"
