# Quick Reference: Update Configs & Deploy

## Update Config with New Parameters (like [adapter.pgp])

```bash
# 1. Edit local config
nano secrets/dapi-config.toml  # Add [adapter.pgp] section

# 2. Encrypt it
./scripts/update-encrypted-configs.sh dev

# 3. Commit and push
git add configs/config.development.age
git commit -m "Add PGP adapter config"
git push

# 4. Deploy
gh workflow run deploy-dev-docker.yaml
```

## Update GitHub Secrets

```bash
# View all secrets
gh secret list

# Update a secret
gh secret set SECRET_NAME -b "value"
gh secret set SECRET_NAME < file.txt

# Example: Update SSL cert
cat secrets/ssl_cert.pem | base64 | gh secret set SSL_CERT
```

## Deploy to Environments

```bash
# Development (auto on PR merge or manual)
gh workflow run deploy-dev-docker.yaml

# Staging
gh workflow run deploy-staging-docker.yaml

# Production (requires confirmation)
gh workflow run deploy-prod-docker.yaml -f confirm_deploy=DEPLOY
```

## Simplify: Remove Old CONFIG_* Secrets

Your workflows now use `age` encryption. You can delete these old secrets:

```bash
gh secret delete CONFIG_API
gh secret delete CONFIG_API_IN_DOCKER
gh secret delete CONFIG_DAPI
gh secret delete CONFIG_DAPI_IN_DOCKER
gh secret delete CONFIG_SAPI
gh secret delete CONFIG_SAPI_IN_DOCKER
```

Only keep:
- `AGE_PRIVATE_KEY` (decrypts configs)
- `SSL_CERT` (PostgreSQL cert)
- `KEYFILE_*` (network keys)
- `WWW_SSH_KEY` or `SSH_KEY` (deployment)

## Emergency: Decrypt Config Locally

If you need to check what's in production config:

```bash
# Get private key from GitHub
gh secret get AGE_PRIVATE_KEY > /tmp/age-key.txt

# Decrypt
age --decrypt -i /tmp/age-key.txt configs/config.production.age

# Clean up
shred -u /tmp/age-key.txt
```

## Current Workflow

The workflows decrypt configs like this:

```yaml
- name: Create required files
  env:
    AGE_PRIVATE_KEY: ${{ secrets.AGE_PRIVATE_KEY }}
  run: |
    apt-get install -y age
    printf '%s' "$AGE_PRIVATE_KEY" > age-key.txt
    age --decrypt -i ./age-key.txt --output config.docker.toml configs/config.production.age
    shred -u age-key.txt  # Secure cleanup
```

No more CONFIG_* secrets needed!
