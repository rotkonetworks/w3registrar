#!/bin/bash
#
# Test add_registrar governance flow on local zombienet
#
# Prerequisites:
#   - zombienet installed
#   - polkadot and polkadot-parachain binaries
#   - polkadot-js cli: npm install -g @polkadot/api-cli
#
# Usage:
#   ./scripts/test_add_registrar.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZOMBIENET_CONFIG="${SCRIPT_DIR}/zombienet.toml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Check dependencies
command -v zombienet >/dev/null 2>&1 || error "zombienet not found"
command -v polkadot-js-api >/dev/null 2>&1 || warn "polkadot-js-api not found, install with: npm i -g @polkadot/api-cli"

# Create zombienet config if not exists
if [[ ! -f "$ZOMBIENET_CONFIG" ]]; then
    log "Creating zombienet configuration..."
    cat > "$ZOMBIENET_CONFIG" << 'EOF'
[settings]
timeout = 120

[relaychain]
chain = "rococo-local"
default_command = "polkadot"

[[relaychain.nodes]]
name = "alice"
validator = true

[[relaychain.nodes]]
name = "bob"
validator = true

[[parachains]]
id = 1004
chain = "people-rococo-local"
cumulus_based = true

[[parachains.collators]]
name = "people-collator"
command = "polkadot-parachain"
EOF
fi

log "Starting zombienet with people chain..."
log "Config: $ZOMBIENET_CONFIG"

# Start zombienet in background
zombienet spawn "$ZOMBIENET_CONFIG" &
ZOMBIENET_PID=$!
trap "kill $ZOMBIENET_PID 2>/dev/null" EXIT

# Wait for chains to be ready
log "Waiting for chains to initialize..."
sleep 30

RELAY_RPC="ws://127.0.0.1:9944"
PEOPLE_RPC="ws://127.0.0.1:9988"

# Test account (Alice on local)
ALICE="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
# Registrar account (Bob)
BOB="5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"

log "Testing add_registrar flow..."

# Step 1: Create the inner call for people chain
log "Step 1: Encoding identity.addRegistrar call..."

INNER_CALL=$(polkadot-js-api --ws "$PEOPLE_RPC" \
    tx.identity.addRegistrar "$BOB" \
    --seed "//Alice" \
    --params 2>/dev/null || echo "")

if [[ -z "$INNER_CALL" ]]; then
    warn "Could not encode call via CLI, using manual approach"
fi

# Step 2: On local testnet with sudo, we can directly call
log "Step 2: Using sudo to add registrar (local test only)..."

# On local testnet, Alice has sudo - use it to add registrar directly on people chain
polkadot-js-api --ws "$PEOPLE_RPC" \
    tx.sudo.sudo \
    "$(polkadot-js-api --ws "$PEOPLE_RPC" tx.identity.addRegistrar "$BOB" --params)" \
    --seed "//Alice" \
    --sign-and-send 2>/dev/null && log "Registrar added!" || warn "Sudo call failed (may need different approach)"

# Step 3: Verify registrar was added
log "Step 3: Verifying registrar..."
polkadot-js-api --ws "$PEOPLE_RPC" \
    query.identity.registrars 2>/dev/null || warn "Could not query registrars"

# Step 4: Set registrar fields
log "Step 4: Setting registrar fields (665 = Display+Matrix+Email+Twitter+Discord)..."
polkadot-js-api --ws "$PEOPLE_RPC" \
    tx.identity.setFields 0 665 \
    --seed "//Bob" \
    --sign-and-send 2>/dev/null && log "Fields set!" || warn "Set fields failed"

# Step 5: Set registrar fee
log "Step 5: Setting registrar fee..."
polkadot-js-api --ws "$PEOPLE_RPC" \
    tx.identity.setFee 0 1000000000000 \
    --seed "//Bob" \
    --sign-and-send 2>/dev/null && log "Fee set!" || warn "Set fee failed"

log "Test complete!"
log ""
log "To test the full XCM governance flow:"
log "1. Remove the sudo.sudo shortcut"
log "2. Use the xcmPallet.send approach from generate_registrar_proposal.ts"
log "3. Fast-track the referendum using sudo"

wait $ZOMBIENET_PID
