#!/bin/bash
echo "Modifying dummy data in Redis..."

# Define the wallet ID and accounts
WALLET_ID="15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
DISCORD_ACCOUNT="Discord:Alice"

# Create accounts JSON with Done status
ACCOUNTS_JSON="{\"Discord:TestUser\":\"Done\"}"

# Connect to Redis and update data to Done status
redis-cli <<EOF
HSET "${WALLET_ID}" "accounts" '${ACCOUNTS_JSON}' "status" "\"Done\""
HSET "${DISCORD_ACCOUNT}:${WALLET_ID}" "status" "\"Done\"" 
EOF

echo "Status changed to Done!"
