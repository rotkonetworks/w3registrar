#!/bin/bash

echo "Adding dummy data to Redis..."

# Define the wallet ID and accounts
WALLET_ID="15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
DISCORD_ACCOUNT="Discord:Alice"
CHALLENGE_TOKEN="dummy-token-123"

# Connect to Redis and add dummy data
redis-cli <<EOF
HSET "${WALLET_ID}" "accounts" '{"Discord":"Pending"}'
HSET "${DISCORD_ACCOUNT}:${WALLET_ID}" "status" "Pending" "wallet_id" "${WALLET_ID}" "token" "${CHALLENGE_TOKEN}"
EOF

echo "Dummy data added successfully!"
