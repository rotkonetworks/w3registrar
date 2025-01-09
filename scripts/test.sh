#!/bin/bash

echo "Creating test payloads..."

# Create compact JSON messages
SUBSCRIBE_MSG=$(cat << EOF | jq -c .
{
    "version": "1.0",
    "type": "SubscribeAccountState",
    "payload": "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
}
EOF
)

VERIFY_MSG=$(cat << EOF | jq -c .
{
    "version": "1.0",
    "type": "VerifyIdentity",
    "payload": {
        "account": "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5",
        "field": "Discord",
        "challenge": "Vfx5qENvaK"
    }
}
EOF
)


echo "Testing with these payloads:"
echo "Subscribe payload:"
echo $SUBSCRIBE_MSG | jq .
echo
echo "Verify payload:"
echo $VERIFY_MSG | jq .
echo

test_websocket() {
    local message=$1
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt to connect..."
        # Use websocket client mode with explicit text framing
        echo "$message" | websocat --text ws://127.0.0.1:8080
        if [ $? -eq 0 ]; then
            echo "Connection successful!"
            return 0
        else
            echo "Connection failed, waiting before retry..."
            sleep 2
        fi
        attempt=$((attempt + 1))
    done
    
    echo "Failed to connect after $max_attempts attempts"
    return 1
}

echo "Testing subscription..."
#test_websocket "$SUBSCRIBE_MSG"

echo "Testing verification..."
test_websocket "$VERIFY_MSG"
