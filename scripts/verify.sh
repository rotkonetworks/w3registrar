#!/bin/bash

echo "Creating VerifyIdentity payload..."

# Create Verify JSON message
VERIFY_MSG=$(cat << EOF | jq -c .
{
    "version": "1.0",
    "type": "VerifyIdentity",
    "payload": {
        "network": "rococo",
        "account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        "field": "Discord",
        "challenge": "38PVKJR8"
    }
}
EOF
)

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

echo "Verify payload:"
echo $VERIFY_MSG | jq .
echo
echo "Testing verification..."
test_websocket "$VERIFY_MSG"
